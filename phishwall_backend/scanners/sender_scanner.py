import json
import logging
import os
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib import parse, request

from scanners.external_http_config import SCANNER_MAX_WORKERS, VT_DOMAIN_TIMEOUT
from scanners.ipqs_email_client import lookup_email
from scanners.lookalike_domain_scanner import (
    analyze_lookalike_domain,
    host_matches_brand,
    infer_brand_from_text,
)


EMAIL_PATTERN = re.compile(r"([A-Z0-9._%+\-]+)@([A-Z0-9.\-]+\.[A-Z]{2,})", re.IGNORECASE)


def _extract_sender_email(sender_value):
    match = EMAIL_PATTERN.search(str(sender_value or "").strip())
    if not match:
        return "", ""
    return match.group(0).lower(), match.group(2).lower()


def _extract_all_emails(values):
    emails = []
    for raw in values:
        text = str(raw or "").strip()
        if not text:
            continue
        for match in EMAIL_PATTERN.finditer(text):
            emails.append(match.group(0).lower())
    # Keep order while removing duplicates.
    return list(dict.fromkeys(emails))


def _domain_from_email(email_value):
    if "@" not in str(email_value):
        return ""
    return str(email_value).rsplit("@", 1)[-1].strip().lower()


def _extract_display_name(sender_value):
    text = str(sender_value or "").strip()
    if not text:
        return ""
    if "<" in text:
        return text.split("<", 1)[0].strip().strip("\"'")
    if "@" in text:
        return ""
    return text


def _virustotal_domain_lookup(domain):
    api_key = os.environ.get("VT_API_KEY", "").strip()
    if not api_key or not domain:
        return None

    endpoint = "https://www.virustotal.com/api/v3/domains/" + parse.quote(domain, safe="")
    req = request.Request(endpoint, headers={"x-apikey": api_key})
    try:
        with request.urlopen(req, timeout=VT_DOMAIN_TIMEOUT) as resp:
            payload = resp.read().decode("utf-8", errors="ignore")
            return json.loads(payload)
    except Exception:
        return None


def _safe_int(value, default=0):
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _score_ipqs_email(ipqs):
    """
    Add IPQS as an extra sender-quality signal.
    Positive score adds risk; negative score reduces false positives.
    """
    findings = []
    risk_delta = 0
    flagged = 0

    success = ipqs.get("success")
    valid = ipqs.get("valid")
    timed_out = ipqs.get("timed_out")
    disposable = ipqs.get("disposable")
    dns_valid = ipqs.get("dns_valid")
    honeypot = ipqs.get("honeypot")
    suspect = ipqs.get("suspect")
    recent_abuse = ipqs.get("recent_abuse")
    fraud_score = _safe_int(ipqs.get("fraud_score"))
    overall_score = _safe_int(ipqs.get("overall_score"))
    spam_trap_score = _safe_int(ipqs.get("spam_trap_score"))
    risky_tld = ipqs.get("risky_tld")
    domain_trust = _safe_int(ipqs.get("domain_trust"))
    domain_age = _safe_int(ipqs.get("domain_age"))
    sanitized_email = str(ipqs.get("sanitized_email") or "").strip()

    if success is False:
        findings.append("IPQS email validation response was not successful.")
        return 0, 0, findings
    if timed_out is True:
        findings.append("IPQS email validation timed out.")
        return 0, 0, findings

    # High-confidence maliciousness signals.
    if honeypot is True:
        risk_delta += 25
        flagged = 1
        findings.append("IPQS indicates sender is a honeypot address.")
    if suspect is True:
        risk_delta += 12
        flagged = 1
        findings.append("IPQS indicates sender appears suspicious.")
    if recent_abuse is True:
        risk_delta += 14
        flagged = 1
        findings.append("IPQS indicates recent abuse activity on sender.")
    if disposable is True:
        risk_delta += 10
        findings.append("IPQS indicates disposable sender email.")
    if risky_tld is True:
        risk_delta += 8
        findings.append("IPQS indicates risky sender TLD.")
    if valid is False:
        risk_delta += 10
        findings.append("IPQS indicates sender email is invalid.")
    if dns_valid is False:
        risk_delta += 8
        findings.append("IPQS indicates sender DNS is invalid.")

    # Score-based signals (maliciousness-oriented, not phishing-only).
    if fraud_score >= 90 or overall_score >= 90:
        risk_delta += 20
        flagged = 1
        findings.append(
            f"IPQS very high risk score (fraud={fraud_score}, overall={overall_score})."
        )
    elif fraud_score >= 75 or overall_score >= 75:
        risk_delta += 12
        flagged = 1
        findings.append(
            f"IPQS elevated risk score (fraud={fraud_score}, overall={overall_score})."
        )
    elif fraud_score >= 55 or overall_score >= 55:
        risk_delta += 6
        findings.append(
            f"IPQS moderate risk score (fraud={fraud_score}, overall={overall_score})."
        )

    if spam_trap_score >= 75:
        risk_delta += 8
        findings.append(f"IPQS high spam trap score ({spam_trap_score}).")

    # Confidence reduction path to lower false positives.
    strong_low_risk = (
        valid is True
        and dns_valid is True
        and disposable is False
        and honeypot is False
        and suspect is False
        and recent_abuse is False
        and risky_tld is False
        and fraud_score <= 20
        and overall_score <= 20
        and spam_trap_score <= 10
        and domain_trust >= 80
        and domain_age >= 365
    )
    if strong_low_risk:
        risk_delta -= 6
        findings.append("IPQS indicates trusted and mature sender domain (risk reduced).")

    if sanitized_email:
        findings.append(f"IPQS sanitized sender: {sanitized_email}")

    return risk_delta, flagged, findings


def _safe_scan_email_reputation(email_value):
    try:
        return _scan_email_reputation(email_value)
    except Exception as exc:  # noqa: BLE001 — external stack; return neutral fallthrough
        logging.getLogger(__name__).warning("Sender reputation error for %s: %s", email_value, exc)
        return 0, 0, [f"Sender reputation lookup failed for {email_value}; used local checks only."]


def _scan_email_reputation(email_value):
    findings = []
    ipqs_flagged = 0
    ipqs_penalty = 0
    lookalike_penalty = 0

    domain = _domain_from_email(email_value)
    if domain:
        lookalike = analyze_lookalike_domain(domain)
        if lookalike["isLookalike"]:
            lookalike_penalty += lookalike["riskPenalty"]
            findings.extend(lookalike["findings"])

    ipqs, ipqs_issue = lookup_email(email_value)
    if ipqs:
        ipqs_delta, ipqs_flag, ipqs_findings = _score_ipqs_email(ipqs)
        ipqs_penalty += max(0, ipqs_delta)
        ipqs_flagged += ipqs_flag
        findings.extend(ipqs_findings)
    elif ipqs_issue == "insufficient_credits":
        findings.append(f"IPQS unavailable (insufficient credits) for {email_value}.")
    elif ipqs_issue in {
        "missing_key",
        "timeout",
        "provider_timeout",
        "request_error",
        "invalid_payload",
        "provider_unsuccessful",
    }:
        findings.append(f"IPQS unavailable for {email_value}; used local checks.")

    # Weighted composition: API is stronger, look-alike remains meaningful.
    combined_penalty = int(round(ipqs_penalty * 0.7 + lookalike_penalty * 0.6))
    return combined_penalty, ipqs_flagged, findings


def scan_sender(sender_value, email_candidates=None, context_text=""):
    findings = []
    risk_penalty = 0
    ipqs_flagged = 0
    vt_flagged = 0

    sender_email, sender_domain = _extract_sender_email(sender_value)
    display_name = _extract_display_name(sender_value)
    if not sender_email:
        return {
            "senderEmail": "",
            "senderDomain": "",
            "riskPenalty": 0,
            "ipqsFlagged": 0,
            "vtFlagged": 0,
            "findings": ["Could not parse sender email address."],
        }

    candidates = [sender_email]
    if isinstance(email_candidates, list):
        candidates.extend(email_candidates)
    elif isinstance(email_candidates, str):
        candidates.append(email_candidates)
    all_emails = _extract_all_emails(candidates)

    if sender_domain.startswith("xn--"):
        risk_penalty += 8
        findings.append(f"Sender uses punycode domain: {sender_domain}")

    brand_from_display = infer_brand_from_text(display_name)
    if brand_from_display and not host_matches_brand(sender_domain, brand_from_display):
        risk_penalty += 18
        findings.append(
            f"Display name references '{brand_from_display}' but sender domain '{sender_domain}' does not match known domains."
        )

    brand_from_context = infer_brand_from_text(context_text)
    if brand_from_context and not host_matches_brand(sender_domain, brand_from_context):
        risk_penalty += 8
        findings.append(
            f"Email content references '{brand_from_context}' while sender domain is '{sender_domain}'."
        )

    vt = None
    if all_emails:
        workers = min(SCANNER_MAX_WORKERS, max(2, len(all_emails) + 1))
        with ThreadPoolExecutor(max_workers=workers) as ex:
            rep_futures = {ex.submit(_safe_scan_email_reputation, ev): ev for ev in all_emails}
            vt_future = ex.submit(_virustotal_domain_lookup, sender_domain) if sender_domain else None
            for fut in as_completed(rep_futures):
                combined_penalty, email_ipqs_flagged, email_findings = fut.result()
                risk_penalty += combined_penalty
                ipqs_flagged += email_ipqs_flagged
                findings.extend(email_findings)
            if vt_future is not None:
                try:
                    vt = vt_future.result()
                except Exception as exc:  # noqa: BLE001
                    logging.getLogger(__name__).warning("VirusTotal lookup error: %s", exc)
                    vt = None
    else:
        vt = _virustotal_domain_lookup(sender_domain) if sender_domain else None

    if vt:
        stats = ((vt.get("data") or {}).get("attributes") or {}).get("last_analysis_stats") or {}
        malicious = int(stats.get("malicious", 0) or 0)
        suspicious = int(stats.get("suspicious", 0) or 0)
        if malicious > 0:
            vt_flagged += 1
            risk_penalty += 30
            findings.append(f"VirusTotal marked sender domain malicious ({malicious} engines).")
        elif suspicious > 0:
            vt_flagged += 1
            risk_penalty += 12
            findings.append(f"VirusTotal marked sender domain suspicious ({suspicious} engines).")

    return {
        "senderEmail": sender_email,
        "senderDomain": sender_domain,
        "riskPenalty": risk_penalty,
        "ipqsFlagged": ipqs_flagged,
        "vtFlagged": vt_flagged,
        "emailsChecked": len(all_emails),
        "findings": findings,
    }
