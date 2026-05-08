import re
from typing import Any, Dict, List

from scanners.attachment_scanner import scan_attachments
from scanners.keyword_scanner import scan_keywords
from scanners.language_scanner import scan_language_quality
from scanners.sender_scanner import scan_sender
from scanners.time_scanner import scan_sending_time
from scanners.url_scanner import scan_urls


URL_PATTERN = re.compile(r"https?://[^\s\"'<>]+")


def normalize_urls(urls_value: Any, body_text: str) -> List[str]:
    if isinstance(urls_value, list):
        urls = [str(url).strip() for url in urls_value if str(url).strip()]
    else:
        urls = []

    if not urls:
        urls = URL_PATTERN.findall(body_text or "")

    return urls


def collect_email_candidates(data: Dict[str, Any]) -> List[str]:
    candidates: List[str] = []
    direct_fields = ["from", "to", "cc", "bcc", "reply_to", "subject", "body", "body_snippet"]
    for field in direct_fields:
        value = data.get(field)
        if isinstance(value, list):
            candidates.extend([str(item) for item in value])
        elif value:
            candidates.append(str(value))
    return candidates


def analyze_email(data: Dict[str, Any]) -> Dict[str, Any]:
    score = 100
    risk_indicators: List[str] = []
    info_findings: List[str] = []

    subject = data.get("subject", "")
    sender = data.get("from", "")
    body = data.get("body", "")
    body_snippet = data.get("body_snippet", "")
    sent_at = data.get("date") or data.get("sent_at") or data.get("timestamp") or ""

    text = f"{subject} {sender} {body} {body_snippet}".lower()

    keyword_scan = scan_keywords(text)
    if keyword_scan["findings"]:
        risk_indicators.extend(keyword_scan["findings"])
    keyword_penalty = keyword_scan["riskPenalty"]
    score -= keyword_penalty

    language_scan = scan_language_quality(subject, body, body_snippet)
    if language_scan["findings"]:
        risk_indicators.extend(language_scan["findings"])
    language_penalty = language_scan["riskPenalty"]
    score -= language_penalty

    email_candidates = collect_email_candidates(data)
    sender_scan = scan_sender(sender, email_candidates=email_candidates)
    if sender_scan["findings"]:
        for finding in sender_scan["findings"]:
            if finding.startswith("IPQS unavailable"):
                info_findings.append(finding)
            else:
                risk_indicators.append(finding)
    sender_penalty = sender_scan["riskPenalty"]
    score -= sender_penalty

    time_context = f"{subject} {body} {body_snippet} {sender}"
    time_scan = scan_sending_time(sent_at, time_context)
    if time_scan["findings"]:
        risk_indicators.extend(time_scan["findings"])
    time_penalty = time_scan["riskPenalty"]
    score -= time_penalty

    urls = normalize_urls(data.get("urls", []), body)

    links = len(urls)
    link_base_penalty = 0
    if links > 0:
        # Keep this intentionally low to avoid penalizing normal emails with links.
        link_base_penalty = min(3, 1 + max(0, links - 1))
        info_findings.append(f"Found {links} link(s) in the email.")
        score -= link_base_penalty

    url_scan = scan_urls(urls)
    url_applied_penalty = 0
    if url_scan["urlCount"] > 0:
        for finding in url_scan["findings"]:
            if (
                "lookup timed out" in finding
                or "lookup failed" in finding
                or "reputation is disabled" in finding
            ):
                info_findings.append(finding)
            else:
                risk_indicators.append(finding)
        url_applied_penalty = int(url_scan["riskPenalty"] * 0.7)
        score -= url_applied_penalty

    attachments = data.get("attachments", [])
    attachment_scan = scan_attachments(attachments)
    if attachment_scan["attachmentCount"] > 0:
        info_findings.append(f"Found {attachment_scan['attachmentCount']} attachment(s).")
        for finding in attachment_scan["findings"]:
            if finding.startswith("PDF attachment detected (no links found):"):
                info_findings.append(finding)
            else:
                risk_indicators.append(finding)
        attachment_penalty = attachment_scan["riskPenalty"]
        score -= attachment_penalty
    else:
        attachment_penalty = 0

    if not risk_indicators:
        info_findings.append("No strong suspicious indicators were found.")

    score = max(0, min(100, score))

    verdict = "Safe"
    color = "#2E7D32"
    icon = "🟢"

    if score < 75:
        verdict = "Suspicious"
        color = "#F57C00"
        icon = "🟡"

    strong_indicator_hit = (
        sender_scan.get("ipqsFlagged", 0) > 0
        or sender_scan.get("vtFlagged", 0) > 0
        or url_scan.get("ipqsFlagged", 0) > 0
        or url_scan.get("gsbFlagged", 0) > 0
        or attachment_scan.get("executableCount", 0) > 0
        or attachment_scan.get("pdfWithLinksCount", 0) > 0
        or keyword_penalty >= 28
    )

    if score < 45 and strong_indicator_hit:
        verdict = "High Risk"
        color = "#D32F2F"
        icon = "🔴"

    malicious_score = 100 - score
    total_penalty = 100 - score

    return {
        "score": score,
        "maliciousScore": malicious_score,
        "verdict": verdict,
        "color": color,
        "icon": icon,
        "links": links,
        "riskWords": keyword_scan["uniqueMatchedCount"],
        # Backward compatible field. Contains risk indicators only.
        "comments": risk_indicators,
        "riskIndicators": risk_indicators,
        "infoFindings": info_findings,
        "scoreBreakdown": {
            "keywords": keyword_penalty,
            "language": language_penalty,
            "sender": sender_penalty,
            "time": time_penalty,
            "linkBase": link_base_penalty,
            "urlRaw": url_scan["riskPenalty"],
            "urlApplied": url_applied_penalty,
            "attachments": attachment_penalty,
            "totalPenalty": total_penalty,
        },
        "attachmentSummary": {
            "count": attachment_scan["attachmentCount"],
            "safePdfCount": attachment_scan["safePdfCount"],
            "pdfWithLinksCount": attachment_scan["pdfWithLinksCount"],
            "executableCount": attachment_scan["executableCount"],
            "unknownAttachmentCount": attachment_scan["unknownAttachmentCount"],
        },
        "urlSummary": {
            "count": url_scan["urlCount"],
            "unresolvedHosts": url_scan["unresolvedHosts"],
            "ipqsFlagged": url_scan["ipqsFlagged"],
        },
        "senderSummary": {
            "email": sender_scan["senderEmail"],
            "domain": sender_scan["senderDomain"],
            "emailsChecked": sender_scan.get("emailsChecked", 1),
            "ipqsFlagged": sender_scan["ipqsFlagged"],
            "vtFlagged": sender_scan["vtFlagged"],
        },
        "languageSummary": {
            "heuristicPenalty": language_scan["riskPenalty"],
        },
        "timeSummary": {
            "analyzed": time_scan["analyzed"],
            "riskPenalty": time_scan["riskPenalty"],
            "becContext": time_scan.get("becContext", False),
            "atoContext": time_scan.get("atoContext", False),
            "hour": time_scan.get("hour"),
            "weekday": time_scan.get("weekday"),
        },
    }
