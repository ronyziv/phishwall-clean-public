import ipaddress
import json
import os
import socket
from urllib import parse, request

from scanners.lookalike_domain_scanner import analyze_lookalike_domain


SUSPICIOUS_TLDS = {
    "zip", "mov", "top", "gq", "tk", "work", "click", "country", "kim",
    "xyz", "site", "online", "icu", "buzz", "cam", "lol"
}

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "cutt.ly", "rebrand.ly",
    "tiny.cc", "rb.gy", "shorturl.at", "t.ly", "buff.ly", "lnkd.in"
}

REQUEST_TIMEOUT_SECONDS = 3
REMOTE_LOOKUP_LIMIT = 5
SUSPICIOUS_URL_TERMS = ("download", "install", "update", "setup", "patch", "enable")
SUSPICIOUS_DOWNLOAD_EXTENSIONS = (
    ".exe", ".msi", ".bat", ".cmd", ".ps1", ".js", ".jar", ".scr", ".hta", ".vbs", ".zip", ".iso"
)


def _read_json_response(resp):
    payload = resp.read().decode("utf-8", errors="ignore")
    if not payload.strip():
        return None
    try:
        return json.loads(payload)
    except Exception:
        return None


def _host_from_url(url):
    try:
        parsed = parse.urlparse(str(url).strip())
    except Exception:
        return ""
    return (parsed.hostname or "").strip().lower()


def _is_ip_host(host):
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _resolve_host(host):
    try:
        socket.getaddrinfo(host, 80, type=socket.SOCK_STREAM)
        return True
    except socket.gaierror:
        return False
    except Exception:
        return False


def _ipqs_lookup(url):
    api_key = os.environ.get("IPQS_API_KEY", "").strip()
    if not api_key:
        return None, "disabled"

    endpoint = (
        "https://ipqualityscore.com/api/json/url/"
        + parse.quote(api_key)
        + "/"
        + parse.quote(url, safe="")
    )

    try:
        with request.urlopen(endpoint, timeout=REQUEST_TIMEOUT_SECONDS) as resp:
            data = _read_json_response(resp)
            if not isinstance(data, dict):
                return None, "empty"
            return data, None
    except TimeoutError:
        return None, "timeout"
    except Exception:
        return None, "error"


def _gsb_lookup(url):
    api_key = os.environ.get("GOOGLE_SAFE_BROWSING_API_KEY", "").strip()
    if not api_key:
        return None, "disabled"

    endpoint = (
        "https://safebrowsing.googleapis.com/v4/threatMatches:find?key="
        + parse.quote(api_key)
    )
    body = {
        "client": {
            "clientId": "phishwall-backend",
            "clientVersion": "1.0.0",
        },
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }
    payload = json.dumps(body).encode("utf-8")
    req = request.Request(
        endpoint,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    try:
        with request.urlopen(req, timeout=REQUEST_TIMEOUT_SECONDS) as resp:
            data = _read_json_response(resp)
            if data is None:
                return {"matches": []}, None
            if isinstance(data, dict):
                return data, None
            return None, "empty"
    except TimeoutError:
        return None, "timeout"
    except Exception:
        return None, "error"


def _apply_remote_reputation(url, findings):
    ipqs, ipqs_issue = _ipqs_lookup(url)
    if ipqs:
        risk_score = int(ipqs.get("risk_score", 0) or 0)
        flagged = (
            ipqs.get("phishing") is True
            or ipqs.get("malware") is True
            or ipqs.get("suspicious") is True
            or risk_score >= 75
        )
        if flagged:
            findings.append(f"IPQS flagged URL (risk {risk_score}): {url}")
            return 30, 1, 0
        return 0, 0, 0

    gsb, gsb_issue = _gsb_lookup(url)
    if gsb:
        matches = gsb.get("matches") or []
        if matches:
            findings.append(f"Google Safe Browsing flagged URL: {url}")
            return 30, 0, 1
        return 0, 0, 0

    if ipqs_issue == "timeout":
        findings.append("IPQS reputation lookup timed out; attempted fallback.")
    elif ipqs_issue in {"error", "empty"}:
        findings.append("IPQS reputation lookup failed; attempted fallback.")

    if gsb_issue == "timeout":
        findings.append("Google Safe Browsing lookup timed out.")
    elif gsb_issue in {"error", "empty"}:
        findings.append("Google Safe Browsing lookup failed.")
    elif ipqs_issue == "disabled" and gsb_issue == "disabled":
        findings.append("Remote URL reputation is disabled (missing API keys).")

    return 0, 0, 0


def scan_urls(urls):
    findings = []
    risk_penalty = 0
    unresolved_hosts = 0
    ipqs_flagged = 0
    gsb_flagged = 0
    long_url_hits = 0

    if not isinstance(urls, list):
        urls = []

    scanned_raw = [str(raw_url).strip() for raw_url in urls if str(raw_url).strip()]
    # Deduplicate exact URL strings while preserving order to prevent repeated inflation.
    scanned = list(dict.fromkeys(scanned_raw))

    for url in scanned:
        host = _host_from_url(url)
        if not host:
            risk_penalty += 20
            findings.append(f"Malformed URL detected: {url}")
            continue

        if any(short in host for short in SHORTENERS):
            risk_penalty += 20
            findings.append(f"URL shortener detected: {host}")

        if "@" in url:
            risk_penalty += 20
            findings.append(f"URL contains '@': {url}")

        lowered_url = url.lower()
        if any(term in lowered_url for term in SUSPICIOUS_URL_TERMS):
            risk_penalty += 6
            findings.append(f"URL contains delivery-related keyword: {host}")

        if any(lowered_url.endswith(ext) for ext in SUSPICIOUS_DOWNLOAD_EXTENSIONS):
            risk_penalty += 14
            findings.append(f"URL points to potentially dangerous downloadable file: {url}")

        if len(url) > 150:
            # Long URL alone is a weak signal; cap its total effect.
            if long_url_hits < 2:
                risk_penalty += 2
            long_url_hits += 1
            findings.append("Very long URL detected.")

        if host.startswith("xn--"):
            risk_penalty += 20
            findings.append(f"Punycode domain detected: {host}")

        lookalike = analyze_lookalike_domain(host)
        if lookalike["isLookalike"]:
            risk_penalty += lookalike["riskPenalty"]
            findings.extend(lookalike["findings"])

        tld = host.rsplit(".", 1)[-1] if "." in host else ""
        if tld in SUSPICIOUS_TLDS:
            risk_penalty += 12
            findings.append(f"Suspicious top-level domain detected: .{tld}")

        if _is_ip_host(host):
            risk_penalty += 15
            findings.append(f"Raw IP address used as domain: {host}")

        if not _resolve_host(host):
            unresolved_hosts += 1
            risk_penalty += 15
            findings.append(f"Domain does not resolve in DNS: {host}")

    # Remote reputation check with fallback: IPQS -> Google Safe Browsing.
    for url in scanned[:REMOTE_LOOKUP_LIMIT]:
        penalty, ipqs_inc, gsb_inc = _apply_remote_reputation(url, findings)
        risk_penalty += penalty
        ipqs_flagged += ipqs_inc
        gsb_flagged += gsb_inc

    deduped_findings = list(dict.fromkeys(findings))

    return {
        "urlCount": len(scanned),
        "unresolvedHosts": unresolved_hosts,
        "ipqsFlagged": ipqs_flagged,
        "gsbFlagged": gsb_flagged,
        "riskPenalty": risk_penalty,
        "findings": deduped_findings,
    }
