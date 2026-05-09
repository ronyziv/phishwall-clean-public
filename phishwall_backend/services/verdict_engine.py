from typing import Any, Dict, List


def _contains_any(text: str, patterns: List[str]) -> bool:
    lowered = str(text or "").lower()
    return any(pattern in lowered for pattern in patterns)


def build_verdict(
    malicious_score: int,
    keyword_penalty: int,
    sender_summary: Dict[str, Any],
    url_summary: Dict[str, Any],
    attachment_summary: Dict[str, Any],
    qr_summary: Dict[str, Any],
    priority_threat_summary: Dict[str, Any],
    risk_indicators: List[str],
) -> Dict[str, Any]:
    indicators_text = " | ".join(risk_indicators)

    has_executable = attachment_summary.get("executableCount", 0) > 0
    has_disguised_attachment = _contains_any(
        indicators_text,
        ["disguised attachment filename pattern", "right-to-left override"],
    )
    has_risky_archive = _contains_any(indicators_text, ["risky archive/container attachment"])
    has_spoofing = _contains_any(
        indicators_text,
        [
            "look-alike domain",
            "display name references",
            "does not match known domains",
            "sender uses punycode domain",
        ],
    )
    has_suspicious_links = (
        url_summary.get("ipqsFlagged", 0) > 0
        or url_summary.get("gsbFlagged", 0) > 0
        or _contains_any(
            indicators_text,
            [
                "malformed url detected",
                "url shortener detected",
                "punycode domain detected",
                "url contains '@'",
                "url points to potentially dangerous downloadable file",
                "suspicious top-level domain detected",
            ],
        )
    )
    has_sender_reputation_hit = sender_summary.get("ipqsFlagged", 0) > 0 or sender_summary.get("vtFlagged", 0) > 0
    has_urgent_pressure = keyword_penalty >= 14
    has_qr_phishing = qr_summary.get("qrDetected", False)
    has_qr_url_payload = _contains_any(indicators_text, ["decoded qr", "contains url target"])
    has_bec_behavior = priority_threat_summary.get("becDetected", False)

    strong_indicators: List[str] = []
    if has_executable:
        strong_indicators.append("executable attachment")
    if has_disguised_attachment:
        strong_indicators.append("disguised attachment pattern")
    if has_risky_archive:
        strong_indicators.append("risky archive attachment")
    if has_spoofing:
        strong_indicators.append("sender spoofing/look-alike signs")
    if has_suspicious_links:
        strong_indicators.append("highly suspicious links")
    if has_sender_reputation_hit:
        strong_indicators.append("sender/domain reputation alerts")
    if has_urgent_pressure:
        strong_indicators.append("urgent pressure wording")
    if has_qr_phishing:
        strong_indicators.append("QR-phishing pattern")
    if has_bec_behavior:
        strong_indicators.append("BEC-style impersonation pattern")

    strong_count = len(strong_indicators)
    hard_blocker = has_executable or has_disguised_attachment or sender_summary.get("vtFlagged", 0) > 0

    verdict = "Safe"
    color = "#2E7D32"
    icon = "🟢"

    dangerous_condition = (
        hard_blocker
        or malicious_score >= 60
        or (has_qr_url_payload and malicious_score >= 25)
        or (has_qr_phishing and malicious_score >= 30)
        or (has_bec_behavior and malicious_score >= 35)
        or (malicious_score >= 45 and strong_count >= 1)
        or (malicious_score >= 35 and strong_count >= 2)
    )

    suspicious_condition = (
        malicious_score >= 20
        or strong_count >= 1
        or len(risk_indicators) >= 2
    )

    if dangerous_condition:
        verdict = "Dangerous / Do Not Open"
        color = "#C62828"
        icon = "⛔"
    elif suspicious_condition:
        verdict = "Suspicious"
        color = "#F57C00"
        icon = "🟠"

    if verdict == "Dangerous / Do Not Open":
        if strong_indicators:
            reasoning = (
                "This email contains highly suspicious indicators, including "
                + ", ".join(strong_indicators[:3])
                + "."
            )
        else:
            reasoning = "This email reached a high maliciousness threshold and should be treated as unsafe."
        recommendation = "Do not open this email, click links, or download/open any attached files."
    elif verdict == "Suspicious":
        if strong_indicators:
            reasoning = (
                "This email shows suspicious indicators, including "
                + ", ".join(strong_indicators[:2])
                + "."
            )
        else:
            reasoning = "This email has multiple warning signals and needs manual verification."
        recommendation = "Avoid clicking links or opening attachments until you verify the sender through a trusted channel."
    else:
        reasoning = "No strong malicious indicators were detected in this message."
        recommendation = "Proceed carefully and keep standard email hygiene before opening links or files."

    return {
        "verdict": verdict,
        "color": color,
        "icon": icon,
        "reasoning": reasoning,
        "recommendation": recommendation,
        "strongIndicators": strong_indicators,
    }
