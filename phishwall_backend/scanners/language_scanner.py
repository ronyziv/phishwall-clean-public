import re


HEBREW_CHARS = re.compile(r"[\u0590-\u05FF]")
LATIN_WORDS = re.compile(r"\b[a-zA-Z]{2,}\b")
MANY_PUNCT = re.compile(r"[!?]{3,}")
REPEATED_CHAR = re.compile(r"(.)\1{3,}")


def scan_language_quality(subject, body, snippet=""):
    findings = []
    risk_penalty = 0

    text = f"{subject or ''} {body or ''} {snippet or ''}".strip()
    if not text:
        return {"riskPenalty": 0, "findings": findings}

    heb = len(HEBREW_CHARS.findall(text))
    lat = len(LATIN_WORDS.findall(text))

    # Heuristic: unusual mixture often appears in low-quality phishing templates.
    if heb > 20 and lat > 20:
        risk_penalty += 6
        findings.append("Unnatural mixed language pattern detected (Hebrew + English).")

    # Heuristic: excessive punctuation / aggressive emphasis.
    if MANY_PUNCT.search(text):
        risk_penalty += 5
        findings.append("Excessive punctuation detected.")

    if REPEATED_CHAR.search(text):
        risk_penalty += 4
        findings.append("Repeated character pattern detected.")

    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
    short_lines = [ln for ln in lines if len(ln) <= 3]
    if len(short_lines) >= 4:
        risk_penalty += 4
        findings.append("Fragmented unnatural text structure detected.")

    return {"riskPenalty": min(risk_penalty, 15), "findings": findings}
