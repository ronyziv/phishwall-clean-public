"""Stylistic heuristics for low-effort phishing templates.

Deliberately weak (capped at 15) — these signals false-positive on auto-generated
mailing lists, so they mostly serve as tie-breakers when other scanners are borderline.
"""

import re


# Hebrew Unicode block — used to spot machine-translated mixed-script content,
# common in low-quality phishing aimed at Israeli users.
HEBREW_CHARS = re.compile(r"[\u0590-\u05FF]")
LATIN_WORDS = re.compile(r"\b[a-zA-Z]{2,}\b")
# 3+ !/? in a row — phishing-grade emphasis.
MANY_PUNCT = re.compile(r"[!?]{3,}")
# Same character 4+ times — typical of spam/template artefacts.
REPEATED_CHAR = re.compile(r"(.)\1{3,}")


def scan_language_quality(subject, body, snippet=""):
    findings = []
    risk_penalty = 0

    text = f"{subject or ''} {body or ''} {snippet or ''}".strip()
    if not text:
        return {"riskPenalty": 0, "findings": findings}

    heb = len(HEBREW_CHARS.findall(text))
    lat = len(LATIN_WORDS.findall(text))

    # Need 20+ chars of each; otherwise a stray brand name like "PayPal" in an
    # otherwise-Hebrew message would trigger.
    if heb > 20 and lat > 20:
        risk_penalty += 6
        findings.append("Unnatural mixed language pattern detected (Hebrew + English).")

    if MANY_PUNCT.search(text):
        risk_penalty += 5
        findings.append("Excessive punctuation detected.")

    if REPEATED_CHAR.search(text):
        risk_penalty += 4
        findings.append("Repeated character pattern detected.")

    # Many ≤3-char lines often mean a copy-paste template that lost its formatting.
    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
    short_lines = [ln for ln in lines if len(ln) <= 3]
    if len(short_lines) >= 4:
        risk_penalty += 4
        findings.append("Fragmented unnatural text structure detected.")

    return {"riskPenalty": min(risk_penalty, 15), "findings": findings}
