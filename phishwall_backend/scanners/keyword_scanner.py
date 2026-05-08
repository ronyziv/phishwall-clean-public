from pathlib import Path


DEFAULT_KEYWORDS_PATH = Path(__file__).resolve().parent.parent / "data" / "risk_keywords.txt"


def _load_keywords(path=DEFAULT_KEYWORDS_PATH):
    entries = []
    try:
        with open(path, "r", encoding="utf-8") as f:
            for raw_line in f:
                line = raw_line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = [p.strip() for p in line.split("|", 2)]
                if len(parts) != 3:
                    continue
                category, weight_raw, keyword = parts
                if not keyword:
                    continue
                try:
                    weight = int(weight_raw)
                except ValueError:
                    continue
                entries.append((category or "generic", weight, keyword.lower()))
    except Exception:
        return []
    return entries


def scan_keywords(text):
    findings = []
    risk_penalty = 0
    normalized = str(text or "").lower()
    matched = []
    category_counts = {}

    for category, weight, keyword in _load_keywords():
        if keyword in normalized:
            matched.append(keyword)
            category_counts[category] = category_counts.get(category, 0) + 1
            risk_penalty += weight

    if matched:
        findings.append(f"Phishing-oriented keywords detected: {', '.join(sorted(set(matched)))}")

    # Escalate if several threat/credential terms co-exist.
    escalation = 0
    if category_counts.get("threat", 0) >= 2:
        escalation += 8
    if category_counts.get("credential", 0) >= 2:
        escalation += 6
    if category_counts.get("urgency", 0) >= 2 and category_counts.get("payment", 0) >= 1:
        escalation += 6

    risk_penalty = min(risk_penalty + escalation, 40)
    if escalation > 0:
        findings.append("Combination of coercive phishing language patterns detected.")

    return {
        "matchedCount": len(matched),
        "uniqueMatchedCount": len(set(matched)),
        "riskPenalty": risk_penalty,
        "findings": findings,
    }
