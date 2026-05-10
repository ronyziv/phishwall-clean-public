"""Look-alike domain / brand impersonation detector.

Loads `data/impersonation_targets.json` once at import time. Provides:
- string-distance checks (typosquats, char swaps, leet substitutions);
- brand inference from arbitrary text so the sender scanner can flag mismatches
  like "PayPal Security <foo@bar.com>".

Catalog format: list of `{name, labels[], domains[]}` where labels are alternate
spellings ("microsoft" / "msft") and domains are the brand's legitimate roots.
"""

import json
from pathlib import Path

DATA_PATH = Path(__file__).resolve().parent.parent / "data" / "impersonation_targets.json"


def _load_targets():
    # Hyphens are stripped from labels so "micro-soft" and "microsoft" hit the
    # same brand entry without bloating the catalog.
    try:
        with open(DATA_PATH, "r", encoding="utf-8") as f:
            rows = json.load(f)
    except Exception:
        rows = []

    brands = []
    label_to_brand = {}
    brand_domains = {}
    for row in rows:
        name = str(row.get("name", "")).strip()
        labels = tuple(
            str(label).strip().lower()
            for label in row.get("labels", [])
            if str(label).strip()
        )
        domains = tuple(
            str(domain).strip().lower()
            for domain in row.get("domains", [])
            if str(domain).strip()
        )
        if not name or not labels:
            continue
        brands.append((name, labels))
        for label in labels:
            label_to_brand[label.replace("-", "")] = name
        if domains:
            brand_domains[name] = domains
    return tuple(brands), label_to_brand, brand_domains


# Loaded once at import; the catalog is small (<200 entries) and read-only.
BRANDS, LABEL_TO_BRAND, BRAND_PRIMARY_DOMAINS = _load_targets()

# Re-normalize defensively in case _load_targets is monkeypatched in a test.
LABEL_TO_BRAND = {
    key.replace("-", ""): value
    for key, value in LABEL_TO_BRAND.items()
}
COMMON_BRANDS = set(LABEL_TO_BRAND.keys())

# "Leet" lookalikes (paypa1 vs paypal). Used to normalize a candidate label
# before comparing it to a known brand.
COMMON_SUBSTITUTIONS = {
    "0": "o",
    "1": "l",
    "3": "e",
    "4": "a",
    "5": "s",
    "6": "g",
    "7": "t",
    "8": "b",
    "9": "g",
    "@": "a",
    "$": "s",
}


def _domain_label(domain):
    # 2nd-level label of the host: "paypa1-secure.com" -> "paypa1".
    # Hyphens stripped so "my-paypal.com" compares against "paypal".
    host = str(domain or "").strip().lower().split(":")[0]
    parts = [part for part in host.split(".") if part]
    if len(parts) < 2:
        return ""
    return parts[-2].replace("-", "")


def normalize_host(domain):
    # Lowercase, strip port, drop leading "www." so equivalent forms compare equal.
    host = str(domain or "").strip().lower().split(":")[0]
    if host.startswith("www."):
        host = host[4:]
    return host


def infer_brand_from_text(text):
    """Return the first known brand mentioned in the text, or None.

    First-match-wins, so catalog ordering matters. Hyphens/underscores stripped
    so "pay-pal" / "pay_pal" still map to "paypal".
    """
    normalized = str(text or "").lower().replace("-", "").replace("_", "")
    if not normalized:
        return None

    for label, brand_name in LABEL_TO_BRAND.items():
        if label and label in normalized:
            return brand_name
    return None


def host_matches_brand(host, brand_name):
    """True when `host` is one of `brand_name`'s legitimate domains."""
    normalized_host = normalize_host(host)
    if not normalized_host or not brand_name:
        return False

    allowed_domains = BRAND_PRIMARY_DOMAINS.get(brand_name, ())
    for allowed in allowed_domains:
        allowed = normalize_host(allowed)
        # endswith("." + allowed) matches subdomains but not similar hostnames
        # (allow "paypal.com" must not match "not-paypal.com").
        if normalized_host == allowed or normalized_host.endswith("." + allowed):
            return True

    # Fallback: brands listed by label only (no explicit domain list) still validate.
    expected_labels = {label for label, mapped_brand in LABEL_TO_BRAND.items() if mapped_brand == brand_name}
    label = _domain_label(normalized_host)
    return bool(label and label in expected_labels)


def _normalize_substitutions(text):
    return "".join(COMMON_SUBSTITUTIONS.get(ch, ch) for ch in text)


def _is_common_substitution(candidate, target):
    # Same after leet-normalization but different originals (paypa1 vs paypal).
    return _normalize_substitutions(candidate) == target and candidate != target


def _has_extra_character(candidate, target):
    # One-char insertion typo: "paypall" vs "paypal".
    if len(candidate) != len(target) + 1:
        return False
    for idx in range(len(candidate)):
        if candidate[:idx] + candidate[idx + 1:] == target:
            return True
    return False


def _has_missing_character(candidate, target):
    # One-char deletion typo: "paypl" vs "paypal".
    if len(candidate) + 1 != len(target):
        return False
    for idx in range(len(target)):
        if target[:idx] + target[idx + 1:] == candidate:
            return True
    return False


def _has_swapped_adjacent_characters(candidate, target):
    # Adjacent transposition: "payapl" vs "paypal".
    if len(candidate) != len(target):
        return False
    for idx in range(len(candidate) - 1):
        swapped = (
            candidate[:idx]
            + candidate[idx + 1]
            + candidate[idx]
            + candidate[idx + 2:]
        )
        if swapped == target:
            return True
    return False


def analyze_lookalike_domain(domain):
    """First matching look-alike rule, or no-op result.

    `break` after the first match keeps the contribution bounded — one domain
    cannot stack multiple look-alike penalties.
    """
    label = _domain_label(domain)
    # If the label is the brand itself (paypal.com), no penalty.
    if not label or label in COMMON_BRANDS:
        return {"isLookalike": False, "riskPenalty": 0, "findings": []}

    findings = []
    risk_penalty = 0

    for brand in COMMON_BRANDS:
        brand_name = LABEL_TO_BRAND.get(brand, brand)
        if _is_common_substitution(label, brand):
            risk_penalty += 16
            findings.append(
                f"Look-alike domain by common substitution: '{label}' resembles '{brand_name}' ({brand})."
            )
            break

        if _has_extra_character(label, brand):
            risk_penalty += 12
            findings.append(
                f"Look-alike domain by extra character: '{label}' resembles '{brand_name}' ({brand})."
            )
            break

        if _has_missing_character(label, brand):
            risk_penalty += 12
            findings.append(
                f"Look-alike domain by missing character: '{label}' resembles '{brand_name}' ({brand})."
            )
            break

        if _has_swapped_adjacent_characters(label, brand):
            risk_penalty += 14
            findings.append(
                f"Look-alike domain by swapped characters: '{label}' resembles '{brand_name}' ({brand})."
            )
            break

    return {
        "isLookalike": bool(findings),
        "riskPenalty": risk_penalty,
        "findings": findings,
    }
