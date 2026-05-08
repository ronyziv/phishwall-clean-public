"""
Look-alike detection is based on domain labels (the part before TLD).

Data model:
- BRANDS: tuple of (display_name, labels_tuple)
- LABEL_TO_BRAND: flattened dict for fast label -> brand lookup and clean findings text.
"""

BRANDS = (
    # Banks and financial institutions - Israel
    ("Bank Hapoalim", ("hapoalim", "poalim", "bankhapoalim")),
    ("Bank Leumi", ("leumi", "bankleumi")),
    ("Discount Bank", ("discount", "discountbank")),
    ("Mizrahi Tefahot", ("mizrahi", "tefahot", "mizrahi-tefahot", "mizrahi-tefahotbank")),
    ("First International Bank", ("fibi", "beinleumi", "internationalbank")),
    ("Mercantile Discount", ("mercantile", "mercantilediscount")),
    ("Bank Yahav", ("yahav", "bankyahav")),
    ("Bank Massad", ("massad", "bankmassad")),
    ("Isracard", ("isracard",)),
    ("MAX", ("max", "max-il", "maxfinance")),
    ("CAL", ("cal", "icc", "israelcreditcards")),
    ("Bit", ("bit", "bitpay")),
    ("PayBox", ("paybox",)),
    ("Pepper", ("pepper", "pepperbank")),
    # Utilities and telecom - Israel
    ("IEC", ("iec", "israelelectric", "electric", "electricity")),
    ("Mekorot", ("mekorot",)),
    ("Cellcom", ("cellcom",)),
    ("Partner", ("partner", "partneril", "orangetv")),
    ("Pelephone", ("pelephone",)),
    ("Bezeq", ("bezeq", "bezek", "bezeqint", "bezeqintl")),
    ("HOT", ("hot", "hotnet")),
    ("yes", ("yes", "yesco")),
    ("019 Mobile", ("019", "xfone", "xphone")),
    # Government and public service style - Israel
    ("Gov.il", ("gov", "govil", "gov-il", "mygov", "mygovil")),
    ("National Insurance Institute", ("btl", "bituachleumi", "nii", "nationalinsurance")),
    ("Israel Tax Authority", ("taxes", "tax", "mash", "rsm", "taxauthority")),
    ("Population and Immigration Authority", ("piba", "immigration", "populationauthority")),
    ("Israel Post", ("israelpost", "postil", "doar", "doarisrael")),
    ("Police", ("police", "israelpolice")),
    # Shipping / logistics and commerce - Israel
    ("HFD", ("hfd", "hfdelivery")),
    ("E-Post", ("epost",)),
    ("Wolt", ("wolt",)),
    ("Gett", ("gett", "gettaxi")),
    # Big tech / consumer internet - global & US
    ("Google", ("google", "gmail", "googlemail", "youtube", "googlepay", "gpay")),
    ("Microsoft", ("microsoft", "outlook", "hotmail", "live", "office", "office365")),
    ("Apple", ("apple", "icloud", "itunes", "appleid")),
    ("Amazon", ("amazon", "aws", "primevideo", "kindle")),
    ("Meta", ("facebook", "instagram", "whatsapp", "meta", "messenger")),
    ("LinkedIn", ("linkedin",)),
    ("X", ("x", "twitter")),
    ("TikTok", ("tiktok",)),
    ("Netflix", ("netflix",)),
    ("Dropbox", ("dropbox",)),
    ("Adobe", ("adobe",)),
    ("Zoom", ("zoom",)),
    ("Slack", ("slack",)),
    ("GitHub", ("github",)),
    ("OpenAI", ("openai", "chatgpt")),
    # Payments / fintech - US/global
    ("PayPal", ("paypal",)),
    ("Venmo", ("venmo",)),
    ("Cash App", ("cashapp",)),
    ("Stripe", ("stripe",)),
    ("Wise", ("wise", "transferwise")),
    ("Western Union", ("westernunion", "wu")),
    # US banks and cards
    ("Bank of America", ("bankofamerica", "bofa")),
    ("Chase", ("chase", "jpmorgan")),
    ("Wells Fargo", ("wellsfargo",)),
    ("Citibank", ("citi", "citibank")),
    ("Capital One", ("capitalone",)),
    ("American Express", ("amex", "americanexpress")),
    ("US Bank", ("usbank",)),
    ("PNC", ("pnc",)),
    ("Truist", ("truist",)),
    # US utilities / telecom / cable
    ("AT&T", ("att",)),
    ("Verizon", ("verizon",)),
    ("T-Mobile", ("tmobile",)),
    ("Comcast", ("comcast", "xfinity")),
    ("Spectrum", ("spectrum",)),
    ("Cox", ("cox", "coxcommunications")),
    # US government/public service style
    ("IRS", ("irs",)),
    ("Social Security", ("ssa", "socialsecurity")),
    ("USPS", ("usps", "postalservice")),
    ("DMV", ("dmv",)),
    ("Medicare", ("medicare",)),
    # Shipping / logistics - US/global
    ("FedEx", ("fedex",)),
    ("UPS", ("ups",)),
    ("DHL", ("dhl",)),
    ("USPS Tracking", ("uspstracking", "trackusps")),
)

LABEL_TO_BRAND = {
    label.replace("-", ""): brand_name
    for brand_name, labels in BRANDS
    for label in labels
}
COMMON_BRANDS = set(LABEL_TO_BRAND.keys())

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
    host = str(domain or "").strip().lower().split(":")[0]
    parts = [part for part in host.split(".") if part]
    if len(parts) < 2:
        return ""
    return parts[-2].replace("-", "")


def _normalize_substitutions(text):
    return "".join(COMMON_SUBSTITUTIONS.get(ch, ch) for ch in text)


def _is_common_substitution(candidate, target):
    return _normalize_substitutions(candidate) == target and candidate != target


def _has_extra_character(candidate, target):
    if len(candidate) != len(target) + 1:
        return False
    for idx in range(len(candidate)):
        if candidate[:idx] + candidate[idx + 1:] == target:
            return True
    return False


def _has_missing_character(candidate, target):
    if len(candidate) + 1 != len(target):
        return False
    for idx in range(len(target)):
        if target[:idx] + target[idx + 1:] == candidate:
            return True
    return False


def _has_swapped_adjacent_characters(candidate, target):
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
    label = _domain_label(domain)
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
