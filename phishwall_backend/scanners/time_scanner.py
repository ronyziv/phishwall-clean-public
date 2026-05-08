from datetime import datetime, timezone
from email.utils import parsedate_to_datetime


BEC_KEYWORDS = {
    "wire",
    "bank",
    "invoice",
    "payment",
    "transfer",
    "urgent",
    "finance",
    "חשבונית",
    "תשלום",
    "העברה",
    "בנק",
    "דחוף",
}

ACCOUNT_TAKEOVER_KEYWORDS = {
    "login",
    "password",
    "reset",
    "verification",
    "verify",
    "otp",
    "2fa",
    "mfa",
    "security code",
    "unusual sign-in",
    "suspicious login",
    "חשבון",
    "התחברות",
    "סיסמה",
    "אימות",
    "קוד אימות",
}

OFF_HOURS = {0, 1, 2, 3, 4, 5}
WEEKEND_DAYS = {5, 6}  # Saturday, Sunday


def _parse_datetime(value):
    text = str(value or "").strip()
    if not text:
        return None

    try:
        # Supports ISO-8601 strings.
        dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except ValueError:
        pass

    try:
        # Supports RFC-style email Date headers.
        dt = parsedate_to_datetime(text)
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except Exception:
        return None


def _is_bec_context(text):
    text_lower = str(text or "").lower()
    return any(keyword in text_lower for keyword in BEC_KEYWORDS)


def _is_ato_context(text):
    text_lower = str(text or "").lower()
    return any(keyword in text_lower for keyword in ACCOUNT_TAKEOVER_KEYWORDS)


def scan_sending_time(date_value, context_text):
    dt = _parse_datetime(date_value)
    if dt is None:
        return {
            "analyzed": False,
            "riskPenalty": 0,
            "findings": [],
        }

    local_dt = dt.astimezone()
    hour = local_dt.hour
    weekday = local_dt.weekday()
    bec_context = _is_bec_context(context_text)
    ato_context = _is_ato_context(context_text)
    suspicious_context = bec_context or ato_context

    risk_penalty = 0
    findings = []

    # Intentionally weak supporting signal:
    # Time anomalies add score only when message context already looks suspicious
    # (BEC or account-takeover patterns). Time by itself adds no score.
    if suspicious_context and hour in OFF_HOURS:
        risk_penalty += 2
        findings.append(
            "Low-weight supporting anomaly: unusual sending hour in BEC/ATO-like context."
        )
    elif suspicious_context and weekday in WEEKEND_DAYS:
        risk_penalty += 1
        findings.append(
            "Low-weight supporting anomaly: weekend sending time in BEC/ATO-like context."
        )

    return {
        "analyzed": True,
        "riskPenalty": risk_penalty,
        "findings": findings,
        "hour": hour,
        "weekday": weekday,
        "becContext": bec_context,
        "atoContext": ato_context,
    }
