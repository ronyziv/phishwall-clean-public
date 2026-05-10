"""Thin client for the IPQualityScore email-validation API.

Returns (data, error_code). Callers must handle error_code and fall back to local
heuristics — this module never raises.
"""

import json
import logging
import os
from urllib import parse, request

from scanners.external_http_config import IPQS_EMAIL_TIMEOUT

IPQS_EMAIL_ENDPOINT = "https://www.ipqualityscore.com/api/json/email/"

# urllib socket budget. Also forwarded to IPQS via the `timeout` query param so the
# provider terminates work server-side and we don't pile up stuck threads under load.
_CLIENT_TIMEOUT = IPQS_EMAIL_TIMEOUT
QUERY_PARAMS = {
    # IPQS expects an int in [5, 15]; clamp into range.
    "timeout": max(5, min(15, int(_CLIENT_TIMEOUT))),
    # Full evaluation (recent_abuse, honeypot, etc.).
    "fast": "false",
    # Mid strictness: catches known-bad without over-flagging obscure providers.
    "abuse_strictness": 1,
}

# IPQS does not have a stable code for credit exhaustion; we string-match the message.
INSUFFICIENT_CREDITS_MARKERS = (
    "insufficient credits",
    "insufficient credit",
)


def lookup_email(email_value):
    """Look up sender reputation. Returns (data_or_None, error_code_or_None).

    Error codes are coarse on purpose — the sender scanner only needs "use it" vs
    "fall back" and the right info message to show.
    """
    api_key = os.environ.get("IPQS_API_KEY", "").strip()
    key_loaded = bool(api_key)

    if not key_loaded:
        logging.warning("IPQS fallback used: missing IPQS_API_KEY.")
        return None, "missing_key"

    if not email_value:
        logging.warning("IPQS fallback used: missing sender email value.")
        return None, "missing_email"

    # Both key and email go in the path — percent-encode so unusual local-parts
    # (`+`, `&`) can't break the URL or be parsed as extra segments.
    endpoint_base = (
        IPQS_EMAIL_ENDPOINT
        + parse.quote(api_key)
        + "/"
        + parse.quote(email_value, safe="")
    )
    endpoint = f"{endpoint_base}?{parse.urlencode(QUERY_PARAMS)}"
    # Truncate to keep logs readable.
    logging.getLogger(__name__).debug("IPQS email lookup: %s", email_value[:80])

    try:
        with request.urlopen(endpoint, timeout=_CLIENT_TIMEOUT) as resp:
            payload = resp.read().decode("utf-8", errors="ignore")
            data = json.loads(payload) if payload.strip() else {}
    except TimeoutError:
        logging.warning("IPQS request failed: timeout. Fallback used.")
        return None, "timeout"
    except Exception as exc:
        # Broad except is intentional: any urllib/SSL/JSON failure -> degrade gracefully.
        logging.warning("IPQS request failed: %s. Fallback used.", exc)
        return None, "request_error"

    if not isinstance(data, dict):
        logging.warning("IPQS request failed: invalid JSON shape. Fallback used.")
        return None, "invalid_payload"

    success = data.get("success") is True
    logging.info("IPQS request succeeded=%s", success)
    if success:
        return data, None

    # Distinguish "ran out of credits" from generic provider failures so the add-on
    # can show an actionable info message.
    message = str(data.get("message") or "").strip().lower()
    if any(marker in message for marker in INSUFFICIENT_CREDITS_MARKERS):
        logging.warning("IPQS fallback used: insufficient credits.")
        return None, "insufficient_credits"

    if data.get("timed_out") is True:
        logging.warning("IPQS fallback used: provider timed out.")
        return None, "provider_timeout"

    logging.warning("IPQS fallback used: provider unsuccessful response.")
    return None, "provider_unsuccessful"
