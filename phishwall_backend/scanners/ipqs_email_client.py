import json
import logging
import os
from urllib import parse, request


IPQS_EMAIL_ENDPOINT = "https://www.ipqualityscore.com/api/json/email/"

QUERY_PARAMS = {
    "timeout": 10,
    "fast": "false",
    "abuse_strictness": 1,
}

INSUFFICIENT_CREDITS_MARKERS = (
    "insufficient credits",
    "insufficient credit",
)


def lookup_email(email_value):
    api_key = os.environ.get("IPQS_API_KEY", "").strip()
    key_loaded = bool(api_key)
    logging.info("IPQS startup: IPQS_API_KEY loaded=%s", key_loaded)

    if not key_loaded:
        logging.warning("IPQS fallback used: missing IPQS_API_KEY.")
        return None, "missing_key"

    if not email_value:
        logging.warning("IPQS fallback used: missing sender email value.")
        return None, "missing_email"

    endpoint_base = (
        IPQS_EMAIL_ENDPOINT
        + parse.quote(api_key)
        + "/"
        + parse.quote(email_value, safe="")
    )
    endpoint = f"{endpoint_base}?{parse.urlencode(QUERY_PARAMS)}"
    logging.info("IPQS request attempted for sender email.")

    try:
        with request.urlopen(endpoint, timeout=10) as resp:
            payload = resp.read().decode("utf-8", errors="ignore")
            data = json.loads(payload) if payload.strip() else {}
    except TimeoutError:
        logging.warning("IPQS request failed: timeout. Fallback used.")
        return None, "timeout"
    except Exception as exc:
        logging.warning("IPQS request failed: %s. Fallback used.", exc)
        return None, "request_error"

    if not isinstance(data, dict):
        logging.warning("IPQS request failed: invalid JSON shape. Fallback used.")
        return None, "invalid_payload"

    success = data.get("success") is True
    logging.info("IPQS request succeeded=%s", success)
    if success:
        return data, None

    message = str(data.get("message") or "").strip().lower()
    if any(marker in message for marker in INSUFFICIENT_CREDITS_MARKERS):
        logging.warning("IPQS fallback used: insufficient credits.")
        return None, "insufficient_credits"

    if data.get("timed_out") is True:
        logging.warning("IPQS fallback used: provider timed out.")
        return None, "provider_timeout"

    logging.warning("IPQS fallback used: provider unsuccessful response.")
    return None, "provider_unsuccessful"
