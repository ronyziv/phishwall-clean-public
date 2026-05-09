"""
Central outbound HTTP timeouts and parallel scan limits (environment-tunable).

All timeouts are socket read/connect budgets for urllib; on failure scanners fall back
to local heuristics and info messages — response shape stays the same (API-stable).
"""

import os


def _pos_float(env_name: str, default: float) -> float:
    try:
        v = float(os.environ.get(env_name, "").strip())
        return v if v > 0.1 else default
    except ValueError:
        return default


def _pos_int(env_name: str, default: int, minimum: int = 2) -> int:
    try:
        v = int(os.environ.get(env_name, "").strip())
        if v < minimum:
            return default
        return v
    except ValueError:
        return default


# --- HTTP timeouts (seconds) ---
IPQS_EMAIL_TIMEOUT = _pos_float("PHISHWALL_IPQS_EMAIL_TIMEOUT", 5.0)
IPQS_URL_TIMEOUT = _pos_float("PHISHWALL_IPQS_URL_TIMEOUT", 5.0)
GSB_TIMEOUT = _pos_float("PHISHWALL_GSB_TIMEOUT", 5.0)
VT_DOMAIN_TIMEOUT = _pos_float("PHISHWALL_VT_DOMAIN_TIMEOUT", 5.0)
QR_FETCH_TIMEOUT = _pos_float("PHISHWALL_QR_FETCH_TIMEOUT", 4.0)

# --- Parallelism caps ---
SCANNER_MAX_WORKERS = _pos_int("PHISHWALL_SCANNER_MAX_WORKERS", 8, minimum=2)
