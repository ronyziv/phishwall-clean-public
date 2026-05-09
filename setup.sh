#!/usr/bin/env bash
# =============================================================================
# PhishWall — single official setup / run entry point (macOS / Linux).
#
# Mirror of setup.ps1: see that file for full rationale and limitations.
# Usage:
#   chmod +x setup.sh
#   ./setup.sh                # install + start backend
#   ./setup.sh --no-start     # install only, do not start uvicorn
#   ./setup.sh --skip-install # reuse existing venv
# =============================================================================
set -euo pipefail

NO_START=0
SKIP_INSTALL=0
for arg in "$@"; do
  case "$arg" in
    --no-start)     NO_START=1 ;;
    --skip-install) SKIP_INSTALL=1 ;;
    *) echo "Unknown flag: $arg"; exit 2 ;;
  esac
done

step()    { printf '\n=== %s ===\n' "$1"; }
manual()  { printf '%s\n' "$1"; }

REPO_ROOT="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
BACKEND_DIR="$REPO_ROOT/phishwall_backend"

if [[ ! -f "$BACKEND_DIR/main.py" ]]; then
  echo "Could not find $BACKEND_DIR/main.py — run this script from the repo root." >&2
  exit 1
fi

step "1. Repository layout"
echo "Repo root : $REPO_ROOT"
echo "Backend   : $BACKEND_DIR"

step "2. Verify Python"
PYTHON_BIN=""
for c in python3 python; do
  if command -v "$c" >/dev/null 2>&1; then PYTHON_BIN="$c"; break; fi
done
if [[ -z "$PYTHON_BIN" ]]; then
  echo "Python is not on PATH. Install Python 3.10+." >&2
  exit 1
fi
PY_VER="$("$PYTHON_BIN" -c 'import sys;print("%d.%d"%sys.version_info[:2])')"
echo "Found $PYTHON_BIN ($PY_VER)"
"$PYTHON_BIN" -c 'import sys;sys.exit(0 if sys.version_info >= (3,10) else 1)' || {
  echo "Python $PY_VER is too old. PhishWall requires 3.10+." >&2
  exit 1
}

step "3. cd into phishwall_backend"
cd "$BACKEND_DIR"
pwd

step "4. Virtualenv (.venv)"
if [[ ! -d .venv ]]; then
  "$PYTHON_BIN" -m venv .venv
else
  echo ".venv already exists — reusing."
fi
# shellcheck disable=SC1091
source .venv/bin/activate
echo "Activated venv: ${VIRTUAL_ENV:-?}"

step "5. Install requirements"
if [[ "$SKIP_INSTALL" -eq 1 ]]; then
  echo "Skipping pip install (--skip-install)."
else
  python -m pip install --upgrade pip --quiet
  python -m pip install -r requirements.txt
fi
python -c 'import fastapi, uvicorn; print("deps ok ->", fastapi.__name__, uvicorn.__name__)'

step "6. Prepare .env"
if [[ -f .env ]]; then
  echo ".env already exists — leaving it untouched."
else
  cp .env.example .env
  echo "Copied .env.example -> .env (no secrets pre-filled)."
fi
echo "Optional: edit phishwall_backend/.env to add IPQS / VT / Safe Browsing keys (backend works without them)."

step "7. Manual next steps (out-of-process by design)"
manual "A) ngrok (free HTTPS tunnel for Gmail Apps Script)"
manual "   - Install ngrok: https://ngrok.com/download"
manual "   - One-time auth:        ngrok config add-authtoken <YOUR_TOKEN>"
manual "   - In a SECOND terminal: ngrok http 8000"
manual "   - Copy the https://... URL it prints."
manual ""
manual "B) gmail-addon/Config.js"
manual "   - Open gmail-addon/Config.js"
manual "   - Set:   const API_URL = \"https://<your-ngrok-host>/scan\";"
manual ""
manual "C) clasp (Apps Script deploy)"
manual "   - One-time:           npm i -g @google/clasp ; clasp login"
manual "   - From repo root:     clasp push"
manual "   - If .clasp.json scriptId is not yours, run 'clasp create' for your own Apps Script project first."
manual ""
manual "D) Reload Gmail and open PhishWall on any message."

if [[ "$NO_START" -eq 1 ]]; then
  step "8. Done (env ready)"
  echo "To start the backend later:"
  echo "  cd phishwall_backend"
  echo "  source .venv/bin/activate"
  echo "  python -m uvicorn main:app --host 0.0.0.0 --port 8000"
  exit 0
fi

step "8. Starting FastAPI on http://0.0.0.0:8000 (Ctrl+C to stop)"
echo "Health check (in a NEW terminal): http://127.0.0.1:8000/health  ->  {\"status\":\"ok\"}"
echo
exec python -m uvicorn main:app --host 0.0.0.0 --port 8000
