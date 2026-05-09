# =============================================================================
# PhishWall - single official setup / run entry point (Windows / cross-platform).
# =============================================================================
# What this script does, in order:
#   1. Verifies Python >= 3.10 is available.
#   2. cd into phishwall_backend/ (where main.py lives).
#   3. Creates a local virtualenv at phishwall_backend/.venv (idempotent).
#   4. Activates the venv for this PowerShell session.
#   5. Installs requirements.txt into the venv.
#   6. Copies .env.example -> .env if .env is missing (no secrets are baked in).
#   7. Prints the manual next steps that this script CANNOT automate
#      (ngrok auth + tunnel, gmail-addon/Config.js, clasp login + push).
#   8. By default, starts the FastAPI backend with uvicorn in the foreground
#      on http://0.0.0.0:8000 (this blocks the terminal - that is intentional).
#
# Why this script does not do everything end-to-end:
#   - ngrok requires a one-time `ngrok config add-authtoken ...` against YOUR
#     ngrok account; we cannot do that for you.
#   - The Gmail add-on lives in Google's Apps Script cloud and must be
#     deployed under YOUR Google account (`clasp login`, `clasp push`,
#     and a `scriptId` you control).
#   - Both ngrok and Apps Script are out-of-process from this repo by design.
#
# Usage:
#   # Recommended (in PowerShell, from repo root):
#   powershell -ExecutionPolicy Bypass -File .\setup.ps1
#
#   # Or from CMD double-click / `setup.bat`, which just invokes this file.
#
# Optional flags:
#   -NoStart       Install + prepare env only; do NOT start uvicorn.
#   -SkipInstall   Reuse existing venv; do not run pip install again.
# =============================================================================

[CmdletBinding()]
param(
  [switch]$NoStart,
  [switch]$SkipInstall
)

$ErrorActionPreference = "Stop"

function Write-Step($msg) {
  Write-Host ""
  Write-Host ("=== {0} ===" -f $msg) -ForegroundColor Cyan
}

function Write-Manual($msg) {
  Write-Host $msg -ForegroundColor Yellow
}

# -----------------------------------------------------------------------------
# 1. Locate repo root + backend folder
# -----------------------------------------------------------------------------
$RepoRoot   = Split-Path -Parent $MyInvocation.MyCommand.Path
$BackendDir = Join-Path $RepoRoot "phishwall_backend"

if (-not (Test-Path -LiteralPath (Join-Path $BackendDir "main.py"))) {
  Write-Error "Could not find phishwall_backend\main.py under '$BackendDir'. Run this script from the repository root."
  exit 1
}

Write-Step "1. Repository layout"
Write-Host ("Repo root : {0}" -f $RepoRoot)
Write-Host ("Backend   : {0}" -f $BackendDir)

# -----------------------------------------------------------------------------
# 2. Verify Python
# -----------------------------------------------------------------------------
Write-Step "2. Verify Python"
$pythonExe = (Get-Command python -ErrorAction SilentlyContinue)
if (-not $pythonExe) {
  Write-Error "Python is not on PATH. Install Python 3.10+ from https://www.python.org/ and re-run."
  exit 1
}

$pyVersion = & python -c "import sys; print('%d.%d' % sys.version_info[:2])"
Write-Host ("Found python {0} at {1}" -f $pyVersion, $pythonExe.Path)
$major, $minor = $pyVersion.Split('.')
if ([int]$major -lt 3 -or ([int]$major -eq 3 -and [int]$minor -lt 10)) {
  Write-Error "Python $pyVersion is too old. PhishWall requires Python 3.10 or newer."
  exit 1
}

# -----------------------------------------------------------------------------
# 3. cd into phishwall_backend
# -----------------------------------------------------------------------------
Write-Step "3. cd into phishwall_backend"
Set-Location -LiteralPath $BackendDir
Write-Host ("Current directory: {0}" -f (Get-Location).Path)

# -----------------------------------------------------------------------------
# 4. Create + activate venv
# -----------------------------------------------------------------------------
Write-Step "4. Virtualenv (.venv)"
$VenvDir       = Join-Path $BackendDir ".venv"
$VenvActivate  = Join-Path $VenvDir "Scripts\Activate.ps1"
$VenvPython    = Join-Path $VenvDir "Scripts\python.exe"

if (-not (Test-Path -LiteralPath $VenvDir)) {
  Write-Host "Creating new venv at .venv ..."
  & python -m venv .venv
} else {
  Write-Host ".venv already exists - reusing."
}

if (-not (Test-Path -LiteralPath $VenvActivate)) {
  Write-Error "Venv activation script not found at $VenvActivate. Delete .venv and re-run."
  exit 1
}

. $VenvActivate
Write-Host ("Activated venv: {0}" -f $env:VIRTUAL_ENV)

# -----------------------------------------------------------------------------
# 5. Install dependencies
# -----------------------------------------------------------------------------
Write-Step "5. Install requirements"
if ($SkipInstall) {
  Write-Host "Skipping pip install (-SkipInstall)."
} else {
  & $VenvPython -m pip install --upgrade pip --quiet
  & $VenvPython -m pip install -r requirements.txt
}

& $VenvPython -c 'import fastapi, uvicorn'
if ($LASTEXITCODE -ne 0) {
  Write-Error "Failed to import fastapi/uvicorn from venv. Re-run setup.ps1 without -SkipInstall."
  exit 1
}
Write-Host "Dependencies imported OK (fastapi, uvicorn)."

# -----------------------------------------------------------------------------
# 6. Prepare .env
# -----------------------------------------------------------------------------
Write-Step "6. Prepare .env"
$EnvExample = Join-Path $BackendDir ".env.example"
$EnvFile    = Join-Path $BackendDir ".env"

if (Test-Path -LiteralPath $EnvFile) {
  Write-Host ".env already exists - leaving it untouched."
} else {
  Copy-Item -LiteralPath $EnvExample -Destination $EnvFile
  Write-Host "Copied .env.example -> .env (no secrets pre-filled)."
}

Write-Host "Optional: edit phishwall_backend\.env to add IPQS / VT / Safe Browsing keys (the backend works without them)."

# -----------------------------------------------------------------------------
# 7. Print the manual steps this script CANNOT automate
# -----------------------------------------------------------------------------
Write-Step "7. Manual next steps (out-of-process by design)"

Write-Manual "A) ngrok (free HTTPS tunnel for Gmail Apps Script)"
Write-Manual "   - Install ngrok: https://ngrok.com/download"
Write-Manual "   - One-time auth:        ngrok config add-authtoken <YOUR_TOKEN>"
Write-Manual "   - In a SECOND terminal: ngrok http 8000"
Write-Manual "   - Copy the https://... URL it prints."

Write-Manual ""
Write-Manual "B) gmail-addon\Config.js"
Write-Manual "   - Open gmail-addon\Config.js"
Write-Manual "   - Set:   const API_URL = ""https://<your-ngrok-host>/scan"";"

Write-Manual ""
Write-Manual "C) clasp (Apps Script deploy)"
Write-Manual "   - One-time:           npm i -g @google/clasp ; clasp login"
Write-Manual "   - From repo root:     clasp push"
Write-Manual "   - If .clasp.json scriptId is not yours, run `clasp create` for your own Apps Script project first."

Write-Manual ""
Write-Manual "D) Reload Gmail and open PhishWall on any message."

# -----------------------------------------------------------------------------
# 8. Start the backend (default) or stop here (-NoStart)
# -----------------------------------------------------------------------------
if ($NoStart) {
  Write-Step "8. Done (env ready)"
  Write-Host "To start the backend later:"
  Write-Host "  cd phishwall_backend"
  Write-Host "  .\.venv\Scripts\Activate.ps1"
  Write-Host "  python -m uvicorn main:app --host 0.0.0.0 --port 8000"
  exit 0
}

Write-Step "8. Starting FastAPI on http://0.0.0.0:8000 (Ctrl+C to stop)"
Write-Host "Health check (in a NEW terminal): http://127.0.0.1:8000/health  ->  {""status"":""ok""}"
Write-Host ""

& $VenvPython -m uvicorn main:app --host 0.0.0.0 --port 8000
