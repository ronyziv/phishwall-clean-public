# Getting started (PhishWall)

This guide is written so a reviewer can run the project **from scratch without guessing**. There is **one official setup path** — the `setup.*` script at the repo root — followed by **three minimal manual steps** that cannot be automated (ngrok, `Config.js`, `clasp push`). The longer step-by-step walkthrough at the end of this file is an **explanation of what the script does**, not an alternative flow.

- Documentation hub → **[docs/README.md](README.md)**
- Canonical HTTP JSON → **[api-contract.md](api-contract.md)**
- Score & verdict → **[scoring-and-verdict.md](scoring-and-verdict.md)**

---

## 0. Prerequisites (install once)

| Tool | Why |
|------|-----|
| **Python 3.10+** | Runs **`phishwall_backend/`** (FastAPI + uvicorn). |
| **ngrok** (or another HTTPS tunnel) | Gmail Apps Script needs **HTTPS**; it cannot call `http://127.0.0.1`. Install from [ngrok.com](https://ngrok.com/), then run **`ngrok config add-authtoken …`** once. |
| **Node.js + npm** + **clasp** | Required to push the add-on to Google Apps Script: **`npm i -g @google/clasp`**, then **`clasp login`**. |
| **Google account** | The Gmail add-on must be deployed under **your** Apps Script project (`clasp create` if `.clasp.json` is not yours). |

---

## 1. Run the official setup script (repo root)

| OS | Command (from repo root) |
|----|--------------------------|
| **Windows (CMD)** | `setup.bat` |
| **Windows (PowerShell)** | `powershell -ExecutionPolicy Bypass -File .\setup.ps1` |
| **macOS / Linux** | `chmod +x setup.sh && ./setup.sh` |

What the script does automatically:

1. Verifies **Python ≥ 3.10** is on `PATH`.
2. `cd`s into **`phishwall_backend/`** (the only folder where `python -m uvicorn main:app` works).
3. Creates **`phishwall_backend/.venv`** if missing, activates it.
4. Installs **`requirements.txt`** into the venv.
5. Copies **`.env.example`** → **`.env`** if there is no `.env` (no secrets pre-filled).
6. Prints the **manual next steps** (§§2–4 below).
7. Starts FastAPI on **`http://0.0.0.0:8000`** in the foreground.

Optional flags:

| Flag (PowerShell / .bat) | Flag (Linux/macOS) | Effect |
|--------------------------|---------------------|--------|
| `-NoStart` | `--no-start` | Install + prepare env only; do not start uvicorn. |
| `-SkipInstall` | `--skip-install` | Reuse existing venv (skip pip install). |

Verify it is alive (in **another** terminal — Terminal C is fine):

```powershell
Invoke-RestMethod http://127.0.0.1:8000/health
# -> {"status":"ok"}
```

> Leave the script’s terminal (Terminal A) running. Closing it stops the API.

---

## 2. Manual step — start an HTTPS tunnel (Terminal B)

Gmail Apps Script can only reach **public HTTPS**. Open a **second** terminal and:

```powershell
ngrok http 8000
```

Copy the HTTPS URL from the **Forwarding** line. Strong sanity check (in a browser): `https://<YOUR-NGROK-HOST>/health` must return the **same** `{"status":"ok"}` JSON as `http://127.0.0.1:8000/health`. Leave Terminal B running.

> Free ngrok hostnames change every restart; re-do §3 each time.

---

## 3. Manual step — point the add-on at your tunnel

Open **`gmail-addon/Config.js`** and set:

```javascript
const API_URL = "https://<your-ngrok-host>/scan";
```

Rules:

- Must start with **`https://`**.
- Must end with **`/scan`** (the FastAPI route in `phishwall_backend/main.py`).
- Do not commit a personal ngrok URL to a public fork — keep the **`YOUR_PUBLIC_HOST_HERE`** placeholder there before pushing.

---

## 4. Manual step — `clasp push` to Google Apps Script

`.clasp.json` lives at the repo root with `"rootDir": "gmail-addon"`. Run from the **repo root**:

```powershell
clasp push      # on some Windows setups: clasp.cmd push
```

If `.clasp.json`’s `scriptId` is the author’s and you do not have access, run **`clasp create`** first to create your own Apps Script project, paste the new `scriptId` into `.clasp.json`, then `clasp push`.

In Apps Script: **Deploy → Manage deployments** → make sure the Gmail add-on deployment is current. Reload Gmail, open any message, run PhishWall.

You should **not** see `[Tunnel offline …]` errors once Terminals A + B are up and `API_URL` matches the live ngrok host.

---

## Why this is the cleanest realistic setup

| Auto-doable | Yes |
|-------------|-----|
| Verify Python and pin a venv | Yes (`setup.*`) |
| Install Python deps | Yes (`setup.*`) |
| Create local `.env` | Yes (`setup.*`) |
| Start FastAPI | Yes (`setup.*`) |

| Cannot be auto-done | Why |
|---------------------|-----|
| **ngrok auth + tunnel** | Requires your ngrok account token + an interactive process. |
| **`Config.js` API_URL** | Depends on the URL ngrok gives you each session. |
| **Gmail add-on deploy** | Requires `clasp login` against **your** Google account, an Apps Script project you own (`scriptId`), and Google’s deploy UI. |

A single one-click flow would either need to bake in someone’s ngrok token (insecure), or take over the reviewer’s Google session (impossible), so the assignment naturally requires one script + three documented manual steps.

---

## Secrets and tuning (`.env`)

| Variable | Role |
|---------|------|
| `IPQS_API_KEY`, `GOOGLE_SAFE_BROWSING_API_KEY`, `VT_API_KEY` | Optional enrichment (service works without them). |
| `PHISHWALL_IPQS_EMAIL_TIMEOUT`, `PHISHWALL_IPQS_URL_TIMEOUT`, `PHISHWALL_GSB_TIMEOUT`, `PHISHWALL_VT_DOMAIN_TIMEOUT`, `PHISHWALL_QR_FETCH_TIMEOUT` | Seconds for outbound urllib calls (defaults in `scanners/external_http_config.py`). |
| `PHISHWALL_SCANNER_MAX_WORKERS` | Cap on parallel scanner / fan-out threads. |

Use **`KEY=value`** — no spaces around **`=`**.

---

## Tests

After `setup.*` finishes (with or without `-NoStart`):

```powershell
cd phishwall_backend
.\.venv\Scripts\Activate.ps1     # Windows; on Unix: source .venv/bin/activate
python -m unittest discover -s tests -v
```

`tests/test_parallel_execution.py` checks wall-clock behaviour for parallel phases and batched URL reputation — see **[latency-and-resilience.md](latency-and-resilience.md)**.

---

## Common issues

| Symptom | Likely fix |
|---------|------------|
| **`Could not import module "main"`** | You are not in `phishwall_backend/`. Re-run `setup.*` from the repo root — it `cd`s there for you. |
| Port **8000 in use** | Stop the other program, or change both `--port` (uvicorn) and `ngrok http <port>`. |
| ngrok **502** | Tunnel is up but nothing on `localhost:8000` → start `setup.*` first, then `ngrok http 8000`. |
| **`ERR_NGROK_3200`**, ngrok “offline”, **404** HTML in the add-on | Tunnel stopped or free hostname changed. Restart `ngrok http 8000`, paste new URL into `Config.js`, `clasp push`. |
| Add-on POST errors | `API_URL` must be `https://…/scan`, run `clasp push`, refresh Gmail / redeploy in Apps Script. |
| PowerShell: “running scripts is disabled” | Use `setup.bat`, or invoke `setup.ps1` with `-ExecutionPolicy Bypass` as shown in §1. |

---

## What `setup.*` is doing under the hood (for the curious)

If you prefer to do the equivalent of the script by hand — for debugging, or to understand each step — these are the same actions, in order. **Do not** mix this with running `setup.*`; it is the same flow, written out.

```powershell
# 1. From repo root
cd phishwall_backend

# 2. Create + activate venv
python -m venv .venv
.\.venv\Scripts\Activate.ps1                # Unix: source .venv/bin/activate

# 3. Install deps
python -m pip install --upgrade pip
python -m pip install -r requirements.txt

# 4. Local .env
copy .env.example .env                       # Unix: cp .env.example .env

# 5. Start FastAPI
python -m uvicorn main:app --host 0.0.0.0 --port 8000
```

Steps 6–8 (ngrok, `Config.js`, `clasp push`) match §§2–4 above.

---

## External services (optional)

| Service | Code | Role |
|---------|------|------|
| IPQS Email | `ipqs_email_client.py`, `sender_scanner.py` | Sender / email reputation |
| VirusTotal | `sender_scanner.py` | Sender domain VT stats |
| IPQS URL | `url_scanner.py` | URL reputation |
| Google Safe Browsing | `url_scanner.py` | URL fallback |
