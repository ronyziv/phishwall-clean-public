# Submission checklist

Use this only as a final sanity check. The root [`README.md`](../README.md) is the main submission document.

## Include

- `README.md`, `docs/`, `gmail-addon/`, `phishwall_backend/`, `setup.ps1`, `setup.bat`, `setup.sh`, `.clasp.json`, `.gitignore`, `system_img.png`, and `docs/screenshots/addon_en.png`.
- `phishwall_backend/.env.example` with variable names only.
- `gmail-addon/Config.js` with `https://YOUR_PUBLIC_HOST_HERE/scan` before public commit.

## Exclude

- `.env`, API keys, live ngrok URLs, local tunnel hosts, caches, logs, virtualenvs, and `__pycache__`.

## Smoke checks

From `phishwall_backend/`:

```powershell
python -m unittest discover -s tests -v
```

With the backend running:

```powershell
Invoke-RestMethod http://127.0.0.1:8000/health
```

Expected health response:

```json
{"status":"ok"}
```
