# Gmail add-on (client-side flow)

The add-on runs **inside Gmail** as a **Google Apps Script** project whose sources live under **`gmail-addon/`**. It serializes the open message into JSON, calls **`POST /scan`** on your backend (`API_URL`), and renders **`CardService`** UI from the response.

---

## Source map

| File | Responsibility |
|------|----------------|
| **`appsscript.json`** | Manifest: **V8** runtime, Gmail add-on triggers (**`buildHomePage`**, **`buildEmailCard`**), OAuth scopes **`gmail.addons.execute`**, **`gmail.readonly`**, **`script.external_request`**. |
| **`Main.js`** | Entry points (`buildHomePage`, `buildEmailCard`, **`switchLanguage`**) and **`CardService` navigation**. |
| **`EmailService.js`** | Reads current message (**`getPlainBody()`**, headers, snippets), URLs, attachments (Base64 inline images supported), derives **`sender_prior_thread_count`** via **`GmailApp.search`**. |
| **`ApiService.js`** | **`UrlFetchApp.fetch`** **`POST`** JSON to **`API_URL`**, status handling, **`normalizeBackendResult`**. |
| **`UiService.js`** | Card layout: assessment, risk lines, collapsible sections, **More detail**, localized copy, error card. |
| **`Config.js`** | **`API_URL`**, **`APP_NAME`**, language constants, **`TIPS`**. |

---

## Request payload (conceptual)

The add-on builds a JSON object aligned with backend expectations (see **[api-contract.md](api-contract.md)** for field names and aliases). Notable behaviors:

- **Body** is **plain text** from **`getPlainBody()`**, not full HTML MIME.
- **URLs** may come from explicit list fields and/or body parsing on the server if empty.
- **Attachments** include **inline images** suitable for QR-style analysis when present.
- **`sender_prior_thread_count`** — count of prior threads with the same sender (**180 days**, max **50** via search). Used **only** in **`verdict_engine`** moderation logic; **not** stored as a trust database.

---

## Backend URL (`API_URL`)

Set in **`gmail-addon/Config.js`**:

```javascript
const API_URL = "https://<public-host>/scan";
```

- Must be **HTTPS** (Gmail / Apps Script requirement for typical setups).
- Path must end with **`/scan`** (FastAPI route in **`phishwall_backend/main.py`**).
- After local tunnel restarts, **free ngrok hostnames change** — update **`API_URL`** and **`clasp push`** (see **[getting-started.md](getting-started.md)** §§6–9).

---

## Deploying changes

See **[getting-started.md — Running from scratch](getting-started.md#running-from-scratch-step-by-step)** §§9–10 (**`clasp push`**, Apps Script deployments, Gmail refresh).
