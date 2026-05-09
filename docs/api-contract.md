# PhishWall HTTP API contract (canonical)

This file is the **authoritative JSON wire specification** for the FastAPI service in `phishwall_backend/`. It matches the Pydantic models in [`phishwall_backend/models.py`](../phishwall_backend/models.py) and the handlers in [`phishwall_backend/main.py`](../phishwall_backend/main.py). The implementation builds the scan result in [`phishwall_backend/services/scan_service.py`](../phishwall_backend/services/scan_service.py). **Documentation index:** **[README.md](README.md)**. For **how `scoreBreakdown`, `maliciousScore`, and `verdict` relate conceptually**, see **[scoring-and-verdict.md](scoring-and-verdict.md)**. For **parallel checks, timeouts, and failure behavior without changing this wire shape**, see **[latency-and-resilience.md](latency-and-resilience.md)**.

**Secondary references (generated, not guaranteed for prose accuracy):** with the server running, OpenAPI UI is at [`/docs`](http://127.0.0.1:8000/docs) and the schema at [`/openapi.json`](http://127.0.0.1:8000/openapi.json).

---

## `GET /health`

**Response** `200` — body shape `HealthResponse`:

```json
{
  "status": "ok"
}
```

---

## `POST /scan`

**Content-Type:** `application/json`

**Success** `200` — body shape `ScanResponse`.

**Validation failure** `422` — body shape `ErrorResponse` (`details` carries Pydantic’s message string).

**Unhandled server error** `500` — body shape `ErrorResponse` with generic `details` (logged server-side).

---

### Compatibility and mapping behavior

These rules affect how a JSON body is interpreted before scoring:

| Behavior | Implementation |
|----------|----------------|
| **Unknown JSON fields** | Ignored (`ScanRequest.model_config["extra"] = "ignore"`). Clients may add forward-compatible metadata without breaking the API. |
| **Sender field name** | The Python attribute is `from_`; the **JSON key must be `from`** (Pydantic alias). |
| **Timestamp for scanners** | `ScanContext.sent_at` is filled from the first non-empty of `date`, then `sent_at`, then `timestamp` (`scan_service.analyze_email`). Empty strings fall through. |
| **URLs** | If `urls` is missing or empty after parsing, the backend extracts `http(s)://…` tokens from `body` (`normalize_urls` in `scanner_pipeline.py`). |
| **`sender_prior_thread_count`** | Clamped to **0–200**; invalid types fall back to **0** (`analyze_email`). |
| **`comments` vs `riskIndicators`** | Both are set to the same list of risk strings from the pipeline (`scan_service.py`). Kept for backward compatibility with older clients that only read `comments`. |
| **`reasons`** | Verdict “strong indicators” text from `verdict_engine.build_verdict` (not the same list as `riskIndicators`, though themes may overlap). |
| **`score` vs `maliciousScore`** | `score` is safety-oriented **0–100** (higher = safer). `maliciousScore = 100 - score`. The Gmail add-on prominently displays **`maliciousScore`** (`ApiService.normalizeBackendResult`). |
| **`urlRaw` vs `urlApplied`** | Only **`urlApplied`** (≈ **`floor(urlRaw × 0.7)`** toward zero) is included in `scoreBreakdown.totalPenalty`. **`urlRaw`** is diagnostic only (`UrlScannerAdapter`). |
| **`qrSummary` shape** | If the QR stage does **not** run (no attachments **and** no URLs), defaults omit linked-resource keys (see § Response object — `qrSummary`). When QR runs, the pipeline adds extra optional counters (linked scans, QR-in-URL cues). |
| **Latency / parallelism** | Independent scanner stages and many outbound reputation/QR fetches may run **concurrently** (`scanner_pipeline.py`, `sender_scanner.py`, `url_scanner.py`, `qr_scanner.py`). **`POST /scan` JSON** is unchanged; completion time is typically bounded by configurable HTTP timeouts (`PHISHWALL_*` in **`scanners/external_http_config.py`** and **`phishwall_backend/.env.example`**). |

---

### Request body (`ScanRequest`)

#### Top-level fields

| JSON field | Type | Required | Default | Constraints / notes |
|------------|------|----------|---------|---------------------|
| `subject` | string | no | `""` | max 300 chars |
| `from` | string | no | `""` | max 320; **required key name** (not `from_`) |
| `to` | string[] | no | `[]` | max 200 items |
| `cc` | string[] | no | `[]` | max 200 items |
| `bcc` | string[] | no | `[]` | max 200 items |
| `reply_to` | string | no | `""` | max 320 |
| `body` | string | no | `""` | max 200,000 chars; drives URL inference |
| `body_snippet` | string | no | `""` | max 5,000 |
| `date` | string | no | `""` | max 100; participates in sent-time parsing |
| `sent_at` | string | no | `""` | max 100; second choice for sent time |
| `timestamp` | string | no | `""` | max 100; third choice for sent time |
| `urls` | string[] | no | `[]` | max 300 items |
| `attachments` | object[] | no | `[]` | max 100 items; see `AttachmentInput` |
| `sender_prior_thread_count` | integer | no | `0` | **0–200**; Gmail add-on supplies live mailbox count |

#### `AttachmentInput` (each element of `attachments`)

| JSON field | Type | Default | Constraints / notes |
|------------|------|---------|----------------------|
| `filename` | string | `""` | max 260 |
| `mimeType` | string | `""` | max 120 |
| `contentBase64` | string | `""` | max 2,000,000 chars (raw Base64 payload) |

---

#### Exact request JSON (minimal, Gmail-shaped)

The bundled add-on sends the fields below (`EmailService.extractEmailData`). Other fields (`to`, `cc`, dates, …) remain optional for direct API testers.

```json
{
  "subject": "Hello",
  "from": "sender@example.com",
  "body": "Please pay the invoice today http://example.com",
  "body_snippet": "Please pay the invoice today http://example.com",
  "urls": ["http://example.com"],
  "attachments": [],
  "sender_prior_thread_count": 0
}
```

#### Exact request JSON (with one attachment)

`contentBase64` is truncated here for readability; production bodies must ship full Base64 of the raw bytes.

```json
{
  "subject": "Report",
  "from": "\"Reports\" <alerts@vendor.example>",
  "to": ["user@company.example"],
  "reply_to": "no-reply@vendor.example",
  "body": "See attached.",
  "body_snippet": "See attached.",
  "date": "Sat, 9 May 2026 12:00:00 +0300",
  "urls": [],
  "attachments": [
    {
      "filename": "summary.pdf",
      "mimeType": "application/pdf",
      "contentBase64": "JVBERi0xLjQK..."
    }
  ],
  "sender_prior_thread_count": 3
}
```

---

### Successful response (`ScanResponse`)

#### Top-level fields

| JSON field | Type | Notes |
|------------|------|-------|
| `score` | int | 0–100, higher = safer |
| `maliciousScore` | int | `100 - score`, higher = more malicious |
| `verdict` | string | One of `Safe`, `Suspicious`, `Dangerous / Do Not Open` (`verdict_engine.py`) |
| `color` | string | Hex color for UI (`#2E7D32`, `#F57C00`, `#C62828`) |
| `icon` | string | Emoji marker for UI (`🟢`, `🟠`, `⛔`) |
| `verdictReasoning` | string | Human-readable explanation |
| `recommendation` | string | Short action guidance |
| `familiarSenderCalibration` | bool | `true` only when calibrated “familiar sender” moderation applies **and** verdict is **`Suspicious`** |
| `links` | int | Count of URLs in scanning context (`len(context.urls)` after normalization) |
| `riskWords` | int | Keyword scanner unique match count |
| `comments` | string[] | Same as `riskIndicators` |
| `riskIndicators` | string[] | Concatenated risk findings from scanners |
| `infoFindings` | string[] | Non-risk notes (counts, disabled reputation, benign PDF notices, …) |
| `reasons` | string[] | Verdict-layer “strong indicators” |
| `scoreBreakdown` | object | See below |
| `attachmentSummary` | object | Attachment scanner summary |
| `urlSummary` | object | URL scanner summary |
| `senderSummary` | object | Sender scanner summary |
| `languageSummary` | object | Language heuristic penalty |
| `timeSummary` | object | Sending-time analyzer |
| `qrSummary` | object | QR pipeline summary (shape varies slightly; see below) |
| `priorityThreatSummary` | object | BEC / priority threat summary |

#### `scoreBreakdown`

| Field | Type | Role |
|-------|------|------|
| `keywords` … `attachments` | int | Per-bucket penalties |
| `totalPenalty` | int | Sum of buckets that affect score (**excludes `urlRaw`**) |

Buckets included in **`totalPenalty`**: `keywords`, `language`, `sender`, `time`, `qr`, `priorityThreats`, `linkBase`, `urlApplied`, `attachments`.

#### `qrSummary`

**Always present.** If the QR stage runs (attachments **or** URLs exist), typical keys:

| Field | Type |
|-------|------|
| `qrDetected` | bool |
| `decodedCount` | int |
| `scannedImages` | int |
| `decodedPayloads` | string[] |
| `qrLinkedCandidates` | int |
| `qrLinkedDetected` | bool |
| `linkedScannedCount` | int |
| `linkedDecodedCount` | int |
| `riskPenalty` | int |

If the QR stage **does not run** (`QrScannerAdapter.applies` is false — **no** attachments and **no** URLs), **`analyze_email`** injects defaults **without** the `qrLinked*` / `linked*` keys:

```json
{
  "qrDetected": false,
  "decodedCount": 0,
  "scannedImages": 0,
  "decodedPayloads": [],
  "riskPenalty": 0
}
```

#### `priorityThreatSummary`

```json
{
  "becDetected": true,
  "becSignalCount": 2,
  "riskPenalty": 16
}
```

(Values depend on message content; `becSignalCount` can be `0`–`4` for scoring paths in `PriorityThreatScannerAdapter`.)

#### `timeSummary`

`hour` and `weekday` are either integers or JSON `null` when the time parser does not populate them.

---

#### Exact response JSON (real output sample)

The following JSON was produced by calling `analyze_email` with the **minimal request example** above on a dev machine **without** optional reputation API keys. Human-readable strings (e.g. IPQS / reputation notices) **will differ** when keys and network behavior change; field names and nesting **do not**.

```json
{
  "score": 75,
  "maliciousScore": 25,
  "verdict": "Suspicious",
  "color": "#F57C00",
  "icon": "🟠",
  "verdictReasoning": "This email shows suspicious indicators, including BEC-style impersonation pattern.",
  "recommendation": "Avoid clicking links or opening attachments until you verify the sender through a trusted channel.",
  "familiarSenderCalibration": false,
  "reasons": [
    "BEC-style impersonation pattern"
  ],
  "links": 1,
  "riskWords": 0,
  "comments": [
    "Email content references 'X' while sender domain is 'example.com'.",
    "BEC-style pattern detected: financial/urgent request with impersonation or social-pressure behavior."
  ],
  "riskIndicators": [
    "Email content references 'X' while sender domain is 'example.com'.",
    "BEC-style pattern detected: financial/urgent request with impersonation or social-pressure behavior."
  ],
  "infoFindings": [
    "IPQS unavailable for sender@example.com; used local checks.",
    "Found 1 link(s) in the email.",
    "Remote URL reputation is disabled (missing API keys)."
  ],
  "scoreBreakdown": {
    "keywords": 0,
    "language": 0,
    "sender": 8,
    "time": 0,
    "qr": 0,
    "priorityThreats": 16,
    "linkBase": 1,
    "urlRaw": 0,
    "urlApplied": 0,
    "attachments": 0,
    "totalPenalty": 25
  },
  "attachmentSummary": {
    "count": 0,
    "safePdfCount": 0,
    "pdfWithLinksCount": 0,
    "executableCount": 0,
    "unknownAttachmentCount": 0
  },
  "urlSummary": {
    "count": 1,
    "unresolvedHosts": 0,
    "ipqsFlagged": 0,
    "gsbFlagged": 0
  },
  "senderSummary": {
    "email": "sender@example.com",
    "domain": "example.com",
    "emailsChecked": 1,
    "ipqsFlagged": 0,
    "vtFlagged": 0
  },
  "languageSummary": {
    "heuristicPenalty": 0
  },
  "timeSummary": {
    "analyzed": false,
    "riskPenalty": 0,
    "becContext": false,
    "atoContext": false,
    "hour": null,
    "weekday": null
  },
  "qrSummary": {
    "qrDetected": false,
    "decodedCount": 0,
    "scannedImages": 0,
    "decodedPayloads": [],
    "qrLinkedCandidates": 0,
    "qrLinkedDetected": false,
    "linkedScannedCount": 0,
    "linkedDecodedCount": 0,
    "riskPenalty": 0
  },
  "priorityThreatSummary": {
    "becDetected": true,
    "becSignalCount": 2,
    "riskPenalty": 16
  }
}
```

---

### Error response body (`ErrorResponse`)

```json
{
  "error": "Validation error",
  "details": "…"
}
```

For `500` responses, `details` is the fixed string `"Internal server error"` from `main.py` (no stack trace in the body).

---

### Client note: Gmail add-on normalization

[`gmail-addon/ApiService.js`](../gmail-addon/ApiService.js) `normalizeBackendResult` maps the HTTP JSON into card state: it **only** surfaces a subset (`maliciousScore`, `verdict`, `icon`, reasoning, arrays, `scoreBreakdown`, `reasons`, etc.). Integrators who bypass the add-on should treat **`ScanResponse`** as the full contract.
