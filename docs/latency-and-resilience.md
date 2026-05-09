# Latency and resilience (parallel checks, timeouts, fallbacks)

**Documentation index:** **[README.md](README.md)**.

This document describes how PhishWall keeps **`POST /scan`** responsive when many checks run, how outbound calls are bounded, and how the API stays **stable** when optional services misbehave. It aligns with **`phishwall_backend/services/scanner_pipeline.py`**, **`scanners/external_http_config.py`**, and the individual scanners (`sender`, `url`, `qr`, etc.).

---

## What used to block (conceptual baseline)

Older or naïve orchestration would run **every** heuristic and **every** remote lookup **one after another**. That multiplies latency: for example four independent context-only stages plus N URL reputations becomes roughly **sum(stage₁…stage₄) + sum(lookup₁…lookupₙ)** plus fixed parsing work.

The current design avoids that where dependencies allow: **stages that only read `ScanContext` and prior merged state shards** run together within a phase, and **per-URL reputation** work runs concurrently up to caps.

---

## What runs in parallel today

### Pipeline phases (`ScannerPipeline`)

Execution is **three phases** so that **priority / BEC logic** sees keyword and sender summaries from phase 1:

| Phase | Scanners (by name) | Parallelism |
|-------|---------------------|-------------|
| **1** | `keywords`, `language`, `sender`, `time` | All eligible adapters (**`applies`**) run concurrently via **`ThreadPoolExecutor`** (bounded by **`PHISHWALL_SCANNER_MAX_WORKERS`**). |
| **2** | `priority_threats` | Sequential (depends on merged state from phase 1). |
| **3** | `qr`, `link_base`, `url`, `attachments` | Eligible scanners run concurrently, same executor cap. |

Inside **QR** (`QrScannerAdapter` / **`qr_scanner.py`**), attachment QR decoding and fetching **QR-linked resources** can overlap where safe.

### URL remote reputation (`url_scanner.py`)

For up to **`REMOTE_LOOKUP_LIMIT`** URLs (5), **`_safe_remote_row`** runs in a thread pool so **each URL’s IPQS (+ GSB fallback) budget** overlaps instead of stacking serially.

### Sender reputation (`sender_scanner.py`)

Where multiple addresses / VirusTotal lookups apply, parallel patterns reduce wall-clock compared to strictly serial calls.

---

## Timeouts and environment tuning

Outbound HTTP uses **urllib** with explicit **socket timeouts** (connect + read as one budget). Central defaults live in **`scanners/external_http_config.py`**:

| Variable | Role (typical default) |
|----------|-------------------------|
| **`PHISHWALL_IPQS_EMAIL_TIMEOUT`** | IPQS mailbox / email APIs used from sender enrichment. |
| **`PHISHWALL_IPQS_URL_TIMEOUT`** | IPQS URL reputation. |
| **`PHISHWALL_GSB_TIMEOUT`** | Google Safe Browsing. |
| **`PHISHWALL_VT_DOMAIN_TIMEOUT`** | VirusTotal domain lookups when enabled. |
| **`PHISHWALL_QR_FETCH_TIMEOUT`** | Fetching linked resources discovered from QR payloads. |
| **`PHISHWALL_SCANNER_MAX_WORKERS`** | Upper bound on threads for pipeline phases and URL batch reputation. |

Template: **`phishwall_backend/.env.example`**.

**Why urllib timeouts:** they return control to Python after a bounded wait instead of hanging on a slow peer. Scanners already treat timeout / error as **degraded remote signal** and continue with **local heuristics** and **`infoFindings`** where appropriate.

---

## Required vs optional (for latency and data quality)

| Category | Behavior |
|----------|----------|
| **Core pipeline** | Keyword, language, sender, time, QR, link-base, URL, attachment, and priority-threat **adapters always exist** in **`build_default_pipeline()`**. The service always returns the same **JSON shape** from **`scan_service.analyze_email`**. |
| **Remote enrichment** | **Optional**: without API keys, IPQS / GSB / VT paths are **skipped or short-circuited** with informational messages—scoring still completes from local rules. |
| **Per-stage failure** | If a single adapter raises unexpectedly, **`_run_phase`** records an **`infoFindings`** line and **omits that stage’s penalties** so the request still completes (**no 500** from that stage alone). *Tradeoff:* a bug in one stage could **under-penalize** until fixed; the alternative (fail the whole scan) would harm availability. |

---

## Fallback strategy (slow, unavailable, or error)

1. **HTTP timeout or transport error** inside a scanner: catch at the **HTTP boundary** (e.g. `_ipqs_lookup`, `_gsb_lookup`), return **no remote flag**, append a short **info** string (e.g. “lookup timed out”), keep **local** URL/sender/attachment signals.
2. **Missing API key**: treat as **disabled**; do not block the pipeline.
3. **Unexpected exception in `run()`**: pipeline catches, logs, adds **`infoFindings`**, **empty breakdown** for that stage only; other stages still contribute to **`scoreBreakdown`** and verdict.

**Stable result:** **`totalPenalty`** and **`maliciousScore`** always derive from whatever breakdown was accumulated; verdict logic in **`verdict_engine.py`** still runs on that partial-but-valid snapshot.

---

## Tradeoffs considered

| Choice | Benefit | Cost |
|--------|---------|------|
| **Phased parallelism** vs fully async | Simple integration with existing sync urllib + clear **dependency order** (BEC after keywords/sender). | Phase 2 still waits for **slowest** of phase 1; cannot overlap phase 3 with phase 1. |
| **Thread pools** vs asyncio | Minimal rewrite; works with blocking urllib. | Thread overhead; GIL mostly irrelevant for I/O-bound waits. |
| **Per-URL parallel reputation** | Wall time ≈ **max** lookup, not **sum** (within batch cap). | Up to **N × timeout** worst-case **socket** pressure if all peers stall—mitigated by **low defaults** and **worker cap**. |
| **Swallow adapter exceptions** | User always gets a **200 + scan body**; partial intelligence beats total failure. | Possible **false negatives** if a stage silently dies—mitigated by **logging** and **`infoFindings`**. |

---

## Verification

- **Automated:** **`tests/test_parallel_execution.py`** asserts wall-clock for (1) a **two-scanner phase-1** pipeline with artificial delays stays near **one** sleep, not two, and (2) **URL** `scan_urls` with mocked slow `_safe_remote_row` scales like **parallel** batch, not serial sum.
- **Operational:** with logging at **DEBUG**, **`scan_service.analyze_email`** logs **`analyze_email pipeline_wall_ms=…`** to compare before/after tuning (keys, network, hardware).

Run from **`phishwall_backend/`**:

```bash
python -m unittest discover -s tests -v
```

---

## Related docs

- **[Architecture](architecture.md)** — pipeline diagram and phase list.
- **[API contract](api-contract.md)** — response fields unchanged by these behaviors.
- **[Getting started](getting-started.md)** — `.env` and smoke tests.
