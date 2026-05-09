# Design decisions and threat focus

**Documentation index:** **[README.md](README.md)**.

## Threat focus (design rationale)

Public reporting consistently emphasises phishing—especially **QR / quishing**, **BEC-style pressure**, **impersonation**, **suspicious URLs**, and **dangerous attachments**.

Sources: [Israel National Cyber Directorate annual report](https://www.gov.il/en/pages/2025report), [Microsoft Threat Intelligence – Email threat landscape Q1 2026](https://www.microsoft.com/en-us/security/blog/2026/04/30/email-threat-landscape-q1-2026-trends-and-insights/).

Scoring is **additive and rule-based**: every bucket writes into **`scoreBreakdown`**, but **`totalPenalty`** (and thus **`maliciousScore`**) uses only a **fixed subset** of keys—see **[Scoring & verdict](scoring-and-verdict.md)**. In particular **`urlRaw`** is transparent; **`urlApplied`** enters the sum. **Verdict** is a **separate** policy layer in **`verdict_engine.py`**.

| Threat category | What is checked | Score impact | Implemented in |
|---|---|---|---|
| **QR / “quishing”** | QR payloads in images, QR-like links, limited linked-content decode | Adds **`qr`**. Important but capped, so repeated QR paths do not over-inflate the score. | `qr_scanner.py`, `QrScannerAdapter` |
| **BEC / priority framing** | Finance/urgency phrases in subject/sender/body (`priority_threat_keywords.json`), keyword+finance coupling, sender-derived impersonation hints from earlier outputs | Adds **`priorityThreats`**. “Pressure” is not inferred from keyword score alone without finance/lexical cues. | `priority_threat_keywords.json`, `PriorityThreatScannerAdapter` |
| **Sender & brand trust** | Display-name/domain mismatch, punycode, look-alikes on **sender**, optional IPQS/VirusTotal | Adds **`sender`**. Look-alikes on **link hosts** score under **`urlRaw`/`urlApplied`**, not **`sender`**. | `sender_scanner.py`, `lookalike_domain_scanner.py`, `data/impersonation_targets.json` |
| **Links & URL reputation** | Suspicious URL structure, TLD hints, malformed patterns, optional reputation | **`urlRaw`** / **`urlApplied`**; only dampened Applied enters **`totalPenalty`**. | `url_scanner.py` |
| **Attachments & payloads** | Executables, disguised names, risky archives, PDFs with extracted links | Adds **`attachments`**. Often among the strongest contributors. | `attachment_scanner.py` |
| **Keywords & language** | Phishing lexicon, escalation, low-quality heuristics | **`keywords`**, **`language`** (capped). | `keyword_scanner.py`, `language_scanner.py` |
| **Context nudges** | Send time under BEC/ATO-like body context; **`linkBase`** from link count (capped) | **`time`**, **`linkBase`**. | `time_scanner.py`, `LinkBaseScannerAdapter` |

**Takeaway:** there is no opaque ML weight vector—behaviour is defined by explicit rules, caps, dampening, and verdict tables in code.

---

## Design decisions and trade-offs

| Decision | Why |
|----------|-----|
| **Modular scanner pipeline** | Small **adapters** implement **`Scanner`** (`scanners/base.py`). **`ScannerPipeline`** merges results in **dependency phases** (parallelism only where safe). Structural typing keeps extension simple. |
| **Rule-first core** | Heuristics work without third-party APIs; reputation is an optional boost. |
| **Optional reputation** | IPQS, VirusTotal, Safe Browsing improve signal when keys exist; otherwise local logic still returns a full **`ScanResponse`**. |
| **Parallel scanners + bounded HTTP** | Independent work runs concurrently (`ThreadPoolExecutor` in **`scanner_pipeline.py`**; fan-out in sender/URL/QR modules). Timeouts via **`PHISHWALL_*`** (see **`phishwall_backend/.env.example`**). Narrative tradeoffs and “what’s optional”: **[latency-and-resilience.md](latency-and-resilience.md)**. |
| **URL penalty dampening** | **`urlApplied ≈ floor(urlRaw × 0.7)`** toward zero—stops a single odd URL from dominating. |
| **Verdict is not score-only** | Verdict uses **`maliciousScore`** plus categorical **strong indicators** and threshold tables—see **[scoring-and-verdict.md](scoring-and-verdict.md)**. |
| **Local backend + tunnel** | **`uvicorn` cwd = `phishwall_backend/`** (where **`main.py`** lives). HTTPS tunnel (ngrok) + **`API_URL`** ending in **`/scan`** in **`Config.js`**, then **`clasp push`**. Walkthrough → **[getting-started.md](getting-started.md#running-from-scratch-step-by-step)**. |
| **Mailbox familiarity is moderation only** | Enough prior threads **without** exe/disguised/risky-archive, sender+URL reputation hits, QR-decode/url-payload cues, etc. (**`verdict_engine._mailbox_familiarity_moderates`**) makes **`Dangerous`** require a **numerically higher** bar; **not** a whitelist—penalties unchanged. |
| **BEC gating** | Multi-signal BEC needs explicit finance/pressure (or coupling), not generic keyword spikes alone. |

---

## Limitations

Heuristics and lists cannot cover every campaign. Reputation APIs add quota and latency. **CardService** limits UI richness. **`GmailApp.search`** is quota-bound.

**Future (not here):** a product might add **persistent** per-user sender trust—separate from this prototype’s stateless **`POST /scan`** + ephemeral mailbox query.
