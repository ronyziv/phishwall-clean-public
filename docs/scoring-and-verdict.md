# Scoring and verdict — deep dive

**Documentation index:** **[README.md](README.md)**.

This document describes **two separate mechanisms** behind the **`POST /scan`** response:

1. **Numeric layer** — scanners produce **penalties**; those roll up into **`score`**, **`maliciousScore`**, and **`scoreBreakdown`** (`scan_service.py` + `scanner_pipeline.py`).
2. **Policy layer** — **`verdict_engine.build_verdict`** maps the numeric outcome **plus categorical signals** into **`verdict`**, colours, **`verdictReasoning`**, **`recommendation`**, and **`reasons`** (API field merges from `strongIndicators`).

They are intentionally **decoupled**: a mid-range **`maliciousScore`** can still become **Dangerous** if strong categorical rules fire, and conversely familiarity tuning can shift cutoffs **without changing penalties**.

Canonical JSON field names live in **`[api-contract.md](api-contract.md)`**.

---

## 1. Numbers the UI shows vs numbers in the payload

| Concept | Meaning | Typical UI usage |
|---------|---------|------------------|
| **`maliciousScore`** | **0–100**, higher = **more malicious** in API terms | Gmail card shows it as a **suspicion / exposure** line (localized caption; see `UiService.js`). |
| **`score`** | **0–100**, higher = **safer** | `score = 100 - maliciousScore` (also exposed for tooling) |
| **`verdict`** | `Safe`, `Suspicious`, or **`Dangerous / Do Not Open`** | Headline verdict line |
| **`scoreBreakdown`** | Integer penalties per bucket + **`totalPenalty`** | Panels / transparency |

---

## 2. How **`totalPenalty`** is built (`scanner_pipeline.py`)

Each adapter adds integers into **`breakdown`** keys. After all scanners run:

```text
totalPenalty =
  keywords + language + sender + time + qr + priorityThreats + linkBase + urlApplied + attachments
```

### Critical rule: **`urlRaw` does not appear in `totalPenalty`**

- **`urlRaw`** accumulates heuristic + reputation penalties from URL analysis **before** dampening.
- **`urlApplied = int(urlRaw × 0.7)`** with truncation **toward zero** (implemented as `int(raw * 0.7)` on non-negative ints in **`UrlScannerAdapter`**).
- Only **`urlApplied`** is summed into **`totalPenalty`**.

So **`urlRaw`** answers “how harsh did URL logic think this was?” while **`urlApplied`** answers “what actually hurts the headline score?”

Other buckets (**`keywords`**, **`language`**, …) are summed **directly**.

---

## 3. From **`totalPenalty`** to **`score`** / **`maliciousScore`** (`scan_service.analyze_email`)

```text
score         = clamp( [0..100], 100 - totalPenalty )
maliciousScore = 100 - score
```

`clamp` is **`max(0, min(100, …))`**. **`totalPenalty` is not capped** before subtraction—extremely high stacks can clamp **`score`** to **`0`** and **`maliciousScore`** to **`100`**.

---

## 4. What each **`scoreBreakdown`** bucket represents

| Bucket | Role (intuition) | Notes |
|--------|------------------|--------|
| **`keywords`** | Lexical phishing / escalation pressure | Driven by **`keyword_scanner.py`** against **`risk_keywords.txt`**—**capped at 40**. |
| **`language`** | Low-quality / spammy text heuristics | **`language_scanner.py`**, capped **15**. |
| **`sender`** | Punycode, brand/display mismatch, IPQS+VirusTotal+look‑alikes (composed) | IPQS penalty blended with look‑alikes per **`sender_scanner.py`** (see Relative weights below). |
| **`time`** | Off-hours sending **only when** BEC/ATO-like context hits | **`time_scanner.py`**, small cap **≤2**. |
| **`qr`** | Decoded payloads, QR-ish links/fetches | **`qr_scanner.py`**; capped **36** attachments path + **42** linked path before merge in adapter—aggregate stored in **`qr`**. |
| **`priorityThreats`** | BEC / finance+pressure coupling | **`+16`** when multi-signal **`becDetected`**, **`+5`** on single weak signal. |
| **`linkBase`** | Link-count nudge once URLs exist | From **1 URL** upward, capped **3**. |
| **`urlRaw` / `urlApplied`** | Structural URL risk + reputation flags | **`urlApplied`** enters **`totalPenalty`** only. |
| **`attachments`** | Executables, disguised filenames, risky archives, linked PDF cues | **`attachment_scanner.py`**—often spikes **e.g. +60** for executables (**see code for exact deltas**). |

### Relative magnitude (orientation, not exhaustive)

From product documentation / code comments:

| Bucket | Typical role |
|--------|----------------|
| **Attachments** | Largest single spikes (e.g. executable **+60**, disguised **+35**, PDF-with-links **+25**, risky archive **+12**). |
| **Sender** | Strong when spoofing + reputation align; IPQS vs look‑alike blend **`round(IPQS×0.7 + look‑alike×0.6)`** on sender lookups. |
| **URLs** | Can be high in **`urlRaw`**, softened via **`~70%`** into **`urlApplied`**. |
| **Keywords** | Capped **40**. |
| **QR** | Strong but branch-capped before entering **`qr`**. |
| **BEC / priority** | **+16** / **+5** pattern. |
| **Language / time / linkBase** | Light nudges. |

---

## 5. Response fields around risk (what is “the evidence”?)

| Field | Source |
|-------|--------|
| **`riskIndicators`** | Concatenated **risk** strings from all scanners (same as **`comments`** for backward compatibility). |
| **`infoFindings`** | Informational notes (counts, “reputation disabled”, benign PDF notices, etc.). |
| **`reasons`** | **`build_verdict`**’s **`strongIndicators`** list—**short categorical labels** (e.g. `"executable attachment"`), **not** the full scanner strings. |
| **`verdictReasoning` / `recommendation`** | Human copy derived from verdict tier + first few strong indicators. |

---

## 6. Verdict policy (`verdict_engine.py`) — inputs

`build_verdict(malicious_score, keyword_penalty, sender_summary, url_summary, attachment_summary, qr_summary, priority_threat_summary, risk_indicators, sender_prior_thread_count)`:

1. **`indicators_text`** — join of **`risk_indicators`** (substring search for patterns).
2. **Boolean “strong signal” flags** — derived from summaries + text, e.g.:
   - **`has_executable`** — `attachment_summary.executableCount > 0`
   - **`has_disguised_attachment`**, **`has_risky_archive`** — substring match on **`indicators_text`**
   - **`has_spoofing`** — phrases like “look-alike domain”, “display name references”, …
   - **`has_suspicious_links`** — URL rep flags **or** URL heuristic phrases in text
   - **`has_sender_reputation_hit`** — `ipqsFlagged` or `vtFlagged` on sender summary
   - **`has_urgent_pressure`** — `keyword_penalty >= 14`
   - **`has_qr_phishing`** — `qr_summary.qrDetected`
   - **`has_qr_url_payload`** — “decoded qr” / “contains url target” in **`indicators_text`**
   - **`has_bec_behavior`** — `priority_threat_summary.becDetected`
3. **`strong_indicators`** — ordered list of short English tags (mapped to API **`reasons`**).
4. **`hard_blocker`** — `has_executable OR has_disguised_attachment OR vtFlagged (sender domain)`; **sender IPQS flags alone do not** set this bucket (`verdict_engine.py`).
5. **`familiar_mod`** — **mailbox familiarity** active only when prior threads **≥ 5** **`_FAMILIAR_PRIOR_THREAD_MIN`** and **`_mailbox_familiarity_moderates`** returns true: not when **`hard_blocker`**, **`has_sender_reputation_hit`**, **`has_executable`**, **`has_disguised_attachment`**, **`has_risky_archive`**, **`has_qr_phishing`**, **`has_qr_url_payload`**, or URL rep flags **`ipqsFlagged`/`gsbFlagged`** **> 0** (`verdict_engine.py`).

---

## 7. Verdict thresholds (exact conditions from code)

Default start: **`verdict = Safe`**. Then:

### Dangerous — **`familiar_mod == True`** (softer Dangerous bar)

`dangerous_condition` is **true** if **any** of:

| Condition |
|-----------|
| **`hard_blocker`** |
| **`malicious_score >= 68`** |
| **`has_qr_url_payload` AND `malicious_score >= 32`** |
| **`has_qr_phishing` AND `malicious_score >= 38`** |
| **`has_bec_behavior` AND `malicious_score >= 58`** |
| **`malicious_score >= 60` AND `strong_count >= 1`** |
| **`malicious_score >= 55` AND `strong_count >= 2`** |

### Dangerous — **`familiar_mod == False`** (default, stricter)

| Condition |
|-----------|
| **`hard_blocker`** |
| **`malicious_score >= 60`** |
| **`has_qr_url_payload` AND `malicious_score >= 25`** |
| **`has_qr_phishing` AND `malicious_score >= 30`** |
| **`has_bec_behavior` AND `malicious_score >= 35`** |
| **`malicious_score >= 45` AND `strong_count >= 1`** |
| **`malicious_score >= 35` AND `strong_count >= 2`** |

If **`dangerous_condition`**: **`verdict = Dangerous / Do Not Open`**. (**`color`** / **`icon`** in **`ScanResponse`** still use red / stop icon for tooling; Gmail UI may tone-map independently.)

### Suspicious — if not Dangerous

`suspicious_condition` is **true** if **any** of:

- **`malicious_score >= 20`**
- **`strong_count >= 1`** (≥1 strong indicator category)
- **`len(risk_indicators) >= 2`**

Then **`verdict = Suspicious`**.

### Safe

Otherwise stay **`Safe`**.

---

## 8. **`familiarSenderCalibration`** (`ScanResponse`)

`familiarSenderCalibration == True` only when **`familiar_mod`** is active **and** the final **`verdict` is `Suspicious`**.

Backend uses it so the Gmail card can choose **gentler wording** (`verdict_engine` returns a softer **`recommendation`** when **`familiar_mod`** on Suspicious).

---

## 9. Mailbox familiarity (how it interacts with verdict only)

From **`sender_prior_thread_count`** (clamp **0–200** on input):

- If familiarity applies (**§6**), the **`Dangerous`** branch uses the **§7 — `familiar_mod == True`** table (generally **higher score bars** than the default branch). **`Suspicious`** / **`Safe`** branching is unchanged in structure.

Penalties in **`scoreBreakdown` are untouched** — only **`verdict` policy** shifts.

---

## 10. End-to-end mental model

```text
[Each Scanner] --> integer penalties --> scoreBreakdown (per bucket)
                                          |
                   + urlRaw/urlApplied logic
                                          v
                               totalPenalty (sum selected keys)
                                          v
                         score = 100 - totalPenalty (clamped)
                         maliciousScore = 100 - score
                                          +
              summaries + riskIndicators + keyword_penalty
                                          v
                          build_verdict(...) --> verdict, reasons, reasoning, ...
```

For wire examples of **`scoreBreakdown`** inside **`ScanResponse`**, see **[api-contract.md](api-contract.md)**.
