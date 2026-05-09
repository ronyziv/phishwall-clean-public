import json
import logging
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any, Dict, List

from scanners.attachment_scanner import scan_attachments
from scanners.base import ScanContext, Scanner, ScannerResult
from scanners.external_http_config import SCANNER_MAX_WORKERS
from scanners.keyword_scanner import scan_keywords
from scanners.language_scanner import scan_language_quality
from scanners.qr_scanner import scan_qr_attachments, scan_qr_linked_resources
from scanners.sender_scanner import scan_sender
from scanners.time_scanner import scan_sending_time
from scanners.url_scanner import scan_urls

URL_PATTERN = re.compile(r"https?://[^\s\"'<>]+")
PRIORITY_KEYWORDS_PATH = Path(__file__).resolve().parent.parent / "data" / "priority_threat_keywords.json"


def normalize_urls(urls_value: Any, body_text: str) -> List[str]:
    if isinstance(urls_value, list):
        urls = [str(url).strip() for url in urls_value if str(url).strip()]
    else:
        urls = []

    if not urls:
        urls = URL_PATTERN.findall(body_text or "")

    return urls


def collect_email_candidates(data: Dict[str, Any]) -> List[str]:
    candidates: List[str] = []
    direct_fields = ["from", "to", "cc", "bcc", "reply_to", "subject", "body", "body_snippet"]
    for field in direct_fields:
        value = data.get(field)
        if isinstance(value, list):
            candidates.extend([str(item) for item in value])
        elif value:
            candidates.append(str(value))
    return candidates


def _contains_any(text: str, patterns: List[str]) -> bool:
    lowered = str(text or "").lower()
    return any(pattern in lowered for pattern in patterns)


def _to_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _to_str_list(value: Any) -> List[str]:
    if not isinstance(value, list):
        return []
    return [str(item) for item in value if str(item).strip()]


def _load_priority_keywords() -> Dict[str, List[str]]:
    defaults = {
        "bec_finance_terms": ["wire transfer", "invoice", "payment"],
        "bec_pressure_terms": ["urgent", "asap", "immediately"],
    }
    try:
        with open(PRIORITY_KEYWORDS_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, dict):
            return defaults
        normalized: Dict[str, List[str]] = {}
        for key in defaults:
            values = data.get(key, [])
            if isinstance(values, list):
                normalized[key] = [str(value).lower() for value in values if str(value).strip()]
            else:
                normalized[key] = defaults[key]
        return normalized
    except Exception:
        return defaults


PRIORITY_KEYWORDS = _load_priority_keywords()


def _consume_scan_result(
    state: Dict[str, Any],
    breakdown: Dict[str, int],
    summaries: Dict[str, Dict[str, Any]],
    risk_indicators: List[str],
    info_findings: List[str],
    risk_words_holder: List[int],
    result: ScannerResult,
) -> None:
    state[result.name] = {
        "breakdown": result.breakdown,
        "summary": result.summary,
        "metadata": result.metadata,
    }
    risk_indicators.extend(result.risk_findings)
    info_findings.extend(result.info_findings)
    for key, value in result.breakdown.items():
        breakdown[key] = int(breakdown.get(key, 0)) + int(value)
    if result.risk_words is not None:
        risk_words_holder[0] = int(result.risk_words)
    if result.summary:
        summaries[result.name] = result.summary


class KeywordScannerAdapter:
    name = "keywords"

    def applies(self, context: ScanContext, state: Dict[str, Any]) -> bool:
        return True

    def run(self, context: ScanContext, state: Dict[str, Any]) -> ScannerResult:
        result = scan_keywords(context.text)
        return ScannerResult(
            name=self.name,
            risk_findings=result.get("findings", []),
            breakdown={"keywords": int(result.get("riskPenalty", 0))},
            metadata={"raw": result},
            risk_words=int(result.get("uniqueMatchedCount", 0)),
        )


class LanguageScannerAdapter:
    name = "language"

    def applies(self, context: ScanContext, state: Dict[str, Any]) -> bool:
        return True

    def run(self, context: ScanContext, state: Dict[str, Any]) -> ScannerResult:
        result = scan_language_quality(context.subject, context.body, context.body_snippet)
        return ScannerResult(
            name=self.name,
            risk_findings=result.get("findings", []),
            breakdown={"language": int(result.get("riskPenalty", 0))},
            summary={"heuristicPenalty": int(result.get("riskPenalty", 0))},
            metadata={"raw": result},
        )


class SenderScannerAdapter:
    name = "sender"

    def applies(self, context: ScanContext, state: Dict[str, Any]) -> bool:
        return bool(context.sender)

    def run(self, context: ScanContext, state: Dict[str, Any]) -> ScannerResult:
        sender_context = f"{context.subject} {context.body} {context.body_snippet}"
        result = scan_sender(
            context.sender,
            email_candidates=context.email_candidates,
            context_text=sender_context,
        )

        risk_findings: List[str] = []
        info_findings: List[str] = []
        for finding in result.get("findings", []):
            if str(finding).startswith("IPQS unavailable"):
                info_findings.append(finding)
            else:
                risk_findings.append(finding)

        return ScannerResult(
            name=self.name,
            risk_findings=risk_findings,
            info_findings=info_findings,
            breakdown={"sender": int(result.get("riskPenalty", 0))},
            summary={
                "email": result.get("senderEmail", ""),
                "domain": result.get("senderDomain", ""),
                "emailsChecked": int(result.get("emailsChecked", 1)),
                "ipqsFlagged": int(result.get("ipqsFlagged", 0)),
                "vtFlagged": int(result.get("vtFlagged", 0)),
            },
            metadata={"raw": result},
        )


class TimeScannerAdapter:
    name = "time"

    def applies(self, context: ScanContext, state: Dict[str, Any]) -> bool:
        return bool(context.sent_at)

    def run(self, context: ScanContext, state: Dict[str, Any]) -> ScannerResult:
        time_context = f"{context.subject} {context.body} {context.body_snippet} {context.sender}"
        result = scan_sending_time(context.sent_at, time_context)
        return ScannerResult(
            name=self.name,
            risk_findings=result.get("findings", []),
            breakdown={"time": int(result.get("riskPenalty", 0))},
            summary={
                "analyzed": bool(result.get("analyzed", False)),
                "riskPenalty": int(result.get("riskPenalty", 0)),
                "becContext": bool(result.get("becContext", False)),
                "atoContext": bool(result.get("atoContext", False)),
                "hour": result.get("hour"),
                "weekday": result.get("weekday"),
            },
            metadata={"raw": result},
        )


class PriorityThreatScannerAdapter:
    name = "priority_threats"

    def applies(self, context: ScanContext, state: Dict[str, Any]) -> bool:
        return True

    def run(self, context: ScanContext, state: Dict[str, Any]) -> ScannerResult:
        sender_raw = ((state.get("sender") or {}).get("metadata") or {}).get("raw", {})
        keyword_penalty = int((state.get("keywords") or {}).get("breakdown", {}).get("keywords", 0))
        normalized_text = f"{context.subject} {context.sender} {context.body} {context.body_snippet}".lower()

        bec_finance_terms = PRIORITY_KEYWORDS["bec_finance_terms"]
        bec_pressure_terms = PRIORITY_KEYWORDS["bec_pressure_terms"]

        risk_penalty = 0
        findings: List[str] = []

        bec_finance_hit = any(term in normalized_text for term in bec_finance_terms)
        lexical_pressure_hit = any(term in normalized_text for term in bec_pressure_terms)
        # Require explicit pressure wording in the merged text OR strong finance+keyword coupling.
        # Generic keyword-score spikes alone must not substitute for BEC "pressure" (reduces study/personal FP).
        bec_pressure_hit = lexical_pressure_hit or (keyword_penalty >= 14 and bec_finance_hit)
        bec_impersonation_hit = _contains_any(
            " | ".join(sender_raw.get("findings", [])),
            [
                "display name references",
                "look-alike domain",
                "does not match known domains",
                "sender uses punycode domain",
            ],
        )
        bec_no_link_pattern = bec_finance_hit and bec_pressure_hit and len(context.urls) == 0

        bec_signal_count = (
            int(bec_finance_hit)
            + int(bec_pressure_hit)
            + int(bec_impersonation_hit)
            + int(bec_no_link_pattern)
        )
        bec_detected = bec_signal_count >= 2
        if bec_detected:
            risk_penalty += 16
            findings.append(
                "BEC-style pattern detected: financial/urgent request with impersonation or social-pressure behavior."
            )
        elif bec_signal_count == 1:
            risk_penalty += 5
            findings.append("Low-confidence BEC-style signal detected.")

        return ScannerResult(
            name=self.name,
            risk_findings=findings,
            breakdown={"priorityThreats": risk_penalty},
            summary={
                "becDetected": bec_detected,
                "becSignalCount": bec_signal_count,
                "riskPenalty": risk_penalty,
            },
            metadata={"raw": {"riskPenalty": risk_penalty, "findings": findings}},
        )


class QrScannerAdapter:
    name = "qr"

    def applies(self, context: ScanContext, state: Dict[str, Any]) -> bool:
        has_attachments = isinstance(context.attachments, list) and len(context.attachments) > 0
        has_urls = isinstance(context.urls, list) and len(context.urls) > 0
        return has_attachments or has_urls

    def run(self, context: ScanContext, state: Dict[str, Any]) -> ScannerResult:
        with ThreadPoolExecutor(max_workers=2) as qr_pool:
            fa = qr_pool.submit(scan_qr_attachments, context.attachments)
            fb = qr_pool.submit(scan_qr_linked_resources, context.urls)
            attachment_result = fa.result()
            linked_result = fb.result()

        findings = _to_str_list(attachment_result.get("findings")) + _to_str_list(linked_result.get("findings"))
        risk_penalty = _to_int(attachment_result.get("riskPenalty")) + _to_int(linked_result.get("riskPenalty"))
        qr_detected = bool(attachment_result.get("qrDetected", False)) or bool(_to_int(linked_result.get("linkedDecodedCount")))
        decoded_payloads = _to_str_list(attachment_result.get("decodedPayloads")) + _to_str_list(
            linked_result.get("linkedDecodedPayloads")
        )
        decoded_payloads = list(dict.fromkeys(decoded_payloads))

        return ScannerResult(
            name=self.name,
            risk_findings=findings,
            breakdown={"qr": risk_penalty},
            summary={
                "qrDetected": qr_detected,
                "decodedCount": _to_int(attachment_result.get("decodedCount")) + _to_int(linked_result.get("linkedDecodedCount")),
                "scannedImages": _to_int(attachment_result.get("scannedImages")),
                "decodedPayloads": decoded_payloads,
                "qrLinkedCandidates": _to_int(linked_result.get("qrLinkedCandidates")),
                "qrLinkedDetected": bool(linked_result.get("qrLinkedDetected", False)),
                "linkedScannedCount": _to_int(linked_result.get("linkedScannedCount")),
                "linkedDecodedCount": _to_int(linked_result.get("linkedDecodedCount")),
                "riskPenalty": risk_penalty,
            },
            metadata={"raw": {"attachments": attachment_result, "linked": linked_result}},
        )


class LinkBaseScannerAdapter:
    name = "link_base"

    def applies(self, context: ScanContext, state: Dict[str, Any]) -> bool:
        return True

    def run(self, context: ScanContext, state: Dict[str, Any]) -> ScannerResult:
        links = len(context.urls)
        if links <= 0:
            return ScannerResult(name=self.name, breakdown={"linkBase": 0}, summary={"count": 0})

        penalty = min(3, 1 + max(0, links - 1))
        return ScannerResult(
            name=self.name,
            info_findings=[f"Found {links} link(s) in the email."],
            breakdown={"linkBase": penalty},
            summary={"count": links},
        )


class UrlScannerAdapter:
    name = "url"

    def applies(self, context: ScanContext, state: Dict[str, Any]) -> bool:
        return len(context.urls) > 0

    def run(self, context: ScanContext, state: Dict[str, Any]) -> ScannerResult:
        result = scan_urls(context.urls)
        risk_findings: List[str] = []
        info_findings: List[str] = []
        for finding in result.get("findings", []):
            lowered = str(finding).lower()
            if "lookup timed out" in lowered or "lookup failed" in lowered or "reputation is disabled" in lowered:
                info_findings.append(finding)
            else:
                risk_findings.append(finding)

        raw_penalty = int(result.get("riskPenalty", 0))
        applied_penalty = int(raw_penalty * 0.7)
        return ScannerResult(
            name=self.name,
            risk_findings=risk_findings,
            info_findings=info_findings,
            breakdown={"urlRaw": raw_penalty, "urlApplied": applied_penalty},
            summary={
                "count": int(result.get("urlCount", 0)),
                "unresolvedHosts": int(result.get("unresolvedHosts", 0)),
                "ipqsFlagged": int(result.get("ipqsFlagged", 0)),
                "gsbFlagged": int(result.get("gsbFlagged", 0)),
            },
            metadata={"raw": result},
        )


class AttachmentScannerAdapter:
    name = "attachments"

    def applies(self, context: ScanContext, state: Dict[str, Any]) -> bool:
        return isinstance(context.attachments, list)

    def run(self, context: ScanContext, state: Dict[str, Any]) -> ScannerResult:
        result = scan_attachments(context.attachments)
        risk_findings: List[str] = []
        info_findings: List[str] = []
        count = int(result.get("attachmentCount", 0))
        if count > 0:
            info_findings.append(f"Found {count} attachment(s).")

        for finding in result.get("findings", []):
            if str(finding).startswith("PDF attachment detected (no links found):"):
                info_findings.append(finding)
            else:
                risk_findings.append(finding)

        return ScannerResult(
            name=self.name,
            risk_findings=risk_findings,
            info_findings=info_findings,
            breakdown={"attachments": int(result.get("riskPenalty", 0))},
            summary={
                "count": count,
                "safePdfCount": int(result.get("safePdfCount", 0)),
                "pdfWithLinksCount": int(result.get("pdfWithLinksCount", 0)),
                "executableCount": int(result.get("executableCount", 0)),
                "unknownAttachmentCount": int(result.get("unknownAttachmentCount", 0)),
            },
            metadata={"raw": result},
        )


class ScannerPipeline:
    # Phase grouping: scanners in a phase touch only ScanContext (+ shared state merged after the phase).
    # Phase 2 must stay after Phase 1 because priority_threats reads keyword/sender intermediates.

    PHASE1_ORDER = ["keywords", "language", "sender", "time"]
    PHASE2_ORDER = ["priority_threats"]
    PHASE3_ORDER = ["qr", "link_base", "url", "attachments"]

    def __init__(self, scanners: List[Scanner]):
        self.scanners = scanners

    def _run_phase(self, ordered_names: List[str], context: ScanContext, state: Dict[str, Any], **agg) -> None:
        breakdown: Dict[str, int] = agg["breakdown"]
        summaries: Dict[str, Dict[str, Any]] = agg["summaries"]
        risk_indicators: List[str] = agg["risk_indicators"]
        info_findings: List[str] = agg["info_findings"]
        risk_words_holder: List[int] = agg["risk_words_holder"]

        by_name = {scanner.name: scanner for scanner in self.scanners}
        pending: List[Scanner] = []
        for name in ordered_names:
            scanner = by_name.get(name)
            if scanner and scanner.applies(context, state):
                pending.append(scanner)

        if not pending:
            return

        _log = logging.getLogger(__name__)
        if len(pending) == 1:
            try:
                result = pending[0].run(context, state)
            except Exception:
                _log.exception("Scanner '%s' failed; continuing without its penalties.", pending[0].name)
                result = ScannerResult(
                    name=pending[0].name,
                    info_findings=[
                        "A scan stage encountered an internal error; other checks still apply."
                    ],
                    breakdown={},
                )
            _consume_scan_result(state, breakdown, summaries, risk_indicators, info_findings, risk_words_holder, result)
            return

        workers = max(2, min(SCANNER_MAX_WORKERS, len(pending)))
        with ThreadPoolExecutor(max_workers=workers) as executor:
            future_map = {executor.submit(scan.run, context, state): scan for scan in pending}
            completed_by_name: Dict[str, ScannerResult] = {}
            for fut in as_completed(future_map):
                scanner = future_map[fut]
                try:
                    completed_by_name[scanner.name] = fut.result()
                except Exception:
                    _log.exception("Scanner '%s' failed; continuing without its penalties.", scanner.name)
                    completed_by_name[scanner.name] = ScannerResult(
                        name=scanner.name,
                        info_findings=[
                            "A scan stage encountered an internal error; other checks still apply."
                        ],
                        breakdown={},
                    )

        for scan in pending:
            result = completed_by_name[scan.name]
            _consume_scan_result(state, breakdown, summaries, risk_indicators, info_findings, risk_words_holder, result)

    def run(self, context: ScanContext) -> Dict[str, Any]:
        state: Dict[str, Any] = {}
        risk_indicators: List[str] = []
        info_findings: List[str] = []
        breakdown = {
            "keywords": 0,
            "language": 0,
            "sender": 0,
            "time": 0,
            "qr": 0,
            "priorityThreats": 0,
            "linkBase": 0,
            "urlRaw": 0,
            "urlApplied": 0,
            "attachments": 0,
        }
        summaries: Dict[str, Dict[str, Any]] = {}
        risk_words_holder = [0]

        phase_kwargs = dict(
            breakdown=breakdown,
            summaries=summaries,
            risk_indicators=risk_indicators,
            info_findings=info_findings,
            risk_words_holder=risk_words_holder,
        )
        self._run_phase(list(self.PHASE1_ORDER), context, state, **phase_kwargs)
        self._run_phase(list(self.PHASE2_ORDER), context, state, **phase_kwargs)
        self._run_phase(list(self.PHASE3_ORDER), context, state, **phase_kwargs)

        risk_words = risk_words_holder[0]

        total_penalty = sum(
            int(breakdown[key])
            for key in ["keywords", "language", "sender", "time", "qr", "priorityThreats", "linkBase", "urlApplied", "attachments"]
        )

        if not risk_indicators:
            info_findings.append("No strong suspicious indicators were found.")

        return {
            "riskIndicators": risk_indicators,
            "infoFindings": info_findings,
            "breakdown": {**breakdown, "totalPenalty": total_penalty},
            "summaries": summaries,
            "riskWords": risk_words,
            "links": len(context.urls),
        }


def build_default_pipeline() -> ScannerPipeline:
    return ScannerPipeline(
        scanners=[
            KeywordScannerAdapter(),
            LanguageScannerAdapter(),
            SenderScannerAdapter(),
            TimeScannerAdapter(),
            QrScannerAdapter(),
            PriorityThreatScannerAdapter(),
            LinkBaseScannerAdapter(),
            UrlScannerAdapter(),
            AttachmentScannerAdapter(),
        ]
    )
