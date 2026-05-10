"""High-level entry point: turn a request dict into a full ScanResponse dict.

Responsibility split:
- normalize the input (URLs, attachments, candidate emails, sent_at);
- run the scanner pipeline;
- ask the verdict engine for a verdict + reasoning;
- assemble the response with stable defaults so every key is always present
  (the add-on assumes the schema is fixed).
"""

import logging
import time
from typing import Any, Dict

from scanners.base import ScanContext
from services.scanner_pipeline import build_default_pipeline, collect_email_candidates, normalize_urls
from services.verdict_engine import build_verdict


def analyze_email(data: Dict[str, Any]) -> Dict[str, Any]:
    _t0 = time.perf_counter()
    subject = data.get("subject", "")
    sender = data.get("from", "")
    body = data.get("body", "")
    body_snippet = data.get("body_snippet", "")
    # Accept any of three sent-time fields; first non-empty wins.
    sent_at = data.get("date") or data.get("sent_at") or data.get("timestamp") or ""
    try:
        # Clamp to [0, 200] in case the add-on sends garbage; same range as the model.
        sender_prior_threads = max(0, min(200, int(data.get("sender_prior_thread_count", 0) or 0)))
    except (TypeError, ValueError):
        sender_prior_threads = 0

    urls = normalize_urls(data.get("urls", []), body)
    attachments = data.get("attachments", [])
    email_candidates = collect_email_candidates(data)
    context = ScanContext(
        subject=str(subject),
        sender=str(sender),
        body=str(body),
        body_snippet=str(body_snippet),
        sent_at=str(sent_at),
        urls=urls,
        attachments=attachments if isinstance(attachments, list) else [],
        email_candidates=email_candidates,
    )

    pipeline_result = build_default_pipeline().run(context)
    logging.getLogger(__name__).debug(
        "analyze_email pipeline_wall_ms=%.1f links=%s attach=%s",
        (time.perf_counter() - _t0) * 1000.0,
        len(context.urls),
        len(context.attachments),
    )
    breakdown = pipeline_result["breakdown"]
    # Two-sided score: clamp into [0, 100] so a malformed scanner can't break the UI.
    score = max(0, min(100, 100 - int(breakdown["totalPenalty"])))
    malicious_score = 100 - score
    verdict_data = build_verdict(
        malicious_score,
        int(breakdown.get("keywords", 0)),
        pipeline_result["summaries"].get("sender", {}),
        pipeline_result["summaries"].get("url", {}),
        pipeline_result["summaries"].get("attachments", {}),
        pipeline_result["summaries"].get(
            "qr",
            {
                "qrDetected": False,
                "decodedCount": 0,
                "scannedImages": 0,
                "decodedPayloads": [],
                "riskPenalty": 0,
            },
        ),
        pipeline_result["summaries"].get("priority_threats", {}),
        pipeline_result["riskIndicators"],
        sender_prior_threads,
    )

    # Defaults below mirror the Pydantic models so the response always has every
    # field — the add-on doesn't tolerate missing keys.
    return {
        "score": score,
        "maliciousScore": malicious_score,
        "verdict": verdict_data["verdict"],
        "color": verdict_data["color"],
        "icon": verdict_data["icon"],
        "verdictReasoning": verdict_data["reasoning"],
        "recommendation": verdict_data["recommendation"],
        "familiarSenderCalibration": verdict_data.get("familiarSenderCalibration", False),
        "reasons": verdict_data["strongIndicators"],
        "links": pipeline_result["links"],
        "riskWords": pipeline_result["riskWords"],
        # Legacy alias kept for older add-on builds that still read `comments`.
        "comments": pipeline_result["riskIndicators"],
        "riskIndicators": pipeline_result["riskIndicators"],
        "infoFindings": pipeline_result["infoFindings"],
        "scoreBreakdown": breakdown,
        "attachmentSummary": pipeline_result["summaries"].get(
            "attachments",
            {
                "count": 0,
                "safePdfCount": 0,
                "pdfWithLinksCount": 0,
                "executableCount": 0,
                "unknownAttachmentCount": 0,
            },
        ),
        "urlSummary": pipeline_result["summaries"].get(
            "url",
            {
                "count": 0,
                "unresolvedHosts": 0,
                "ipqsFlagged": 0,
                "gsbFlagged": 0,
            },
        ),
        "senderSummary": pipeline_result["summaries"].get(
            "sender",
            {
                "email": "",
                "domain": "",
                "emailsChecked": 0,
                "ipqsFlagged": 0,
                "vtFlagged": 0,
            },
        ),
        "languageSummary": pipeline_result["summaries"].get("language", {"heuristicPenalty": 0}),
        "timeSummary": pipeline_result["summaries"].get(
            "time",
            {
                "analyzed": False,
                "riskPenalty": 0,
                "becContext": False,
                "atoContext": False,
                "hour": None,
                "weekday": None,
            },
        ),
        "qrSummary": pipeline_result["summaries"].get(
            "qr",
            {
                "qrDetected": False,
                "decodedCount": 0,
                "scannedImages": 0,
                "decodedPayloads": [],
                "riskPenalty": 0,
            },
        ),
        "priorityThreatSummary": pipeline_result["summaries"].get(
            "priority_threats",
            {
                "becDetected": False,
                "becSignalCount": 0,
                "riskPenalty": 0,
            },
        ),
    }
