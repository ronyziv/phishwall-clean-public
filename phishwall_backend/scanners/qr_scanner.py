"""QR-phishing detector.

Two paths:
- scan_qr_attachments: decode QR codes from inline image attachments.
- scan_qr_linked_resources: spot URLs that *look* QR-related (path/query hints
  or image extensions), optionally fetch them, and decode any QR found.

cv2 is imported eagerly at module top to avoid lazy-load hiccups inside thread
pools at request time.
"""

import base64
import logging
import os
import re
from concurrent.futures import ThreadPoolExecutor
from typing import Callable, Dict, List, Optional, Tuple
from urllib import parse, request

import cv2  # type: ignore[import-not-found]
import numpy as np

from scanners.external_http_config import QR_FETCH_TIMEOUT, SCANNER_MAX_WORKERS


IMAGE_EXTENSIONS = {".png", ".jpg", ".jpeg", ".bmp", ".webp"}
# Words inside a decoded QR payload that suggest credential phishing.
SUSPICIOUS_QR_TERMS = (
    "login",
    "verify",
    "password",
    "payment",
    "invoice",
    "secure",
    "account",
    "mfa",
    "2fa",
)
URL_PATTERN = re.compile(r"^https?://", re.IGNORECASE)
# Hints that a URL itself is a QR target (image / challenge page) — gates the fetch step.
QR_LINK_HINT_TERMS = (
    "qr",
    "qrcode",
    "qr-code",
    "scan-code",
    "scanqr",
    "challenge",
    "verify",
    "2fa",
    "mfa",
)
IMAGE_LINK_EXTENSIONS = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp"}
# Cap fetches per email so QR scanning stays cheap on link-heavy mail.
REMOTE_QR_FETCH_LIMIT = 3
FETCH_TIMEOUT_SECONDS = QR_FETCH_TIMEOUT


def _is_image_attachment(filename: str, mime_type: str) -> bool:
    lowered_name = str(filename or "").strip().lower()
    lowered_mime = str(mime_type or "").strip().lower()
    ext = os.path.splitext(lowered_name)[1]
    if lowered_mime.startswith("image/"):
        return True
    return ext in IMAGE_EXTENSIONS


def _decode_qr_from_image_bytes(image_bytes: bytes) -> List[str]:
    """Return distinct QR payloads decoded from a single image buffer.

    Tries detectAndDecodeMulti first, falls back to single-QR decode for OpenCV
    builds where multi-detect is flaky. Both calls swallow exceptions so corrupt
    or non-image bytes can't break the request.
    """
    if not image_bytes:
        return []

    # OpenCV needs an ndarray, not raw bytes.
    np_image = np.frombuffer(image_bytes, dtype=np.uint8)
    image = cv2.imdecode(np_image, cv2.IMREAD_COLOR)
    if image is None:
        return []

    detector = cv2.QRCodeDetector()
    decoded_values: List[str] = []

    try:
        ok_multi, decoded_multi, _, _ = detector.detectAndDecodeMulti(image)
        if ok_multi and decoded_multi:
            decoded_values.extend([str(value).strip() for value in decoded_multi if str(value).strip()])
    except Exception:
        pass

    if not decoded_values:
        try:
            decoded_single, _, _ = detector.detectAndDecode(image)
            if str(decoded_single).strip():
                decoded_values.append(str(decoded_single).strip())
        except Exception:
            return []

    # dict.fromkeys preserves first-seen order.
    return list(dict.fromkeys(decoded_values))


def _score_decoded_qr_payload(payload: str) -> int:
    # URL > suspicious-text > generic-text. URL inside a QR is the textbook quishing pattern.
    lowered = str(payload or "").strip().lower()
    if not lowered:
        return 0

    if URL_PATTERN.search(lowered):
        return 18

    if any(term in lowered for term in SUSPICIOUS_QR_TERMS):
        return 12

    return 8


def _decode_qr_payloads_for_source(image_bytes: bytes, source_label: str) -> Tuple[List[str], List[str], int]:
    # source_label is embedded in the user-facing finding so the add-on can show
    # "from image attachment 'foo.png'" vs "from linked resource 'https://...'".
    payloads = _decode_qr_from_image_bytes(image_bytes)
    findings: List[str] = []
    risk_penalty = 0

    for payload in payloads:
        payload_penalty = _score_decoded_qr_payload(payload)
        risk_penalty += payload_penalty
        if URL_PATTERN.search(payload):
            findings.append(f"Decoded QR from {source_label} contains URL target: {payload}")
        else:
            findings.append(f"Decoded QR from {source_label} contains actionable text: {payload}")

    return payloads, findings, risk_penalty


def _is_qr_related_url(url: str) -> bool:
    # Image-extension URLs and any URL whose path/query/fragment hints at QR.
    # Fragment is included because some trackers stash the target in #...
    raw = str(url or "").strip().lower()
    if not raw:
        return False

    try:
        parsed = parse.urlparse(raw)
    except Exception:
        return False

    target = " ".join(
        [
            parsed.path or "",
            parsed.query or "",
            parsed.fragment or "",
        ]
    ).lower()
    ext = os.path.splitext((parsed.path or "").lower())[1]
    if ext in IMAGE_LINK_EXTENSIONS:
        return True
    return any(term in target for term in QR_LINK_HINT_TERMS)


def _fetch_url_bytes(url: str) -> Optional[bytes]:
    # Returns the body even when Content-Type isn't image-like — phishing pages
    # often serve images with bogus types, and OpenCV will just fail to decode if
    # the bytes aren't actually an image.
    req = request.Request(
        str(url).strip(),
        headers={"User-Agent": "PhishWall-QRScanner/1.0"},
        method="GET",
    )
    try:
        with request.urlopen(req, timeout=FETCH_TIMEOUT_SECONDS) as resp:
            content_type = str(resp.headers.get("Content-Type") or "").lower()
            payload = resp.read()
            if not payload:
                return None
            if "image/" in content_type or "octet-stream" in content_type:
                return payload
            return payload
    except Exception:
        return None


def scan_qr_attachments(attachments: List[dict]) -> Dict[str, object]:
    """Decode QRs from every image attachment and aggregate findings.

    Penalty capped at 36 to avoid runaway scoring on duplicate QRs across images.
    """
    if not isinstance(attachments, list):
        attachments = []

    findings: List[str] = []
    decoded_payloads: List[str] = []
    decoded_count = 0
    scanned_images = 0
    risk_penalty = 0

    for attachment in attachments:
        if not isinstance(attachment, dict):
            continue

        filename = str(attachment.get("filename", "unknown"))
        mime_type = str(attachment.get("mimeType", ""))
        content_base64 = str(attachment.get("contentBase64", "") or "")

        if not _is_image_attachment(filename, mime_type):
            continue

        scanned_images += 1
        try:
            image_bytes = base64.b64decode(content_base64, validate=False)
        except Exception:
            continue

        source_label = f"image attachment '{filename}'"
        source_payloads, source_findings, source_penalty = _decode_qr_payloads_for_source(image_bytes, source_label)
        if not source_payloads:
            continue
        decoded_count += len(source_payloads)
        decoded_payloads.extend(source_payloads)
        findings.extend(source_findings)
        risk_penalty += source_penalty

    risk_penalty = min(risk_penalty, 36)
    deduped_payloads = list(dict.fromkeys(decoded_payloads))
    deduped_findings = list(dict.fromkeys(findings))

    return {
        "qrDetected": decoded_count > 0,
        "decodedCount": decoded_count,
        "scannedImages": scanned_images,
        "decodedPayloads": deduped_payloads,
        "riskPenalty": risk_penalty,
        "findings": deduped_findings,
    }


def _safe_fetch_one_linked(
    url: str,
    fetch: Callable[[str], Optional[bytes]],
) -> Tuple[str, Dict[str, object]]:
    """Fetch + decode one QR-related URL on a worker thread.

    Always returns a partial result — even on fetch failure we surface a small
    penalty + finding so the user sees we tried. `fetch` is injectable for tests.
    """
    scanned_urls = 1
    decoded_payloads: List[str] = []
    decoded_count = 0
    risk_penalty = 0
    findings: List[str] = []
    payload: Optional[bytes] = None
    try:
        payload = fetch(url)
    except Exception as exc:  # noqa: BLE001
        logging.getLogger(__name__).debug("QR-linked fetch aborted %s: %s", url, exc)
        payload = None
    if not payload:
        findings.append(f"Could not fetch/decode QR-linked resource: {url}")
        risk_penalty += 3
        return url, {
            "scanned": scanned_urls,
            "decoded_payloads": decoded_payloads,
            "decoded_count": decoded_count,
            "risk_penalty": risk_penalty,
            "findings": findings,
        }

    source_payloads, source_findings, source_penalty = _decode_qr_payloads_for_source(
        payload, f"linked resource '{url}'"
    )
    if source_payloads:
        decoded_count += len(source_payloads)
        decoded_payloads.extend(source_payloads)
        findings.extend(source_findings)
        # +4 bonus: a QR fetched from a remote URL is a stronger signal than one in an attachment.
        risk_penalty += source_penalty + 4
    else:
        findings.append(f"QR-related linked resource fetched but no QR decoded: {url}")
        risk_penalty += 2
    return url, {
        "scanned": scanned_urls,
        "decoded_payloads": decoded_payloads,
        "decoded_count": decoded_count,
        "risk_penalty": risk_penalty,
        "findings": findings,
    }


def scan_qr_linked_resources(
    urls: List[str],
    fetcher: Optional[Callable[[str], Optional[bytes]]] = None,
) -> Dict[str, object]:
    """Score QR-shaped URLs, then fetch+decode the top REMOTE_QR_FETCH_LIMIT.

    First pass adds a small "looks like QR" signal per URL (works offline).
    Second pass fetches in parallel since calls are network-bound and independent.
    """
    if not isinstance(urls, list):
        urls = []

    fetch = fetcher or _fetch_url_bytes
    candidate_urls = [str(url).strip() for url in urls if str(url).strip()]
    candidate_urls = list(dict.fromkeys(candidate_urls))
    qr_candidate_urls = [url for url in candidate_urls if _is_qr_related_url(url)]

    findings: List[str] = []
    decoded_payloads: List[str] = []
    scanned_urls = 0
    decoded_count = 0
    risk_penalty = 0

    # QR-shaped link is stronger than a generic URL hit, even before fetching.
    for url in qr_candidate_urls:
        risk_penalty += 7
        findings.append(f"QR-related linked resource detected: {url}")

    fetch_batch = qr_candidate_urls[:REMOTE_QR_FETCH_LIMIT]
    if len(fetch_batch) <= 1:
        # Skip thread-pool overhead for the common 0/1 case.
        for url in fetch_batch:
            _, part = _safe_fetch_one_linked(url, fetch)
            scanned_urls += int(part["scanned"])
            decoded_payloads.extend(part["decoded_payloads"])  # type: ignore[arg-type]
            decoded_count += int(part["decoded_count"])
            findings.extend(part["findings"])  # type: ignore[arg-type]
            risk_penalty += int(part["risk_penalty"])
    else:
        workers = max(2, min(SCANNER_MAX_WORKERS, len(fetch_batch)))
        with ThreadPoolExecutor(max_workers=min(workers, REMOTE_QR_FETCH_LIMIT)) as ex:
            parts = list(ex.map(lambda u: _safe_fetch_one_linked(u, fetch), fetch_batch))
        for _, part in parts:
            scanned_urls += int(part["scanned"])
            decoded_payloads.extend(part["decoded_payloads"])  # type: ignore[arg-type]
            decoded_count += int(part["decoded_count"])
            findings.extend(part["findings"])  # type: ignore[arg-type]
            risk_penalty += int(part["risk_penalty"])

    # Hard cap so a single email full of QR-shaped links can't dominate the score.
    risk_penalty = min(risk_penalty, 42)
    deduped_payloads = list(dict.fromkeys(decoded_payloads))
    deduped_findings = list(dict.fromkeys(findings))

    return {
        "qrLinkedDetected": bool(qr_candidate_urls),
        "qrLinkedCandidates": len(qr_candidate_urls),
        "linkedScannedCount": scanned_urls,
        "linkedDecodedCount": decoded_count,
        "linkedDecodedPayloads": deduped_payloads,
        "riskPenalty": risk_penalty,
        "findings": deduped_findings,
    }
