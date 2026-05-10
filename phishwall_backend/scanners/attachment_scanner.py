"""Attachment heuristics: classify by extension/MIME, flag disguised filenames,
extract URLs from PDFs.

Penalties here are calibrated against the URL/sender scanners — executable is the
strongest single attachment signal, generic non-PDFs the lowest.
"""

import base64
import os
import re


# Extensions that almost always mean "code execution" on Windows or cross-platform.
EXECUTABLE_EXTENSIONS = {
    ".exe", ".msi", ".bat", ".cmd", ".ps1", ".js", ".jse", ".vbs",
    ".vbe", ".wsf", ".wsh", ".scr", ".com", ".pif", ".jar", ".hta"
}

# Containers often used to ship malware, but legitimate enough to be a moderate signal.
RISKY_CONTAINER_EXTENSIONS = {
    ".zip", ".rar", ".7z", ".iso", ".img", ".cab", ".ace",
}

# MIME fallback when filenames are renamed/missing.
EXECUTABLE_MIME_HINTS = (
    "application/x-msdownload",
    "application/x-msdos-program",
    "application/x-executable",
    "application/x-msi",
    "application/java-archive",
    "application/x-bat",
    "application/x-ms-shortcut",
)

URL_PATTERN = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
# Classic phishing trick (invoice.pdf.exe). Anchored to end-of-string so my.pdf.notes won't match.
DOUBLE_EXTENSION_PATTERN = re.compile(
    r"\.(pdf|doc|docx|xls|xlsx|ppt|pptx|txt|jpg|jpeg|png)\.(exe|scr|js|jse|vbs|vbe|cmd|bat|ps1)$",
    re.IGNORECASE,
)
# Catches "payload.exe   document" — trailing spaces hide the real extension in
# clients that left-truncate long names.
HIDDEN_EXTENSION_TRAIL_PATTERN = re.compile(r"\.(exe|scr|js|vbs|cmd|bat|ps1)\s+[A-Za-z0-9]+$", re.IGNORECASE)


def _is_pdf(filename, mime_type):
    name = (filename or "").lower()
    mime = (mime_type or "").lower()
    return name.endswith(".pdf") or mime == "application/pdf"


def _is_executable(filename, mime_type):
    name = (filename or "").lower()
    mime = (mime_type or "").lower()
    ext = os.path.splitext(name)[1]
    return ext in EXECUTABLE_EXTENSIONS or any(hint in mime for hint in EXECUTABLE_MIME_HINTS)


def _is_risky_container(filename, mime_type):
    name = (filename or "").lower()
    mime = (mime_type or "").lower()
    ext = os.path.splitext(name)[1]
    return ext in RISKY_CONTAINER_EXTENSIONS or "compressed" in mime or "zip" in mime or "archive" in mime


def _is_disguised_filename(filename):
    """Three common filename-obfuscation tricks used by droppers."""
    name = str(filename or "").strip()
    normalized = name.lower()
    # U+202E (RTL Override) flips display order — "doc<U+202E>exe.pdf" renders as "docfdp.exe".
    if "\u202e" in name:
        return True
    if DOUBLE_EXTENSION_PATTERN.search(normalized):
        return True
    if HIDDEN_EXTENSION_TRAIL_PATTERN.search(normalized):
        return True
    return False


def _extract_pdf_links(content_base64):
    """Best-effort PDF link extraction without a full PDF parser.

    Two cheap signals: raw `https?://` matches in the decoded bytes, and explicit
    `/URI ( ... )` action objects. We skip pypdf etc. to keep the request budget low.
    """
    if not content_base64:
        return []

    try:
        raw = base64.b64decode(content_base64, validate=False)
    except Exception:
        return []

    # latin-1 + errors="ignore" preserves byte values 1:1 even through binary streams.
    text = raw.decode("latin-1", errors="ignore")
    urls = URL_PATTERN.findall(text)
    if "/URI" in text:
        uri_matches = re.findall(r"/URI\s*\((.*?)\)", text, flags=re.IGNORECASE)
        urls.extend(uri_matches)

    deduped = []
    seen = set()
    for url in urls:
        normalized = str(url).strip()
        if normalized and normalized not in seen:
            seen.add(normalized)
            deduped.append(normalized)
    return deduped


def scan_attachments(attachments):
    """Classify and score every attachment in one pass.

    Each strong signal short-circuits with `continue` so an executable that also
    matches the disguised pattern doesn't double-count further per-file penalties.
    """
    findings = []
    attachment_count = 0
    safe_pdf_count = 0
    pdf_with_links_count = 0
    executable_count = 0
    unknown_count = 0
    risk_penalty = 0

    if not isinstance(attachments, list):
        attachments = []

    for attachment in attachments:
        if not isinstance(attachment, dict):
            continue
        attachment_count += 1

        filename = str(attachment.get("filename", "unknown"))
        mime_type = str(attachment.get("mimeType", ""))
        content_base64 = attachment.get("contentBase64", "")

        if _is_disguised_filename(filename):
            risk_penalty += 35
            findings.append(f"Disguised attachment filename pattern detected: {filename}")

        if _is_executable(filename, mime_type):
            executable_count += 1
            risk_penalty += 60
            findings.append(f"Executable attachment detected: {filename}")
            continue

        if _is_risky_container(filename, mime_type):
            risk_penalty += 12
            findings.append(f"Risky archive/container attachment detected: {filename}")
            continue

        if _is_pdf(filename, mime_type):
            pdf_links = _extract_pdf_links(content_base64)
            if pdf_links:
                pdf_with_links_count += 1
                risk_penalty += 25
                findings.append(
                    f"PDF contains {len(pdf_links)} link(s): {filename}"
                )
            else:
                safe_pdf_count += 1
                findings.append(f"PDF attachment detected (no links found): {filename}")
            continue

        unknown_count += 1
        # Generic attachments stay a low signal to avoid FPs on benign docs.
        risk_penalty += 4
        findings.append(f"Non-PDF attachment requires caution: {filename}")

    return {
        "attachmentCount": attachment_count,
        "safePdfCount": safe_pdf_count,
        "pdfWithLinksCount": pdf_with_links_count,
        "executableCount": executable_count,
        "unknownAttachmentCount": unknown_count,
        "riskPenalty": risk_penalty,
        "findings": findings,
    }
