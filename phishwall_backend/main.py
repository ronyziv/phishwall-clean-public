"""FastAPI entry point for the PhishWall backend.

Exposes /health and /scan, loads .env on startup, and turns errors into
a stable JSON envelope so the Gmail add-on never sees raw tracebacks.
"""

import logging
import os
from pathlib import Path
from typing import Any, Dict

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from models import ErrorResponse, HealthResponse, ScanRequest, ScanResponse
from services.scan_service import analyze_email


def _load_local_env_file(env_path: Path) -> None:
    # Minimal .env parser to avoid pulling in python-dotenv.
    # setdefault means real environment values win over the file.
    if not env_path.exists():
        return

    for raw_line in env_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue

        key = ""
        value = ""
        if "=" in line:
            key, value = line.split("=", 1)
        else:
            # Tolerate "KEY value" typos.
            parts = line.split(None, 1)
            if len(parts) == 2:
                key, value = parts
            else:
                continue

        key = key.strip()
        # Strip surrounding quotes: KEY="abc" -> abc.
        value = value.strip().strip("\"'").strip()
        if key:
            os.environ.setdefault(key, value)


def _configure_runtime():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    # Resolve relative to this file, not CWD, so uvicorn reload + repo-root launches both work.
    backend_dir = Path(__file__).resolve().parent
    _load_local_env_file(backend_dir / ".env")
    # Only log presence, never the value.
    logging.info("Startup: IPQS_API_KEY loaded=%s", bool(os.environ.get("IPQS_API_KEY", "").strip()))


# Must run before scanner modules read env vars at import time.
_configure_runtime()


app = FastAPI(title="PhishWall Backend", version="1.0.0")


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    # The add-on parses error/details directly; keep the shape stable.
    return JSONResponse(
        status_code=422,
        content=ErrorResponse(
            error="Validation error",
            details=str(exc),
        ).model_dump(),
    )


@app.exception_handler(Exception)
async def generic_exception_handler(request: Request, exc: Exception):
    # Log the traceback server-side, return a generic message to the client.
    logging.exception("Unhandled backend exception")
    return JSONResponse(
        status_code=500,
        content=ErrorResponse(
            error="Backend error",
            details="Internal server error",
        ).model_dump(),
    )


def _request_to_scan_data(payload: ScanRequest) -> Dict[str, Any]:
    # by_alias=True preserves the wire name "from" (Python keyword in the model as from_).
    data = payload.model_dump(by_alias=True)
    data["attachments"] = [attachment.model_dump() for attachment in payload.attachments]
    return data


@app.get("/health", response_model=HealthResponse)
async def health():
    return HealthResponse(status="ok")


@app.post("/scan", response_model=ScanResponse)
async def scan(payload: ScanRequest):
    # Thin route: all scanning + parallel work lives in analyze_email.
    scan_input = _request_to_scan_data(payload)
    result = analyze_email(scan_input)
    return ScanResponse(**result)
