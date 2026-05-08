import logging
import os
from typing import Any, Dict

from dotenv import load_dotenv
from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from models import ErrorResponse, HealthResponse, ScanRequest, ScanResponse
from services.scan_service import analyze_email


def _configure_runtime():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    if load_dotenv is None:
        logging.warning("python-dotenv is not installed; .env autoload disabled.")
    else:
        # Primary environment file for runtime secrets.
        load_dotenv(dotenv_path=".env", override=False)
        # Backward-compatible fallback file name if teams still use it locally.
        load_dotenv(dotenv_path="IPQS_API.env", override=False)
    logging.info("Startup: IPQS_API_KEY loaded=%s", bool(os.environ.get("IPQS_API_KEY", "").strip()))


_configure_runtime()


app = FastAPI(title="PhishWall Backend", version="1.0.0")


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    return JSONResponse(
        status_code=422,
        content=ErrorResponse(
            error="Validation error",
            details=str(exc),
        ).model_dump(),
    )


@app.exception_handler(Exception)
async def generic_exception_handler(request: Request, exc: Exception):
    logging.exception("Unhandled backend exception")
    return JSONResponse(
        status_code=500,
        content=ErrorResponse(
            error="Backend error",
            details=str(exc),
        ).model_dump(),
    )


def _request_to_scan_data(payload: ScanRequest) -> Dict[str, Any]:
    data = payload.model_dump(by_alias=True)
    data["attachments"] = [attachment.model_dump() for attachment in payload.attachments]
    return data


@app.get("/health", response_model=HealthResponse)
async def health():
    return HealthResponse(status="ok")


@app.post("/scan", response_model=ScanResponse)
async def scan(payload: ScanRequest):
    scan_input = _request_to_scan_data(payload)
    result = analyze_email(scan_input)
    return ScanResponse(**result)