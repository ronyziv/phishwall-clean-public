"""Pydantic schemas for the wire contract between the Gmail add-on and the backend.

max_length caps double as a cheap DoS guard: oversized payloads are rejected at
validation time before the scanners ever see them.
"""

from typing import List, Optional

from pydantic import BaseModel, Field


class AttachmentInput(BaseModel):
    filename: str = Field(default="", max_length=260)
    mimeType: str = Field(default="", max_length=120)
    # ~2MB per attachment keeps memory bounded.
    contentBase64: str = Field(default="", max_length=2_000_000)


class ScanRequest(BaseModel):
    subject: str = Field(default="", max_length=300)
    # "from" is a Python keyword; exposed as from_ but serialized as "from" on the wire.
    from_: str = Field(default="", alias="from", max_length=320)
    to: List[str] = Field(default_factory=list, max_length=200)
    cc: List[str] = Field(default_factory=list, max_length=200)
    bcc: List[str] = Field(default_factory=list, max_length=200)
    reply_to: str = Field(default="", max_length=320)
    body: str = Field(default="", max_length=200_000)
    body_snippet: str = Field(default="", max_length=5_000)
    # Any one of these date fields is used (see scan_service.analyze_email).
    date: str = Field(default="", max_length=100)
    sent_at: str = Field(default="", max_length=100)
    timestamp: str = Field(default="", max_length=100)
    urls: List[str] = Field(default_factory=list, max_length=300)
    attachments: List[AttachmentInput] = Field(default_factory=list, max_length=100)
    # Threads from this sender already in the mailbox (180d window). The verdict
    # engine uses this to soften borderline scores for known correspondents — never
    # to bypass hard blockers.
    sender_prior_thread_count: int = Field(default=0, ge=0, le=200)

    model_config = {
        # Accept both the Python name (from_) and the JSON alias (from).
        "populate_by_name": True,
        # Drop unknown keys instead of 422-ing — keeps add-on / backend versions loose.
        "extra": "ignore",
    }


class AttachmentSummary(BaseModel):
    count: int
    safePdfCount: int
    pdfWithLinksCount: int
    executableCount: int
    unknownAttachmentCount: int


class UrlSummary(BaseModel):
    count: int
    unresolvedHosts: int
    ipqsFlagged: int
    gsbFlagged: int = 0


class SenderSummary(BaseModel):
    email: str
    domain: str
    emailsChecked: int
    ipqsFlagged: int
    vtFlagged: int


class LanguageSummary(BaseModel):
    heuristicPenalty: int


class TimeSummary(BaseModel):
    analyzed: bool
    riskPenalty: int
    becContext: bool
    atoContext: bool
    hour: Optional[int] = None
    weekday: Optional[int] = None


class ScoreBreakdown(BaseModel):
    # urlRaw is for diagnostics; urlApplied (raw * 0.7) is what actually feeds the score.
    keywords: int
    language: int
    sender: int
    time: int
    qr: int
    priorityThreats: int
    linkBase: int
    urlRaw: int
    urlApplied: int
    attachments: int
    totalPenalty: int


class ScanResponse(BaseModel):
    # score = trust (100 = clean); maliciousScore = 100 - score (the headline number in the UI).
    score: int
    maliciousScore: int
    verdict: str
    color: str
    icon: str
    verdictReasoning: str
    recommendation: str
    # True when prior-mailbox history relaxed a borderline verdict.
    familiarSenderCalibration: bool = False
    links: int
    riskWords: int
    # Legacy alias for riskIndicators — older add-on builds still read it.
    comments: List[str]
    riskIndicators: List[str]
    infoFindings: List[str]
    reasons: List[str]
    scoreBreakdown: ScoreBreakdown
    attachmentSummary: AttachmentSummary
    urlSummary: UrlSummary
    senderSummary: SenderSummary
    languageSummary: LanguageSummary
    timeSummary: TimeSummary
    # Plain dicts: shapes evolve more often than the others.
    qrSummary: dict
    priorityThreatSummary: dict


class HealthResponse(BaseModel):
    status: str = "ok"


class ErrorResponse(BaseModel):
    error: str
    details: Optional[str] = None
