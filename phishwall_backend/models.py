from typing import List, Optional

from pydantic import BaseModel, Field


class AttachmentInput(BaseModel):
    filename: str = Field(default="", max_length=260)
    mimeType: str = Field(default="", max_length=120)
    contentBase64: str = Field(default="", max_length=2_000_000)


class ScanRequest(BaseModel):
    subject: str = Field(default="", max_length=300)
    from_: str = Field(default="", alias="from", max_length=320)
    to: List[str] = Field(default_factory=list, max_length=200)
    cc: List[str] = Field(default_factory=list, max_length=200)
    bcc: List[str] = Field(default_factory=list, max_length=200)
    reply_to: str = Field(default="", max_length=320)
    body: str = Field(default="", max_length=200_000)
    body_snippet: str = Field(default="", max_length=5_000)
    date: str = Field(default="", max_length=100)
    sent_at: str = Field(default="", max_length=100)
    timestamp: str = Field(default="", max_length=100)
    urls: List[str] = Field(default_factory=list, max_length=300)
    attachments: List[AttachmentInput] = Field(default_factory=list, max_length=100)
    # Optional: Gmail add-on counts threads from this mailbox with the same sender (e.g. newer_than:180d).
    sender_prior_thread_count: int = Field(default=0, ge=0, le=200)

    model_config = {
        "populate_by_name": True,
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
    score: int
    maliciousScore: int
    verdict: str
    color: str
    icon: str
    verdictReasoning: str
    recommendation: str
    familiarSenderCalibration: bool = False
    links: int
    riskWords: int
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
    qrSummary: dict
    priorityThreatSummary: dict


class HealthResponse(BaseModel):
    status: str = "ok"


class ErrorResponse(BaseModel):
    error: str
    details: Optional[str] = None
