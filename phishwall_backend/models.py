from typing import List, Optional

from pydantic import BaseModel, Field


class AttachmentInput(BaseModel):
    filename: str = ""
    mimeType: str = ""
    contentBase64: str = ""


class ScanRequest(BaseModel):
    subject: str = ""
    from_: str = Field(default="", alias="from")
    to: List[str] = Field(default_factory=list)
    cc: List[str] = Field(default_factory=list)
    bcc: List[str] = Field(default_factory=list)
    reply_to: str = ""
    body: str = ""
    body_snippet: str = ""
    date: str = ""
    sent_at: str = ""
    timestamp: str = ""
    urls: List[str] = Field(default_factory=list)
    attachments: List[AttachmentInput] = Field(default_factory=list)

    model_config = {
        "populate_by_name": True,
        "extra": "allow",
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
    links: int
    riskWords: int
    comments: List[str]
    riskIndicators: List[str]
    infoFindings: List[str]
    scoreBreakdown: ScoreBreakdown
    attachmentSummary: AttachmentSummary
    urlSummary: UrlSummary
    senderSummary: SenderSummary
    languageSummary: LanguageSummary
    timeSummary: TimeSummary


class HealthResponse(BaseModel):
    status: str = "ok"


class ErrorResponse(BaseModel):
    error: str
    details: Optional[str] = None
