from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Protocol


@dataclass
class ScanContext:
    subject: str
    sender: str
    body: str
    body_snippet: str
    sent_at: str
    urls: List[str] = field(default_factory=list)
    attachments: List[Dict[str, Any]] = field(default_factory=list)
    email_candidates: List[str] = field(default_factory=list)

    @property
    def text(self) -> str:
        return f"{self.subject} {self.sender} {self.body} {self.body_snippet}".lower()


@dataclass
class ScannerResult:
    name: str
    risk_findings: List[str] = field(default_factory=list)
    info_findings: List[str] = field(default_factory=list)
    breakdown: Dict[str, int] = field(default_factory=dict)
    summary: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)
    risk_words: Optional[int] = None


class Scanner(Protocol):
    name: str

    def applies(self, context: ScanContext, state: Dict[str, Any]) -> bool:
        ...

    def run(self, context: ScanContext, state: Dict[str, Any]) -> ScannerResult:
        ...
