"""Shared types for the scanner pipeline.

Each scanner reads an immutable ScanContext and returns a self-contained
ScannerResult. That decoupling is what makes phases parallelizable.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Protocol


@dataclass
class ScanContext:
    """Read-only view of one email passed to every scanner."""

    subject: str
    sender: str
    body: str
    body_snippet: str
    sent_at: str
    urls: List[str] = field(default_factory=list)
    attachments: List[Dict[str, Any]] = field(default_factory=list)
    # All email-like strings found across headers/body, so reputation lookups can
    # also score Reply-To / quoted addresses, not just From.
    email_candidates: List[str] = field(default_factory=list)

    @property
    def text(self) -> str:
        # Pre-lowercased blob used by keyword/language/priority-threat scanners.
        return f"{self.subject} {self.sender} {self.body} {self.body_snippet}".lower()


@dataclass
class ScannerResult:
    """Output contract for every scanner.

    - risk_findings show up in the user-facing verdict.
    - info_findings are diagnostics (e.g. third-party API down) and never raise the score.
    - breakdown keys are merged into the global ScoreBreakdown.
    - summary is the public per-scanner block returned to the add-on.
    - metadata is internal-only; later phases may read it via shared state.
    """

    name: str
    risk_findings: List[str] = field(default_factory=list)
    info_findings: List[str] = field(default_factory=list)
    breakdown: Dict[str, int] = field(default_factory=dict)
    summary: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)
    # Surfaced separately because the add-on shows a "risk words" counter.
    risk_words: Optional[int] = None


class Scanner(Protocol):
    """Structural contract used by ScannerPipeline (not a base class)."""

    name: str

    def applies(self, context: ScanContext, state: Dict[str, Any]) -> bool:
        ...

    def run(self, context: ScanContext, state: Dict[str, Any]) -> ScannerResult:
        ...
