"""The Finding type: one piece of evidence that an email may be phishing.

Every check in Scamalyser returns a list of Findings. The risk score is
nothing more than the sum of the findings' points, so every point in the
final score can be traced back to a specific, human-readable reason.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import Enum


class Severity(str, Enum):
    """How worried a single finding should make you.

    INFO findings carry no points. They exist so the report can show what
    was checked and passed (e.g. "DKIM signature verified"), which matters
    when you need to explain why an email scored low.
    """

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


@dataclass(frozen=True)
class Finding:
    check: str          # machine-readable id, e.g. "headers.reply_to_mismatch"
    severity: Severity
    points: int         # contribution to the 0-100 risk score
    title: str          # one-line summary shown in the report
    detail: str         # the evidence: what we saw and why it matters

    def to_dict(self) -> dict:
        data = asdict(self)
        data["severity"] = self.severity.value
        return data
