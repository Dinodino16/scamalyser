"""Run every check and turn the findings into an explainable risk score.

Scoring model (keep it simple enough to explain on a whiteboard):

    score   = min(100, sum of points of every finding)
    verdict = LOW (0-24) | SUSPICIOUS (25-49) | LIKELY PHISHING (50+)

Why additive points instead of machine learning?
* Explainability: every point maps to a sentence a non-expert understands.
* No training data needed, and no "the model said so" answers.
* Weights encode expert judgement and are easy to tune in one place.
The trade-off is that weights are hand-picked; Week 2 tests against real
samples are how we check they're sensible.

Passing SPF/DKIM/DMARC never *subtracts* points. Phishers routinely pass
all three on domains they registered, so "authenticated" is not "safe".
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from .checks import auth, headers, links
from .findings import Finding
from .parser import ParsedEmail


class Verdict(str, Enum):
    LOW = "LOW RISK"
    SUSPICIOUS = "SUSPICIOUS"
    PHISHING = "LIKELY PHISHING"


SUSPICIOUS_THRESHOLD = 25
PHISHING_THRESHOLD = 50
MAX_SCORE = 100


@dataclass
class Report:
    subject: str
    sender: str
    score: int
    verdict: Verdict
    findings: list[Finding] = field(default_factory=list)
    links_checked: int = 0

    def to_dict(self) -> dict:
        return {
            "subject": self.subject,
            "sender": self.sender,
            "score": self.score,
            "verdict": self.verdict.value,
            "links_checked": self.links_checked,
            "findings": [f.to_dict() for f in self.findings],
        }


def score_findings(findings: list[Finding]) -> tuple[int, Verdict]:
    score = min(MAX_SCORE, sum(f.points for f in findings))
    if score >= PHISHING_THRESHOLD:
        return score, Verdict.PHISHING
    if score >= SUSPICIOUS_THRESHOLD:
        return score, Verdict.SUSPICIOUS
    return score, Verdict.LOW


def analyse(email: ParsedEmail, online: bool = False) -> Report:
    findings = auth.run(email, online=online) + headers.run(email) + links.run(email)
    # Highest-impact findings first so the report leads with the reason.
    findings.sort(key=lambda f: f.points, reverse=True)
    score, verdict = score_findings(findings)
    return Report(
        subject=email.subject,
        sender=email.from_header,
        score=score,
        verdict=verdict,
        findings=findings,
        links_checked=len(email.links),
    )
