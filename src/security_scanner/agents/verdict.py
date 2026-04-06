"""Verdict data models for the review agent."""

from dataclasses import dataclass, field
from typing import List

from security_scanner.scanner import Finding


@dataclass
class FindingVerdict:
    """AI review verdict for a single finding."""

    finding: Finding
    is_true_positive: bool = True
    confidence: float = 1.0  # 0.0 - 1.0
    explanation: str = ""
    suggested_fix: str = ""


@dataclass
class ReviewVerdict:
    """Aggregated AI review verdict for all findings."""

    finding_verdicts: List[FindingVerdict] = field(default_factory=list)
    risk_level: str = ""  # "critical", "high", "medium", "low", "none"
    summary: str = ""
    recommended_actions: List[str] = field(default_factory=list)

    @property
    def true_positives(self) -> List[FindingVerdict]:
        return [v for v in self.finding_verdicts if v.is_true_positive]

    @property
    def false_positives(self) -> List[FindingVerdict]:
        return [v for v in self.finding_verdicts if not v.is_true_positive]
