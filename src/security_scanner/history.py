"""
Quality history tracking — stores scan snapshots for trend analysis.

Maintains a JSON history file at ``.ai-security-scan/quality-history.json``
and supports health score calculation with trend indicators.
"""

import json
import time
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Dict, List, Optional

from security_scanner.scanner import ScanResult, LOW

DEFAULT_HISTORY_DIR = ".ai-security-scan"
DEFAULT_HISTORY_FILE = "quality-history.json"
MAX_SNAPSHOTS = 90


@dataclass
class QualitySnapshot:
    """A point-in-time quality measurement."""

    timestamp: float
    scanned_files: int
    total_findings: int
    critical: int
    high: int
    medium: int
    low: int
    health_score: float  # 0.0 - 10.0
    domains: Dict[str, int]  # domain → finding count
    passed: bool


def compute_health_score(result: ScanResult) -> float:
    """Calculate a health score from 0.0 (worst) to 10.0 (best).

    Scoring:
      - Start at 10.0
      - Deduct 2.0 per CRITICAL finding
      - Deduct 1.0 per HIGH finding
      - Deduct 0.3 per MEDIUM finding
      - Deduct 0.1 per LOW finding
      - Floor at 0.0
    """
    score = 10.0
    score -= result.critical_count * 2.0
    score -= result.high_count * 1.0
    score -= result.medium_count * 0.3
    score -= sum(1 for f in result.findings if f.severity == LOW) * 0.1
    return max(0.0, round(score, 1))


def create_snapshot(result: ScanResult) -> QualitySnapshot:
    """Create a snapshot from a ScanResult."""
    domain_counts: Dict[str, int] = {}
    for f in result.findings:
        domain_counts[f.domain] = domain_counts.get(f.domain, 0) + 1

    return QualitySnapshot(
        timestamp=time.time(),
        scanned_files=result.scanned,
        total_findings=len(result.findings),
        critical=result.critical_count,
        high=result.high_count,
        medium=result.medium_count,
        low=sum(1 for f in result.findings if f.severity == LOW),
        health_score=compute_health_score(result),
        domains=domain_counts,
        passed=result.passed,
    )


class HistoryManager:
    """Manages quality history snapshots."""

    def __init__(self, project_root: Path, max_snapshots: int = MAX_SNAPSHOTS):
        self.history_dir = project_root / DEFAULT_HISTORY_DIR
        self.history_file = self.history_dir / DEFAULT_HISTORY_FILE
        self.max_snapshots = max_snapshots

    def append(self, snapshot: QualitySnapshot) -> None:
        """Add a snapshot, pruning old entries if over the limit."""
        snapshots = self._load()
        snapshots.append(asdict(snapshot))
        if len(snapshots) > self.max_snapshots:
            snapshots = snapshots[-self.max_snapshots:]
        self._save(snapshots)

    def get_latest(self) -> Optional[QualitySnapshot]:
        snapshots = self._load()
        if not snapshots:
            return None
        return self._dict_to_snapshot(snapshots[-1])

    def get_previous(self) -> Optional[QualitySnapshot]:
        snapshots = self._load()
        if len(snapshots) < 2:
            return None
        return self._dict_to_snapshot(snapshots[-2])

    def get_snapshots(self, count: int = 10) -> List[QualitySnapshot]:
        snapshots = self._load()
        return [self._dict_to_snapshot(s) for s in snapshots[-count:]]

    def trend_indicator(self) -> str:
        """Return a trend arrow comparing latest to previous snapshot."""
        latest = self.get_latest()
        prev = self.get_previous()
        if latest is None or prev is None:
            return ""
        delta = latest.health_score - prev.health_score
        if delta > 0.5:
            return f"↑ +{delta:.1f}"
        elif delta < -0.5:
            return f"↓ {delta:.1f}"
        else:
            return "→ stable"

    def _load(self) -> List[dict]:
        if not self.history_file.is_file():
            return []
        try:
            return json.loads(self.history_file.read_text())
        except (json.JSONDecodeError, OSError):
            return []

    def _save(self, snapshots: List[dict]) -> None:
        self.history_dir.mkdir(parents=True, exist_ok=True)
        self.history_file.write_text(json.dumps(snapshots, indent=2))

    @staticmethod
    def _dict_to_snapshot(d: dict) -> QualitySnapshot:
        return QualitySnapshot(**{
            k: d.get(k, 0) for k in QualitySnapshot.__dataclass_fields__
        })
