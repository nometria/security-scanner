"""
json_reporter.py - Machine-readable JSON output (for CI/CD integration).
"""

from __future__ import annotations
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    from security_scanner.compliance.scanner import ScanReport


class JsonReporter:
    """
    Outputs scan results as structured JSON.

    Schema:
    {
      "scan_timestamp": "ISO-8601",
      "passed": true/false,
      "summary": { "total": N, "critical": N, "high": N, "medium": N, "low": N },
      "findings": [ <Finding.as_dict()>, ... ]
    }
    """

    def __init__(self, output_file: Optional[Path] = None, indent: int = 2):
        self.output_file = output_file
        self.indent = indent

    def report(self, scan_report: "ScanReport") -> str:
        payload = {
            "scan_timestamp": datetime.now(tz=timezone.utc).isoformat(),
            "passed": scan_report.passed,
            "scanned_files": scan_report.scanned_files,
            "rules_applied": scan_report.rules_applied,
            "summary": {
                "total": len(scan_report.findings),
                "critical": len(scan_report.critical),
                "high": len(scan_report.high),
                "medium": len(scan_report.medium),
                "low": len(scan_report.low),
            },
            "findings": [f.as_dict() for f in scan_report.findings],
        }

        output = json.dumps(payload, indent=self.indent, default=str)

        if self.output_file:
            Path(self.output_file).write_text(output, encoding="utf-8")
        else:
            print(output)

        return output
