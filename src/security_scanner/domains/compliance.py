"""
Compliance domain - wraps the HIPAA / SOC2 / OWASP / FedRAMP rule engine
(ported from the standalone ``security-validator`` package, now living at
``security_scanner.compliance``) as a regular scan Domain.

Why wrap rather than rewrite:
  • The compliance ruleset has 33 rules with regulatory references, severities,
    auto-fix metadata, and a manual-action checklist (MAN-001..014). Rewriting
    them as ``security_scanner.scanner`` SEC-style rules would be lossy.
  • The compliance scanner has its own ``ScanReport`` shape with per-framework
    breakdown - we keep it intact for the dedicated ``--framework``/``--checklist``
    CLI paths, and convert to the scanner's normalised ``Finding`` here for the
    multi-domain run.
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from security_scanner.domains.base import Domain, DomainResult
from security_scanner.scanner import Finding as ScannerFinding


class ComplianceDomain(Domain):
    """Runs the compliance ruleset (HIPAA/SOC2/OWASP/FedRAMP) as a domain."""

    name = "compliance"
    description = (
        "Compliance scan: HIPAA, SOC 2 Type II, OWASP Top 10, FedRAMP Moderate "
        "- 33 framework rules with regulatory references and remediation."
    )

    def __init__(self, frameworks: Optional[List[str]] = None):
        # Parsed at runtime to avoid importing rich/click at module load time
        # in environments that don't have the compliance optional deps installed.
        self._frameworks = frameworks  # None = all four

    def is_available(self) -> bool:
        try:
            import security_scanner.compliance.scanner  # noqa: F401
            return True
        except Exception:
            return False

    def run(
        self,
        project_root: Path,
        paths: Optional[List[Path]] = None,
        config: Optional[Dict[str, Any]] = None,
    ) -> DomainResult:
        t0 = time.time()
        cfg_overrides = config or {}

        try:
            from security_scanner.compliance.config import (
                Framework,
                ScanConfig,
            )
            from security_scanner.compliance.scanner import Scanner
        except Exception as e:
            return DomainResult(
                domain=self.name,
                tool_name="compliance",
                errors=[f"compliance subpackage import failed: {e}"],
                execution_time=time.time() - t0,
            )

        # Frameworks: CLI / config override > constructor > all
        fw_names = (
            cfg_overrides.get("frameworks")
            or self._frameworks
            or [f.value for f in Framework]
        )
        frameworks = [
            f for f in Framework if f.value in {n.upper() for n in fw_names}
        ] or list(Framework)

        scan_paths = list(paths) if paths else [project_root]
        scan_config = ScanConfig(paths=scan_paths, frameworks=frameworks)

        try:
            report = Scanner(scan_config).scan()
        except Exception as e:
            return DomainResult(
                domain=self.name,
                tool_name="compliance",
                errors=[f"compliance scan failed: {e}"],
                execution_time=time.time() - t0,
            )

        # Convert compliance Findings → normalised scanner Findings.
        # We preserve framework + reference on the Finding's category/url fields
        # so the dashboard can render them without a separate code path.
        normalised: List[ScannerFinding] = []
        for f in report.findings:
            normalised.append(
                ScannerFinding(
                    rule_id=f.rule_id,
                    severity=f.severity.value if hasattr(f.severity, "value") else str(f.severity),
                    file=str(f.file_path),
                    line=f.line_number,
                    message=f.title,
                    snippet=f.line_content,
                    fix=f.remediation,
                    domain=self.name,
                    tool="compliance",
                    category=f.framework.value if hasattr(f.framework, "value") else str(f.framework),
                    url=f.reference,
                )
            )

        return DomainResult(
            domain=self.name,
            findings=normalised,
            tool_name="compliance",
            tool_version="1.0",
            execution_time=time.time() - t0,
            metadata={
                "frameworks": [f.value for f in frameworks],
                "rules_applied": report.rules_applied,
                "scanned_files": report.scanned_files,
                "skipped_files": report.skipped_files,
                "by_framework": {
                    fw.value: len(findings)
                    for fw, findings in report.by_framework.items()
                },
            },
        )
