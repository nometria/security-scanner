"""
SCA domain - Software Composition Analysis (dependency vulnerability scanning).

Uses Trivy to scan lock files / manifests for known CVEs.
"""

import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from security_scanner.scanner import Finding, CRITICAL, HIGH, MEDIUM, LOW

from .base import Domain, DomainResult
from .tool_runner import ToolRunner

_CVSS_SEVERITY = {
    "CRITICAL": CRITICAL,
    "HIGH": HIGH,
    "MEDIUM": MEDIUM,
    "LOW": LOW,
    "UNKNOWN": LOW,
}


class ScaDomain(Domain):
    name = "sca"
    description = "Dependency vulnerability scanning via Trivy."

    def __init__(self):
        self._runner = ToolRunner()

    def is_available(self) -> bool:
        return bool(self._runner.find_tool("trivy"))

    def run(self, project_root: Path, paths: Optional[List[Path]] = None,
            config: Optional[Dict[str, Any]] = None) -> DomainResult:
        t0 = time.monotonic()

        tool = self._runner.find_tool("trivy")
        if not tool:
            return DomainResult(
                domain="sca",
                errors=["trivy not found in PATH or managed tools"],
                execution_time=time.monotonic() - t0,
            )

        cmd = [
            str(tool), "fs",
            "--format", "json",
            "--scanners", "vuln",
            "--severity", "UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL",
            str(project_root),
        ]

        parsed, output = self._runner.run_json(cmd, cwd=project_root, timeout=300)

        findings: List[Finding] = []
        if parsed and isinstance(parsed, dict):
            for result in parsed.get("Results", []):
                target = result.get("Target", "")
                for vuln in result.get("Vulnerabilities", []):
                    cve = vuln.get("VulnerabilityID", "UNKNOWN")
                    sev = _CVSS_SEVERITY.get(vuln.get("Severity", "UNKNOWN"), LOW)
                    pkg = vuln.get("PkgName", "")
                    installed = vuln.get("InstalledVersion", "")
                    fixed = vuln.get("FixedVersion", "")
                    title = vuln.get("Title", vuln.get("Description", "")[:120])

                    fix_msg = ""
                    if fixed:
                        fix_msg = f"Update {pkg} from {installed} to {fixed}"
                    elif pkg:
                        fix_msg = f"No fix available yet for {pkg}@{installed}"

                    findings.append(Finding(
                        rule_id=f"SCA-{cve}",
                        severity=sev,
                        file=target,
                        line=0,
                        message=f"{pkg}@{installed}: {title}",
                        snippet=f"Package: {pkg}, Installed: {installed}, Fixed: {fixed or 'N/A'}",
                        fix=fix_msg,
                        domain="sca",
                        tool="trivy",
                        category="vulnerability",
                        url=vuln.get("PrimaryURL", ""),
                    ))

        errors = []
        if output.stderr and output.returncode != 0:
            errors.append(f"trivy: {output.stderr[:200]}")

        return DomainResult(
            domain="sca",
            findings=findings,
            tool_name="trivy",
            execution_time=time.monotonic() - t0,
            errors=errors,
        )
