"""
IaC domain - Infrastructure-as-Code misconfiguration scanning via Checkov.
"""

import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from security_scanner.scanner import Finding, CRITICAL, HIGH, MEDIUM, LOW

from .base import Domain, DomainResult
from .tool_runner import ToolRunner

_SEVERITY_MAP = {
    "CRITICAL": CRITICAL,
    "HIGH": HIGH,
    "MEDIUM": MEDIUM,
    "LOW": LOW,
}


class IacDomain(Domain):
    name = "iac"
    description = "Infrastructure-as-Code misconfiguration scanning via Checkov."

    def __init__(self):
        self._runner = ToolRunner()

    def is_available(self) -> bool:
        return bool(self._runner.find_tool("checkov"))

    def run(self, project_root: Path, paths: Optional[List[Path]] = None,
            config: Optional[Dict[str, Any]] = None) -> DomainResult:
        t0 = time.monotonic()

        tool = self._runner.find_tool("checkov")
        if not tool:
            return DomainResult(
                domain="iac",
                errors=["checkov not found in PATH or managed tools"],
                execution_time=time.monotonic() - t0,
            )

        cmd = [str(tool), "-d", str(project_root), "--output", "json", "--quiet"]

        # Skip specific checks if configured
        if config and "skip" in config:
            cmd += ["--skip-check", ",".join(config["skip"])]

        parsed, output = self._runner.run_json(cmd, cwd=project_root, timeout=300)

        findings: List[Finding] = []
        if parsed:
            # Checkov output can be a list of check-type results or a single dict
            results_list = parsed if isinstance(parsed, list) else [parsed]
            for block in results_list:
                if not isinstance(block, dict):
                    continue
                for failed in block.get("results", {}).get("failed_checks", []):
                    check_id = failed.get("check_id", "UNKNOWN")
                    sev = _SEVERITY_MAP.get(
                        failed.get("severity", "MEDIUM"), MEDIUM
                    )
                    findings.append(Finding(
                        rule_id=f"IAC-{check_id}",
                        severity=sev,
                        file=failed.get("file_path", ""),
                        line=failed.get("file_line_range", [0, 0])[0],
                        message=failed.get("check_name", ""),
                        snippet=failed.get("resource", ""),
                        fix=failed.get("guideline", ""),
                        domain="iac",
                        tool="checkov",
                        category="misconfiguration",
                        url=failed.get("guideline", ""),
                    ))

        errors = []
        if output.stderr and output.returncode not in (0, 1):
            errors.append(f"checkov: {output.stderr[:200]}")

        return DomainResult(
            domain="iac",
            findings=findings,
            tool_name="checkov",
            execution_time=time.monotonic() - t0,
            errors=errors,
        )
