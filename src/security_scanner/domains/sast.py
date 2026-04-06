"""
SAST domain — Static Application Security Testing via OpenGrep (semgrep fork).

Runs ``opengrep scan`` (or ``semgrep scan``) with JSON output and normalises
results into the common Finding format.
"""

import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from security_scanner.scanner import Finding, HIGH, MEDIUM, LOW

from .base import Domain, DomainResult
from .tool_runner import ToolRunner

_SEVERITY_MAP = {
    "ERROR": HIGH,
    "WARNING": MEDIUM,
    "INFO": LOW,
}

_IMPACT_SEVERITY = {
    "HIGH": HIGH,
    "MEDIUM": MEDIUM,
    "LOW": LOW,
}


class SastDomain(Domain):
    name = "sast"
    description = "Static Application Security Testing via OpenGrep / Semgrep."

    def __init__(self):
        self._runner = ToolRunner()

    def is_available(self) -> bool:
        return bool(
            self._runner.find_tool("opengrep")
            or self._runner.find_tool("semgrep")
        )

    def run(self, project_root: Path, paths: Optional[List[Path]] = None,
            config: Optional[Dict[str, Any]] = None) -> DomainResult:
        t0 = time.monotonic()

        tool_path = (
            self._runner.find_tool("opengrep")
            or self._runner.find_tool("semgrep")
        )
        if not tool_path:
            return DomainResult(
                domain="sast",
                errors=["Neither opengrep nor semgrep found in PATH or managed tools"],
                execution_time=time.monotonic() - t0,
            )

        tool_name = "opengrep" if "opengrep" in str(tool_path) else "semgrep"
        cmd = [str(tool_path), "scan", "--json"]

        # Add custom rulesets if configured
        if config and "rulesets" in config:
            for rs in config["rulesets"]:
                cmd += ["--config", rs]
        else:
            cmd += ["--config", "auto"]

        if paths:
            for p in paths:
                cmd += ["--include", str(p)]
        cmd.append(str(project_root))

        parsed, output = self._runner.run_json(cmd, cwd=project_root, timeout=600)

        findings: List[Finding] = []
        if parsed and isinstance(parsed, dict):
            for result in parsed.get("results", []):
                check_id = result.get("check_id", "unknown")
                extra = result.get("extra", {})
                severity = extra.get("severity", "WARNING")
                impact = extra.get("metadata", {}).get("impact", "")

                sev = _IMPACT_SEVERITY.get(impact, _SEVERITY_MAP.get(severity, MEDIUM))

                start = result.get("start", {})
                findings.append(Finding(
                    rule_id=f"SAST-{check_id}",
                    severity=sev,
                    file=result.get("path", ""),
                    line=start.get("line", 0),
                    message=extra.get("message", result.get("check_id", "")),
                    snippet=extra.get("lines", "")[:80],
                    fix=extra.get("fix", "") or extra.get("metadata", {}).get("fix", ""),
                    domain="sast",
                    tool=tool_name,
                    category="security",
                    url=extra.get("metadata", {}).get("references", [""])[0]
                        if extra.get("metadata", {}).get("references") else "",
                ))

        errors = []
        if parsed and parsed.get("errors"):
            for err in parsed["errors"]:
                errors.append(f"SAST: {err.get('message', str(err))}")

        return DomainResult(
            domain="sast",
            findings=findings,
            tool_name=tool_name,
            tool_version="",
            execution_time=time.monotonic() - t0,
            errors=errors,
        )
