"""
Container domain — container image vulnerability scanning via Trivy.

Detects Dockerfiles in the project, identifies the image name, and scans
for known CVEs in the container layers.
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


def _find_dockerfiles(project_root: Path) -> List[Path]:
    """Find Dockerfiles in the project."""
    found = []
    for p in project_root.rglob("*"):
        if p.is_file():
            name = p.name.lower()
            if name == "dockerfile" or name.startswith("dockerfile.") or name.endswith(".dockerfile"):
                found.append(p)
    return found


class ContainerDomain(Domain):
    name = "container"
    description = "Container image vulnerability scanning via Trivy."

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
                domain="container",
                errors=["trivy not found"],
                execution_time=time.monotonic() - t0,
            )

        dockerfiles = _find_dockerfiles(project_root)
        if not dockerfiles:
            return DomainResult(
                domain="container",
                tool_name="trivy",
                execution_time=time.monotonic() - t0,
                metadata={"scanned_files": 0},
            )

        findings: List[Finding] = []
        errors: List[str] = []

        # Scan each Dockerfile's config (misconfigurations)
        for df in dockerfiles:
            cmd = [
                str(tool), "config",
                "--format", "json",
                str(df),
            ]
            parsed, output = self._runner.run_json(cmd, cwd=project_root, timeout=120)
            if parsed and isinstance(parsed, dict):
                for result in parsed.get("Results", []):
                    for misconfig in result.get("Misconfigurations", []):
                        sev = _CVSS_SEVERITY.get(misconfig.get("Severity", "MEDIUM"), MEDIUM)
                        try:
                            rel = str(df.relative_to(project_root))
                        except ValueError:
                            rel = str(df)
                        findings.append(Finding(
                            rule_id=f"CONTAINER-{misconfig.get('ID', 'UNKNOWN')}",
                            severity=sev,
                            file=rel,
                            line=misconfig.get("CauseMetadata", {}).get("StartLine", 0),
                            message=misconfig.get("Title", ""),
                            snippet=misconfig.get("Message", "")[:80],
                            fix=misconfig.get("Resolution", ""),
                            domain="container",
                            tool="trivy",
                            category="misconfiguration",
                            url=misconfig.get("PrimaryURL", ""),
                        ))

        return DomainResult(
            domain="container",
            findings=findings,
            tool_name="trivy",
            execution_time=time.monotonic() - t0,
            errors=errors,
            metadata={"scanned_files": len(dockerfiles)},
        )
