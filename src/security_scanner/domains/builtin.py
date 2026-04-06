"""
Built-in security domain — wraps the existing regex-based check_* functions.

This domain is always available (zero external dependencies) and provides
the original SEC-001 through SEC-012 rules.
"""

import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from security_scanner.scanner import (
    Finding,
    _scan_single_file,
    _should_skip,
    _sort_findings,
    SOURCE_EXTS,
    EXTRA_SCAN_FILES,
)

from .base import Domain, DomainResult


class BuiltinSecurityDomain(Domain):
    """The original ai-security-scan regex rules (SEC-001 .. SEC-012)."""

    name = "security"
    description = (
        "Built-in static security checks for AI-generated web apps: "
        "hardcoded secrets, injection, CORS, auth, localStorage, and more."
    )

    def is_available(self) -> bool:
        return True  # pure Python, always available

    def run(
        self,
        project_root: Path,
        paths: Optional[List[Path]] = None,
        config: Optional[Dict[str, Any]] = None,
    ) -> DomainResult:
        t0 = time.monotonic()
        findings: List[Finding] = []
        scanned = 0

        if paths is not None:
            # Incremental mode: scan only the given files
            for fpath in paths:
                if not fpath.is_file():
                    continue
                if _should_skip(fpath, project_root):
                    continue
                if fpath.suffix not in SOURCE_EXTS and not fpath.name.startswith(".env") and fpath.name not in EXTRA_SCAN_FILES:
                    continue
                try:
                    rel = str(fpath.relative_to(project_root))
                except ValueError:
                    continue
                scanned += 1
                findings.extend(_scan_single_file(fpath, rel, project_root))
        else:
            # Full project scan
            for fpath in project_root.rglob("*"):
                if not fpath.is_file():
                    continue
                if _should_skip(fpath, project_root):
                    continue
                if fpath.suffix not in SOURCE_EXTS and not fpath.name.startswith(".env") and fpath.name not in EXTRA_SCAN_FILES:
                    continue
                try:
                    rel = str(fpath.relative_to(project_root))
                except ValueError:
                    continue
                scanned += 1
                findings.extend(_scan_single_file(fpath, rel, project_root))

        _sort_findings(findings)

        return DomainResult(
            domain="security",
            findings=findings,
            tool_name="builtin",
            tool_version="0.3.0",
            execution_time=time.monotonic() - t0,
            metadata={"scanned_files": scanned},
        )
