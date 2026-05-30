"""
scanner.py - Core scan engine.

Orchestrates file discovery and rule evaluation.
Completely I/O-isolated from any specific project.

Usage:
    from security_scanner.compliance.scanner import Scanner
    from security_scanner.compliance.config import ScanConfig

    config = ScanConfig(paths=[Path("./myproject")])
    scanner = Scanner(config)
    report = scanner.scan()
    print(report.summary())
"""

from __future__ import annotations

import fnmatch
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed

from security_scanner.compliance.config import Framework, Severity, ScanConfig, SEVERITY_ORDER
from security_scanner.compliance.rules import ALL_RULES
from security_scanner.compliance.rules.base import Finding, Rule


@dataclass
class ScanReport:
    """
    Immutable result of a full scan run.

    Attributes:
        findings:      All findings, sorted by severity (CRITICAL first)
        scanned_files: Total files scanned
        skipped_files: Files skipped (unreadable, excluded)
        rules_applied: How many rules ran
        config:        The config used for this scan
    """
    findings: List[Finding]
    scanned_files: int
    skipped_files: int
    rules_applied: int
    config: ScanConfig

    # ---- Convenience accessors -------------------------------------------

    @property
    def critical(self) -> List[Finding]:
        return [f for f in self.findings if f.severity == Severity.CRITICAL]

    @property
    def high(self) -> List[Finding]:
        return [f for f in self.findings if f.severity == Severity.HIGH]

    @property
    def medium(self) -> List[Finding]:
        return [f for f in self.findings if f.severity == Severity.MEDIUM]

    @property
    def low(self) -> List[Finding]:
        return [f for f in self.findings if f.severity == Severity.LOW]

    @property
    def by_framework(self) -> Dict[Framework, List[Finding]]:
        result: Dict[Framework, List[Finding]] = {}
        for f in self.findings:
            result.setdefault(f.framework, []).append(f)
        return result

    @property
    def by_severity(self) -> Dict[Severity, List[Finding]]:
        result: Dict[Severity, List[Finding]] = {}
        for f in self.findings:
            result.setdefault(f.severity, []).append(f)
        return result

    @property
    def passed(self) -> bool:
        """True when no findings exceed the configured fail_on threshold."""
        fail_threshold = SEVERITY_ORDER[self.config.fail_on]
        return all(
            SEVERITY_ORDER[f.severity] < fail_threshold
            for f in self.findings
        )

    def summary(self) -> str:
        lines = [
            f"Scan complete - {self.scanned_files} files scanned, "
            f"{len(self.findings)} findings",
            f"  CRITICAL: {len(self.critical)}",
            f"  HIGH:     {len(self.high)}",
            f"  MEDIUM:   {len(self.medium)}",
            f"  LOW:      {len(self.low)}",
            f"  Passed:   {'✅ YES' if self.passed else '❌ NO'}",
        ]
        return "\n".join(lines)


class Scanner:
    """
    Main scan engine.

    Thread-safe: one Scanner instance can be shared across threads.
    Files are scanned in parallel using a ThreadPoolExecutor.
    """

    def __init__(self, config: ScanConfig, rules: Optional[List[Rule]] = None):
        self.config = config
        self.rules = rules or [
            r for r in ALL_RULES
            if r.framework in config.frameworks
        ]

    # ---- Public API -------------------------------------------------------

    def scan(self) -> ScanReport:
        """Discover all files and run all applicable rules against them."""
        files = list(self._discover_files())
        findings: List[Finding] = []
        skipped = 0

        with ThreadPoolExecutor(max_workers=min(8, len(files) or 1)) as pool:
            future_to_file = {
                pool.submit(self._scan_file, f): f for f in files
            }
            for future in as_completed(future_to_file):
                try:
                    file_findings = future.result()
                    findings.extend(file_findings)
                except Exception:
                    skipped += 1

        # Sort by severity (CRITICAL first), then file path
        findings.sort(
            key=lambda f: (
                -SEVERITY_ORDER[f.severity],
                str(f.file_path),
                f.line_number,
            )
        )

        return ScanReport(
            findings=findings,
            scanned_files=len(files) - skipped,
            skipped_files=skipped,
            rules_applied=len(self.rules),
            config=self.config,
        )

    def scan_content(self, content: str, file_path: Path) -> List[Finding]:
        """
        Scan a string of content as if it were `file_path`.
        Useful for testing individual snippets without touching the filesystem.
        """
        findings = []
        for rule in self.rules:
            if not rule.applies_to(file_path):
                continue
            try:
                for finding in rule.check(file_path, content):
                    findings.append(finding)
                    if (
                        self.config.max_findings_per_rule > 0
                        and len(findings) >= self.config.max_findings_per_rule
                    ):
                        break
            except Exception:
                pass  # Never let a rule crash the scanner
        return findings

    # ---- Internal helpers -------------------------------------------------

    def _discover_files(self):
        """Yield all files matching the configured include/exclude patterns."""
        for root_path in self.config.paths:
            root = Path(root_path).resolve()
            if root.is_file():
                if self._is_included(root):
                    yield root
                continue
            for dirpath, dirnames, filenames in os.walk(root):
                dir_path = Path(dirpath)
                # Prune excluded directories in-place for efficiency
                dirnames[:] = [
                    d for d in dirnames
                    if not self._is_excluded(dir_path / d, root)
                ]
                for fname in filenames:
                    file_path = dir_path / fname
                    if self._is_included(file_path) and not self._is_excluded(file_path, root):
                        yield file_path

    def _is_included(self, file_path: Path) -> bool:
        if not self.config.include_extensions:
            return True
        return file_path.suffix.lower() in self.config.include_extensions

    def _is_excluded(self, path: Path, root: Path) -> bool:
        try:
            rel = path.relative_to(root)
        except ValueError:
            rel = path
        rel_str = str(rel)
        rel_parts = rel.parts
        for pattern in self.config.exclude_patterns:
            if fnmatch.fnmatch(rel_str, pattern) or fnmatch.fnmatch(path.name, pattern):
                return True
            # Handle **/name/** patterns: exclude if 'name' appears as any path component.
            # Python's fnmatch does not treat ** as a multi-segment wildcard, so we must
            # check explicitly for this common case.
            if pattern.startswith("**/") and pattern.endswith("/**"):
                inner = pattern[3:-3]
                if inner in rel_parts:
                    return True
        return False

    def _scan_file(self, file_path: Path) -> List[Finding]:
        """Read and scan a single file. Returns findings for this file."""
        try:
            content = file_path.read_text(encoding="utf-8", errors="replace")
        except (PermissionError, OSError):
            return []

        # Filter to min severity
        min_order = SEVERITY_ORDER[self.config.min_severity]
        findings = []

        for rule in self.rules:
            if not rule.applies_to(file_path):
                continue
            try:
                for finding in rule.check(file_path, content):
                    if SEVERITY_ORDER[finding.severity] >= min_order:
                        findings.append(finding)
                        if (
                            self.config.max_findings_per_rule > 0
                            and len(findings) >= self.config.max_findings_per_rule
                        ):
                            break
            except Exception:
                pass  # Defensive: never let a rule bring down the scanner

        return findings
