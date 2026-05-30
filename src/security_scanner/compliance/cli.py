"""
cli.py - Command-line interface for the HIPAA/SOC2/FedRAMP scanner.

Usage:
    hipaa-soc2-scan [OPTIONS] PATH [PATH...]

Examples:
    # Full scan - all frameworks, show per-endpoint map
    hipaa-soc2-scan . --endpoint-report

    # Scan + interactively apply all auto-fixable patches
    hipaa-soc2-scan . --fix

    # Generate the manual compliance checklist (MFA, BAA, RLS, etc.)
    hipaa-soc2-scan . --checklist --checklist-output COMPLIANCE_CHECKLIST.md

    # FedRAMP only, fail on CRITICAL
    hipaa-soc2-scan . --framework FEDRAMP --fail-on CRITICAL

    # JSON output for CI artefacts
    hipaa-soc2-scan . --format json --output scan-report.json

    # Dry-run: show what --fix would do without writing
    hipaa-soc2-scan . --fix --dry-run

    # HIPAA-only scan, no remediation text
    hipaa-soc2-scan . --framework HIPAA --no-remediation
"""

from __future__ import annotations

import fnmatch
import sys
from pathlib import Path
from typing import List, Optional, Tuple

import click

from security_scanner.compliance.config import Framework, Severity, ScanConfig
from security_scanner.compliance.scanner import Scanner
from security_scanner.compliance.reporters import ConsoleReporter, JsonReporter, HtmlReporter, ChecklistReporter


def _parse_severity(value: str) -> Severity:
    try:
        return Severity[value.upper()]
    except KeyError:
        raise click.BadParameter(
            f"Unknown severity '{value}'. Choose from: {[s.value for s in Severity]}"
        )


def _parse_framework(value: str) -> Framework:
    try:
        return Framework[value.upper()]
    except KeyError:
        raise click.BadParameter(
            f"Unknown framework '{value}'. Choose from: {[f.value for f in Framework]}"
        )


@click.command(name="hipaa-soc2-scan")
@click.argument("paths", nargs=-1, type=click.Path(exists=True), required=True)
@click.option(
    "--framework", "-f",
    multiple=True,
    default=("HIPAA", "SOC2", "OWASP", "FEDRAMP"),
    show_default=True,
    help="Compliance framework(s) to check. Can be repeated.",
)
@click.option(
    "--min-severity", "-s",
    default="LOW",
    show_default=True,
    help="Minimum severity to report [CRITICAL|HIGH|MEDIUM|LOW|INFO].",
)
@click.option(
    "--fail-on",
    default="HIGH",
    show_default=True,
    help="Exit with code 1 if any finding at this severity or above is found.",
)
@click.option(
    "--format", "output_format",
    type=click.Choice(["console", "json", "html"], case_sensitive=False),
    default="console",
    show_default=True,
    help="Output format for the main scan report.",
)
@click.option(
    "--output", "-o",
    default=None,
    type=click.Path(),
    help="Write scan report to this file (default: stdout).",
)
@click.option(
    "--endpoint-report",
    is_flag=True,
    default=False,
    help=(
        "Run AST-based endpoint scanner on discovered Python files and print "
        "a per-endpoint vulnerability map."
    ),
)
@click.option(
    "--fix",
    is_flag=True,
    default=False,
    help=(
        "After scanning, interactively offer to apply auto-fixable patches. "
        "Shows a unified diff before each change and asks for confirmation."
    ),
)
@click.option(
    "--fix-all",
    is_flag=True,
    default=False,
    help="Apply all auto-fixable patches without prompting (non-interactive).",
)
@click.option(
    "--dry-run",
    is_flag=True,
    default=False,
    help="Show what --fix would do without writing any files.",
)
@click.option(
    "--checklist",
    is_flag=True,
    default=False,
    help=(
        "Print the manual compliance action checklist (MFA, BAA contracts, "
        "RLS, encryption at rest, etc.)."
    ),
)
@click.option(
    "--checklist-output",
    default=None,
    type=click.Path(),
    help="Write the manual checklist to a Markdown file.",
)
@click.option(
    "--exclude",
    multiple=True,
    help="Glob patterns to exclude (e.g. '**/tests/**'). Can be repeated.",
)
@click.option(
    "--no-remediation",
    is_flag=True,
    default=False,
    help="Suppress remediation advice (useful for compact CI output).",
)
@click.option(
    "--no-backup",
    is_flag=True,
    default=False,
    help="Do not write .bak files when applying fixes.",
)
@click.version_option(package_name="hipaa-soc2-validator")
def main(
    paths: Tuple[str, ...],
    framework: Tuple[str, ...],
    min_severity: str,
    fail_on: str,
    output_format: str,
    output: Optional[str],
    endpoint_report: bool,
    fix: bool,
    fix_all: bool,
    dry_run: bool,
    checklist: bool,
    checklist_output: Optional[str],
    exclude: Tuple[str, ...],
    no_remediation: bool,
    no_backup: bool,
) -> None:
    """
    HIPAA / SOC 2 / OWASP / FedRAMP compliance scanner.

    Scans PATH(s) for security and compliance violations.

    \b
    Exit codes:
      0 - scan passed (no findings at or above --fail-on threshold)
      1 - scan failed (findings at or above --fail-on threshold)
    """
    frameworks = [_parse_framework(f) for f in framework]
    min_sev = _parse_severity(min_severity)
    fail_sev = _parse_severity(fail_on)
    exclude_patterns = _default_excludes() + list(exclude)

    config = ScanConfig(
        paths=[Path(p) for p in paths],
        frameworks=frameworks,
        min_severity=min_sev,
        fail_on=fail_sev,
        output_format=output_format,
        output_file=Path(output) if output else None,
        exclude_patterns=exclude_patterns,
    )

    # ── Run scan ───────────────────────────────────────────────────────────
    scanner = Scanner(config)
    report = scanner.scan()

    # ── Endpoint scanner ───────────────────────────────────────────────────
    endpoints = []
    if endpoint_report or fix:
        from security_scanner.compliance.endpoint_scanner import EndpointScanner

        py_files = []
        for root_str in paths:
            root = Path(root_str)
            if root.is_file() and root.suffix == ".py":
                py_files.append(root)
            elif root.is_dir():
                for p in root.rglob("*.py"):
                    if _not_excluded(p, root, exclude_patterns):
                        py_files.append(p)

        ep_scanner = EndpointScanner()
        endpoints = ep_scanner.scan_files(py_files)
        endpoints = ep_scanner.correlate_findings(endpoints, report.findings)

    # ── Output report ──────────────────────────────────────────────────────
    output_path = Path(output) if output else None

    if output_format == "json":
        JsonReporter(output_file=output_path).report(report)
    elif output_format == "html":
        HtmlReporter(output_file=output_path).report(report)
    else:
        ConsoleReporter(
            show_remediation=not no_remediation
        ).report(report, endpoints=endpoints if endpoint_report else None)

    # ── Interactive fixer ──────────────────────────────────────────────────
    if fix or fix_all:
        from security_scanner.compliance.fixer import InteractiveFixer

        fixer = InteractiveFixer(
            dry_run=dry_run,
            backup=not no_backup,
        )
        if fix_all:
            fixer._apply_all = True

        fix_results = fixer.run(report.findings)

        if fix_results and not dry_run:
            applied = sum(1 for r in fix_results if r.applied)
            if applied > 0:
                click.echo(
                    f"\n✅ {applied} fix(es) applied. "
                    "Re-run the scanner to verify the patched code.\n"
                )

    # ── Manual checklist ───────────────────────────────────────────────────
    if checklist:
        cl_output = Path(checklist_output) if checklist_output else None
        ChecklistReporter().report(report, output_file=cl_output)

    # ── Exit code ──────────────────────────────────────────────────────────
    sys.exit(0 if report.passed else 1)


def _default_excludes() -> List[str]:
    return [
        "**/node_modules/**",
        "**/.git/**",
        "**/dist/**",
        "**/build/**",
        "**/__pycache__/**",
        "**/coverage/**",
        "**/coverage_html/**",
        "**/*.pyc",
        "**/vendor/**",
        "**/security-validator/**",
        "**/*.bak",
    ]


def _not_excluded(file_path: Path, root: Path, patterns: List[str]) -> bool:
    try:
        rel = str(file_path.relative_to(root))
    except ValueError:
        rel = str(file_path)
    for pattern in patterns:
        if fnmatch.fnmatch(rel, pattern) or fnmatch.fnmatch(file_path.name, pattern):
            return False
    return True


if __name__ == "__main__":
    main()
