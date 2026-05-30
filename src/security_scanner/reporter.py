"""
Output formatters for security scan results.
Supports: console (ANSI), JSON, SARIF (GitHub Code Scanning), Markdown.
"""
import json
import time
try:
    from .scanner import ScanResult, CRITICAL, HIGH, MEDIUM, LOW
except ImportError:
    from scanner import ScanResult, CRITICAL, HIGH, MEDIUM, LOW  # type: ignore[no-redef]


SEVERITY_EMOJI = {CRITICAL: "🔴", HIGH: "🟠", MEDIUM: "🟡", LOW: "🔵"}
SEVERITY_ANSI  = {CRITICAL: "\033[91m", HIGH: "\033[93m", MEDIUM: "\033[94m", LOW: "\033[96m"}
RESET = "\033[0m"
CLEAR_SCREEN = "\033[2J\033[H"
DIM = "\033[2m"


def format_console(result: ScanResult, no_color: bool = False) -> str:
    lines = []

    def sev(s):
        if no_color:
            return s
        return f"{SEVERITY_ANSI.get(s, '')}{s}{RESET}"

    lines.append(f"\n{'═'*70}")
    lines.append(f"  SECURITY SCAN - {result.scanned} files scanned, {len(result.findings)} findings")
    lines.append(f"{'═'*70}")

    if not result.findings:
        lines.append("\n  ✅ No security issues found.\n")
        return "\n".join(lines)

    for f in result.findings:
        emoji = SEVERITY_EMOJI.get(f.severity, "⚪")
        lines.append(f"\n  {emoji} [{sev(f.severity)}] {f.rule_id}")
        lines.append(f"     File   : {f.file}:{f.line}")
        lines.append(f"     Issue  : {f.message}")
        if f.snippet:
            lines.append(f"     Code   : {f.snippet}")
        if f.fix:
            lines.append(f"     Fix    : {f.fix}")

    lines.append(f"\n{'─'*70}")
    lines.append(
        f"  Critical: {result.critical_count}  |  "
        f"High: {result.high_count}  |  "
        f"Medium: {sum(1 for x in result.findings if x.severity == MEDIUM)}  |  "
        f"Low: {sum(1 for x in result.findings if x.severity == LOW)}"
    )
    lines.append(f"  Overall: {'❌ FAIL' if not result.passed else '✅ PASS'}")
    lines.append(f"{'─'*70}\n")
    return "\n".join(lines)


def format_json(result: ScanResult) -> str:
    return json.dumps({
        "passed": result.passed,
        "scanned_files": result.scanned,
        "summary": {
            "critical": result.critical_count,
            "high": result.high_count,
            "medium": sum(1 for f in result.findings if f.severity == MEDIUM),
            "low": sum(1 for f in result.findings if f.severity == LOW),
            "total": len(result.findings),
        },
        "findings": [
            {
                "rule_id": f.rule_id, "severity": f.severity,
                "file": f.file, "line": f.line,
                "message": f.message, "snippet": f.snippet, "fix": f.fix,
            }
            for f in result.findings
        ],
    }, indent=2)


def format_sarif(result: ScanResult, tool_version=None) -> str:
    """SARIF 2.1 format - supported by GitHub Code Scanning."""
    if tool_version is None:
        try:
            from . import __version__
            tool_version = __version__
        except ImportError:
            tool_version = "0.0.0"
    rules = {}
    for f in result.findings:
        if f.rule_id not in rules:
            rules[f.rule_id] = {"id": f.rule_id, "name": f.rule_id,
                                 "shortDescription": {"text": f.message},
                                 "defaultConfiguration": {"level": _sarif_level(f.severity)}}
    sarif = {
        "$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0-rtm.5.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "security-scanner", "version": tool_version,
                                "rules": list(rules.values())}},
            "results": [
                {
                    "ruleId": f.rule_id,
                    "level": _sarif_level(f.severity),
                    "message": {"text": f.message},
                    "locations": [{"physicalLocation": {
                        "artifactLocation": {"uri": f.file},
                        "region": {"startLine": f.line}
                    }}],
                }
                for f in result.findings
            ],
        }],
    }
    return json.dumps(sarif, indent=2)


def format_markdown(result: ScanResult) -> str:
    lines = [
        "# Security Scan Report\n",
        f"**Files scanned**: {result.scanned}  ",
        f"**Status**: {'❌ FAIL' if not result.passed else '✅ PASS'}  ",
        f"**Findings**: {len(result.findings)} "
        f"({result.critical_count} critical, {result.high_count} high)\n",
    ]
    if not result.findings:
        lines.append("No security issues found. ✅")
        return "\n".join(lines)

    lines.append("## Findings\n")
    lines.append("| Severity | Rule | File | Line | Issue |")
    lines.append("|----------|------|------|------|-------|")
    for f in result.findings:
        emoji = SEVERITY_EMOJI.get(f.severity, "⚪")
        lines.append(f"| {emoji} {f.severity} | `{f.rule_id}` | `{f.file}` | {f.line} | {f.message} |")

    lines.append("\n## Fix Guidance\n")
    shown = set()
    for f in result.findings:
        if f.fix and f.rule_id not in shown:
            lines.append(f"### {f.rule_id}")
            lines.append(f"{f.fix}\n")
            shown.add(f.rule_id)

    return "\n".join(lines)


def format_watch_output(result: ScanResult, formatter, changed_files=None,
                        no_color: bool = False) -> str:
    """Format scan results for watch mode with clear screen and status line.

    Clears the terminal, prints the formatted scan results, then appends a
    'Watching for changes...' status line so the developer always sees a
    clean, up-to-date view.

    Args:
        result:         ScanResult from the latest scan.
        formatter:      One of the format_* callables (format_console, etc.).
        changed_files:  List of relative paths that changed (None on initial scan).
        no_color:       Disable ANSI colours.
    """
    parts = [CLEAR_SCREEN]

    timestamp = time.strftime("%H:%M:%S")
    if changed_files:
        parts.append(f"[{timestamp}] Re-scanned {len(changed_files)} changed file(s)\n")
    else:
        parts.append(f"[{timestamp}] Full scan\n")

    # Delegate to the chosen formatter
    if formatter is format_console:
        parts.append(format_console(result, no_color=no_color))
    else:
        parts.append(formatter(result))

    dim = "" if no_color else DIM
    reset = "" if no_color else RESET
    parts.append(f"\n{dim}Watching for changes... (Ctrl+C to stop){reset}\n")

    return "".join(parts)


def format_summary(result: ScanResult) -> str:
    """One-line summary suitable for CI status or commit messages."""
    status = "PASS" if result.passed else "FAIL"
    return (
        f"[{status}] {result.scanned} files scanned, "
        f"{len(result.findings)} findings "
        f"({result.critical_count}C/{result.high_count}H/"
        f"{result.medium_count}M)"
    )


def format_table(result: ScanResult) -> str:
    """ASCII table format."""
    if not result.findings:
        return f"No findings ({result.scanned} files scanned).\n"

    # Column widths
    lines = []
    header = f"{'Severity':10s} {'Rule':25s} {'File':30s} {'Line':>5s}  Message"
    lines.append(header)
    lines.append("-" * len(header))
    for f in result.findings:
        fpath = f.file[:28] + ".." if len(f.file) > 30 else f.file
        lines.append(
            f"{f.severity:10s} {f.rule_id:25s} {fpath:30s} {f.line:5d}  {f.message[:60]}"
        )
    lines.append("-" * len(header))
    lines.append(
        f"Total: {len(result.findings)} findings | "
        f"C:{result.critical_count} H:{result.high_count} M:{result.medium_count}"
    )
    return "\n".join(lines)


def format_ai_friendly(result: ScanResult) -> str:
    """Structured text optimised for LLM consumption (Claude Code feedback loop)."""
    lines = []
    status = "PASS" if result.passed else "FAIL"
    lines.append(f"SCAN_STATUS: {status}")
    lines.append(f"FILES_SCANNED: {result.scanned}")
    lines.append(f"TOTAL_FINDINGS: {len(result.findings)}")
    lines.append(f"CRITICAL: {result.critical_count}")
    lines.append(f"HIGH: {result.high_count}")
    lines.append(f"MEDIUM: {result.medium_count}")
    lines.append("")

    # Domain results if present
    if result.domain_results:
        lines.append("DOMAIN_RESULTS:")
        for name, dr in sorted(result.domain_results.items()):
            lines.append(f"  {name}: findings={dr.get('findings', 0)} passed={dr.get('passed', True)} time={dr.get('time', 0):.1f}s")
        lines.append("")

    if result.findings:
        lines.append("FINDINGS:")
        for i, f in enumerate(result.findings, 1):
            lines.append(f"  [{i}] {f.severity} {f.rule_id}")
            lines.append(f"      file: {f.file}:{f.line}")
            lines.append(f"      issue: {f.message}")
            if f.fix:
                lines.append(f"      fix: {f.fix}")
            if f.domain != "security":
                lines.append(f"      domain: {f.domain}")
            lines.append("")

    return "\n".join(lines)


def format_mcp(result: ScanResult) -> str:
    """JSON format optimised for MCP tool responses (concise, structured)."""
    data = {
        "status": "pass" if result.passed else "fail",
        "scanned": result.scanned,
        "summary": {
            "critical": result.critical_count,
            "high": result.high_count,
            "medium": result.medium_count,
            "total": len(result.findings),
        },
    }
    if result.domain_results:
        data["domains"] = result.domain_results
    if result.findings:
        data["findings"] = [
            {
                "rule": f.rule_id,
                "sev": f.severity[0],  # C/H/M/L for compactness
                "file": f.file,
                "line": f.line,
                "msg": f.message,
                **({"fix": f.fix} if f.fix else {}),
                **({"domain": f.domain} if f.domain != "security" else {}),
            }
            for f in result.findings
        ]
    return json.dumps(data, indent=2)


def _sarif_level(severity: str) -> str:
    return {"CRITICAL": "error", "HIGH": "error",
            "MEDIUM": "warning", "LOW": "note"}.get(severity, "note")
