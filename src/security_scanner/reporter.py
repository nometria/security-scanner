"""
Output formatters for security scan results.
Supports: console (ANSI), JSON, SARIF (GitHub Code Scanning), Markdown.
"""
import json
try:
    from .scanner import ScanResult, CRITICAL, HIGH, MEDIUM, LOW
except ImportError:
    from scanner import ScanResult, CRITICAL, HIGH, MEDIUM, LOW  # type: ignore[no-redef]


SEVERITY_EMOJI = {CRITICAL: "🔴", HIGH: "🟠", MEDIUM: "🟡", LOW: "🔵"}
SEVERITY_ANSI  = {CRITICAL: "\033[91m", HIGH: "\033[93m", MEDIUM: "\033[94m", LOW: "\033[96m"}
RESET = "\033[0m"


def format_console(result: ScanResult, no_color: bool = False) -> str:
    lines = []

    def sev(s):
        if no_color:
            return s
        return f"{SEVERITY_ANSI.get(s, '')}{s}{RESET}"

    lines.append(f"\n{'═'*70}")
    lines.append(f"  SECURITY SCAN — {result.scanned} files scanned, {len(result.findings)} findings")
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


def format_sarif(result: ScanResult, tool_version: str = "0.1.0") -> str:
    """SARIF 2.1 format — supported by GitHub Code Scanning."""
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


def _sarif_level(severity: str) -> str:
    return {"CRITICAL": "error", "HIGH": "error",
            "MEDIUM": "warning", "LOW": "note"}.get(severity, "note")
