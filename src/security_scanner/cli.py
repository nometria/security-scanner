#!/usr/bin/env python3
"""
security-scan CLI

Usage:
  security-scan [PATH] [--format console|json|sarif|markdown] [--output FILE]
                [--no-color] [--fail-on critical|high|medium|low]

Examples:
  security-scan .
  security-scan ./my-app --format json --output report.json
  security-scan . --format sarif --output results.sarif   # GitHub Code Scanning
  security-scan . --fail-on high    # exit 1 if any high+ findings
"""
import argparse
import sys
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(
        prog="security-scan",
        description="Static security scanner for AI-generated web app code.",
    )
    parser.add_argument("path", nargs="?", default=".", help="Project path to scan (default: .)")
    parser.add_argument("--format", choices=["console", "json", "sarif", "markdown"],
                        default="console", help="Output format")
    parser.add_argument("--output", metavar="FILE", help="Write output to file instead of stdout")
    parser.add_argument("--no-color", action="store_true", help="Disable ANSI color output")
    parser.add_argument("--fail-on", choices=["critical", "high", "medium", "low", "any"],
                        default="high", help="Exit code 1 if findings at this level or above (default: high)")
    args = parser.parse_args()

    root = Path(args.path).resolve()
    if not root.exists():
        print(f"Error: path does not exist: {root}", file=sys.stderr)
        sys.exit(2)

    # Lazy import so startup is fast
    from scanner import scan_project
    from reporter import format_console, format_json, format_sarif, format_markdown

    print(f"Scanning {root} ...", file=sys.stderr)
    result = scan_project(root)

    formatters = {
        "console":  lambda r: format_console(r, no_color=args.no_color),
        "json":     format_json,
        "sarif":    format_sarif,
        "markdown": format_markdown,
    }
    output = formatters[args.format](result)

    if args.output:
        Path(args.output).write_text(output, encoding="utf-8")
        print(f"Report written to {args.output}", file=sys.stderr)
    else:
        print(output)

    # Exit code
    fail_levels = {
        "critical": {"CRITICAL"},
        "high":     {"CRITICAL", "HIGH"},
        "medium":   {"CRITICAL", "HIGH", "MEDIUM"},
        "low":      {"CRITICAL", "HIGH", "MEDIUM", "LOW"},
        "any":      {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"},
    }
    threshold = fail_levels.get(args.fail_on, {"CRITICAL", "HIGH"})
    if any(f.severity in threshold for f in result.findings):
        sys.exit(1)


if __name__ == "__main__":
    main()
