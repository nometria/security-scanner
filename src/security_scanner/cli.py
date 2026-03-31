#!/usr/bin/env python3
"""
security-scan CLI

Usage:
  security-scan [PATH] [--format console|json|sarif|markdown] [--output FILE]
                [--no-color] [--fail-on critical|high|medium|low] [--watch]

Examples:
  security-scan .
  security-scan ./my-app --format json --output report.json
  security-scan . --format sarif --output results.sarif   # GitHub Code Scanning
  security-scan . --fail-on high    # exit 1 if any high+ findings
  security-scan . --watch           # re-scan on file changes
"""
import argparse
import os
import sys
import time
from pathlib import Path


def _collect_mtimes(root: Path, skip_dirs=None):
    """Walk the project tree and return a dict of {relative_path: mtime}.

    Uses a simple os.stat() approach — no external dependencies needed.
    """
    if skip_dirs is None:
        skip_dirs = {"node_modules", ".git", "dist", "build", ".next", "__pycache__", ".venv", "venv"}
    source_exts = {".js", ".jsx", ".ts", ".tsx", ".py", ".env", ".mjs", ".cjs"}
    mtimes = {}
    for dirpath, dirnames, filenames in os.walk(root):
        # Prune skip dirs in-place so os.walk doesn't descend into them
        dirnames[:] = [d for d in dirnames if d not in skip_dirs]
        for fname in filenames:
            fpath = Path(dirpath) / fname
            if fpath.suffix not in source_exts and not fname.startswith(".env"):
                continue
            try:
                rel = str(fpath.relative_to(root))
                mtimes[rel] = fpath.stat().st_mtime
            except (OSError, ValueError):
                continue
    return mtimes


def _diff_mtimes(old, new):
    """Return lists of (added, modified, removed) file paths between two mtime snapshots."""
    added = [k for k in new if k not in old]
    removed = [k for k in old if k not in new]
    modified = [k for k in new if k in old and new[k] != old[k]]
    return added, modified, removed


def watch_loop(root, fmt_name="console", output_file=None, no_color=False, poll_interval=2.0):
    """Watch for file changes and incrementally re-scan.

    Does a full scan on startup, then polls for mtime changes every
    ``poll_interval`` seconds.  Only changed files are re-scanned; their
    findings replace the previous findings for those files, keeping the
    overall result set current without repeating a full tree walk.

    The terminal is cleared before each update so the developer always sees
    a clean report plus a "Watching for changes..." status line.

    Args:
        root:           Project root Path.
        fmt_name:       Format name ("console", "json", "sarif", "markdown").
        output_file:    Optional path; when set, each scan writes here too.
        no_color:       Disable ANSI colours.
        poll_interval:  Seconds between mtime polls (default: 2.0).
    """
    from security_scanner.scanner import scan_project, scan_files, ScanResult, _sort_findings
    from security_scanner.reporter import (
        format_console, format_json, format_sarif, format_markdown,
        format_watch_output,
    )

    formatters = {
        "console":  format_console,
        "json":     format_json,
        "sarif":    format_sarif,
        "markdown": format_markdown,
    }
    format_fn = formatters[fmt_name]

    def _format_result(result):
        if fmt_name == "console":
            return format_console(result, no_color=no_color)
        return format_fn(result)

    def _write_output(result, changed_files=None):
        output = format_watch_output(result, format_fn, changed_files=changed_files,
                                     no_color=no_color)
        sys.stdout.write(output)
        sys.stdout.flush()
        if output_file:
            Path(output_file).write_text(_format_result(result), encoding="utf-8")

    # ── Initial full scan ────────────────────────────────────────────────
    result = scan_project(root)
    _write_output(result, changed_files=None)

    # Keep a per-file findings cache so we can swap in incremental results
    # Key: relative path, Value: list of Finding
    findings_by_file = {}
    for f in result.findings:
        findings_by_file.setdefault(f.file, []).append(f)

    prev_mtimes = _collect_mtimes(root)
    scanned_total = result.scanned

    try:
        while True:
            time.sleep(poll_interval)
            curr_mtimes = _collect_mtimes(root)
            added, modified, removed = _diff_mtimes(prev_mtimes, curr_mtimes)

            if not (added or modified or removed):
                continue

            changed_files = added + modified

            # Remove findings for deleted/changed files
            for rel in changed_files + removed:
                findings_by_file.pop(rel, None)

            # Re-scan only the changed / new files
            if changed_files:
                incremental = scan_files(root, changed_files)
                for f in incremental.findings:
                    findings_by_file.setdefault(f.file, []).append(f)
                scanned_total += incremental.scanned

            # Rebuild a merged ScanResult
            merged = ScanResult(scanned=scanned_total)
            for file_findings in findings_by_file.values():
                merged.findings.extend(file_findings)
            _sort_findings(merged.findings)

            _write_output(merged, changed_files=changed_files)
            prev_mtimes = curr_mtimes
    except KeyboardInterrupt:
        print("\nWatch stopped.", file=sys.stderr)


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
    parser.add_argument("--watch", action="store_true",
                        help="Watch for file changes and re-run the scan automatically (polls every 2s)")
    args = parser.parse_args()

    root = Path(args.path).resolve()
    if not root.exists():
        print(f"Error: path does not exist: {root}", file=sys.stderr)
        sys.exit(2)

    # Lazy import so startup is fast
    from security_scanner.scanner import scan_project
    from security_scanner.reporter import format_console, format_json, format_sarif, format_markdown

    formatters = {
        "console":  lambda r: format_console(r, no_color=args.no_color),
        "json":     format_json,
        "sarif":    format_sarif,
        "markdown": format_markdown,
    }

    fail_levels = {
        "critical": {"CRITICAL"},
        "high":     {"CRITICAL", "HIGH"},
        "medium":   {"CRITICAL", "HIGH", "MEDIUM"},
        "low":      {"CRITICAL", "HIGH", "MEDIUM", "LOW"},
        "any":      {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"},
    }
    threshold = fail_levels.get(args.fail_on, {"CRITICAL", "HIGH"})

    def run_scan():
        """Run a single scan, format and output results."""
        print(f"Scanning {root} ...", file=sys.stderr)
        result = scan_project(root)
        output = formatters[args.format](result)

        if args.output:
            Path(args.output).write_text(output, encoding="utf-8")
            print(f"Report written to {args.output}", file=sys.stderr)
        else:
            print(output)

        return result

    if args.watch:
        # In watch mode, run continuously — don't exit on findings
        watch_loop(root, fmt_name=args.format, output_file=args.output,
                   no_color=args.no_color)
        sys.exit(0)

    # Single run mode
    result = run_scan()
    if any(f.severity in threshold for f in result.findings):
        sys.exit(1)


if __name__ == "__main__":
    main()
