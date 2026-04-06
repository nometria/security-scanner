#!/usr/bin/env python3
"""
security-scan CLI

Usage:
  security-scan [PATH] [OPTIONS]            Scan a project
  security-scan init                        Set up config + MCP integration
  security-scan doctor                      Validate environment
  security-scan serve                       Start MCP stdio server
  security-scan tools list|install|clean    Manage tool binaries

Examples:
  security-scan .
  security-scan ./my-app --format json --output report.json
  security-scan . --format sarif --output results.sarif
  security-scan . --mode pr --base-ref origin/main
  security-scan . --domains security,lint --fix
  security-scan init
"""
import argparse
import json
import os
import sys
import time
from pathlib import Path


# ── Init command ─────────────────────────────────────────────────────────────

def _init_command():
    """Generate config, .mcp.json, and .claude/CLAUDE.md for a project."""
    root = Path(".").resolve()

    # Detect project
    from security_scanner.detection import ProjectContext
    ctx = ProjectContext(root)
    summary = ctx.summary()

    print(f"Detected: {', '.join(summary['languages']) or 'no languages'}")
    if summary['frameworks']:
        print(f"Frameworks: {', '.join(summary['frameworks'])}")

    # Generate ai-security-scan.yml
    domains = ctx.recommended_domains()
    config_content = (
        "# ai-security-scan configuration\n"
        f"# Auto-generated for: {ctx.primary_language} project\n"
        "\n"
        f"domains: [{', '.join(domains)}]\n"
        "fail_on: high\n"
        "scan_mode: full\n"
    )
    cfg_path = root / "ai-security-scan.yml"
    if not cfg_path.exists():
        cfg_path.write_text(config_content)
        print(f"Created: {cfg_path.name}")
    else:
        print(f"Exists:  {cfg_path.name} (skipped)")

    # Generate .mcp.json for Claude Code
    mcp_path = root / ".mcp.json"
    if not mcp_path.exists():
        mcp_config = {
            "mcpServers": {
                "security-scan": {
                    "command": "security-scan",
                    "args": ["serve"],
                }
            }
        }
        mcp_path.write_text(json.dumps(mcp_config, indent=2) + "\n")
        print(f"Created: {mcp_path.name}")
    else:
        print(f"Exists:  {mcp_path.name} (skipped)")

    # Generate .claude/CLAUDE.md
    claude_dir = root / ".claude"
    claude_md = claude_dir / "CLAUDE.md"
    if not claude_md.exists():
        claude_dir.mkdir(exist_ok=True)
        claude_md.write_text(
            "# Security Scanner Integration\n\n"
            "This project uses `security-scan` for code quality checks.\n\n"
            "## After editing code\n"
            "Run `security-scan .` to check for security issues, "
            "linting errors, and dependency vulnerabilities.\n\n"
            "## Available commands\n"
            "- `security-scan .` — full scan\n"
            "- `security-scan . --fix` — scan and auto-fix lint issues\n"
            "- `security-scan . --mode pr --base-ref origin/main` — scan PR changes only\n"
            "- `security-scan . --format json` — JSON output for CI\n"
        )
        print("Created: .claude/CLAUDE.md")
    else:
        print("Exists:  .claude/CLAUDE.md (skipped)")

    print("\nReady! Run: security-scan .")


# ── Doctor command ───────────────────────────────────────────────────────────

def _doctor_command():
    """Validate environment setup."""
    root = Path(".").resolve()

    # Config file
    from security_scanner.config import CONFIG_FILENAMES
    config_found = any((root / name).exists() for name in CONFIG_FILENAMES)
    _doctor_check("Config file", config_found, "Run: security-scan init")

    # Git repo
    from security_scanner.git_utils import is_git_repo
    _doctor_check("Git repository", is_git_repo(root), "Not in a git repo (PR mode won't work)")

    # MCP integration
    mcp_found = (root / ".mcp.json").exists()
    _doctor_check("MCP integration", mcp_found, "Run: security-scan init")

    # Domain tools
    from security_scanner.domains import get_all_domains
    domains = get_all_domains()
    for name, domain in sorted(domains.items()):
        _doctor_check(f"Domain: {name}", domain.is_available(),
                      f"{name} tool not installed (domain will be skipped)")

    print()
    if all(d.is_available() for d in domains.values()):
        print("All checks passed!")
    else:
        print("Some tools are not installed. Domains without tools will be skipped.")
        print("Install missing tools via your package manager (brew, pip, npm, etc.)")


def _doctor_check(label: str, ok: bool, hint: str):
    icon = "  [OK]" if ok else "  [--]"
    msg = f"{icon} {label}"
    if not ok:
        msg += f"  ({hint})"
    print(msg)


# ── Serve command (MCP stdio server) ────────────────────────────────────────

def _serve_command():
    """Start MCP stdio server for Claude Code integration."""
    from security_scanner.mcp_server import run_mcp_server
    run_mcp_server()


# ── Tools subcommand ─────────────────────────────────────────────────────────

def _tools_cli():
    """Standalone CLI parser for 'security-scan tools ...'."""
    parser = argparse.ArgumentParser(
        prog="security-scan tools",
        description="Manage external tool binaries.",
    )
    parser.add_argument("tools_action", choices=["list", "install", "clean"],
                        help="Action to perform")
    parser.add_argument("tool_name", nargs="?", default="--all",
                        help="Tool name to install (or --all)")
    args = parser.parse_args(sys.argv[2:])

    from security_scanner.provisioning import ToolProvisioner, MANAGED_TOOLS

    provisioner = ToolProvisioner()

    if args.tools_action == "list":
        installed = provisioner.list_provisioned()
        print(f"{'Tool':15s} {'Version':12s} {'Status':10s} Path")
        print("-" * 70)
        for name, manifest in sorted(MANAGED_TOOLS.items()):
            found = next((p for n, v, p in installed if n == name), None)
            status = "installed" if found else "not installed"
            print(f"{name:15s} {manifest.version:12s} {status:10s} {str(found) if found else ''}")

    elif args.tools_action == "install":
        tool_name = args.tool_name
        if tool_name == "--all":
            for name in MANAGED_TOOLS:
                print(f"Installing {name}...", end=" ", flush=True)
                path = provisioner.ensure_tool(name)
                print(f"OK: {path}" if path else "SKIP (no binary for this platform)")
        elif tool_name in MANAGED_TOOLS:
            print(f"Installing {tool_name}...", end=" ", flush=True)
            path = provisioner.ensure_tool(tool_name)
            print(f"OK: {path}" if path else "FAILED (no binary for this platform)")
        else:
            print(f"Unknown tool: {tool_name}. Available: {', '.join(MANAGED_TOOLS.keys())}")
            sys.exit(2)

    elif args.tools_action == "clean":
        count = provisioner.clean()
        print(f"Removed {count} managed tool(s).")


# ── Watch loop ───────────────────────────────────────────────────────────────

def _collect_mtimes(root: Path, skip_dirs=None):
    if skip_dirs is None:
        skip_dirs = {"node_modules", ".git", "dist", "build", ".next", "__pycache__", ".venv", "venv"}
    source_exts = {".js", ".jsx", ".ts", ".tsx", ".py", ".env", ".mjs", ".cjs"}
    mtimes = {}
    for dirpath, dirnames, filenames in os.walk(root):
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
    added = [k for k in new if k not in old]
    removed = [k for k in old if k not in new]
    modified = [k for k in new if k in old and new[k] != old[k]]
    return added, modified, removed


def watch_loop(root, fmt_name="console", output_file=None, no_color=False, poll_interval=2.0):
    """Watch for file changes and incrementally re-scan."""
    from security_scanner.scanner import scan_project_v2, scan_files, ScanResult, _sort_findings
    from security_scanner.config import load_config
    from security_scanner.reporter import format_console, format_json, format_sarif, format_markdown, format_watch_output

    config = load_config(root)
    formatters = {"console": format_console, "json": format_json, "sarif": format_sarif, "markdown": format_markdown}
    format_fn = formatters.get(fmt_name, format_console)

    def _write_output(result, changed_files=None):
        output = format_watch_output(result, format_fn, changed_files=changed_files, no_color=no_color)
        sys.stdout.write(output)
        sys.stdout.flush()
        if output_file:
            Path(output_file).write_text(format_fn(result) if fmt_name != "console" else format_console(result, no_color=no_color), encoding="utf-8")

    try:
        result = scan_project_v2(root, config)
    except Exception as e:
        print(f"Initial scan failed: {e}", file=sys.stderr)
        from security_scanner.scanner import scan_project
        result = scan_project(root)  # fallback to builtin-only
    _write_output(result, changed_files=None)

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
            for rel in changed_files + removed:
                findings_by_file.pop(rel, None)
            if changed_files:
                incremental = scan_files(root, changed_files)
                for f in incremental.findings:
                    findings_by_file.setdefault(f.file, []).append(f)
                scanned_total += incremental.scanned
            merged = ScanResult(scanned=scanned_total)
            for file_findings in findings_by_file.values():
                merged.findings.extend(file_findings)
            _sort_findings(merged.findings)
            _write_output(merged, changed_files=changed_files)
            prev_mtimes = curr_mtimes
    except KeyboardInterrupt:
        print("\nWatch stopped.", file=sys.stderr)


# ── Main ─────────────────────────────────────────────────────────────────────

def main():
    # Intercept subcommands before argparse
    if len(sys.argv) >= 2:
        cmd = sys.argv[1]
        if cmd == "init":
            _init_command()
            return
        if cmd == "doctor":
            _doctor_command()
            return
        if cmd == "serve":
            _serve_command()
            return
        if cmd == "tools":
            _tools_cli()
            return

    parser = argparse.ArgumentParser(
        prog="security-scan",
        description="Code quality gate for AI-generated apps.",
        epilog="Commands: init, doctor, serve, tools",
    )
    parser.add_argument("path", nargs="?", default=".", help="Project path to scan (default: .)")
    parser.add_argument("--format", choices=["console", "json", "sarif", "markdown"],
                        default="console", help="Output format")
    parser.add_argument("--output", metavar="FILE", help="Write output to file")
    parser.add_argument("--no-color", action="store_true", help="Disable ANSI color output")
    parser.add_argument("--fail-on", choices=["critical", "high", "medium", "low", "any"],
                        default="high", help="Exit 1 if findings at this level or above (default: high)")
    parser.add_argument("--watch", action="store_true", help="Watch for file changes and re-scan")
    parser.add_argument("--mode", choices=["full", "incremental", "pr"],
                        default="full", help="Scan mode (default: full)")
    parser.add_argument("--base-ref", default="", help="Base branch for PR mode")
    parser.add_argument("--config", metavar="FILE", help="Config file path")
    parser.add_argument("--dashboard", action="store_true", help="Generate QUALITY.md")
    parser.add_argument("--domains", default="", help="Comma-separated domains to run")
    parser.add_argument("--fix", action="store_true", help="Auto-fix lint and formatting issues")
    parser.add_argument("--strict", action="store_true", help="Missing tools are findings")
    args = parser.parse_args()

    root = Path(args.path).resolve()
    if not root.exists():
        print(f"Error: path does not exist: {root}", file=sys.stderr)
        sys.exit(2)

    if args.watch:
        watch_loop(root, fmt_name=args.format, output_file=args.output, no_color=args.no_color)
        sys.exit(0)

    # Lazy imports
    from security_scanner.scanner import scan_project_v2
    from security_scanner.config import ScanConfig, load_config
    from security_scanner.reporter import format_console, format_json, format_sarif, format_markdown

    formatters = {
        "console": lambda r: format_console(r, no_color=args.no_color),
        "json": format_json,
        "sarif": format_sarif,
        "markdown": format_markdown,
    }

    fail_levels = {
        "critical": {"CRITICAL"},
        "high": {"CRITICAL", "HIGH"},
        "medium": {"CRITICAL", "HIGH", "MEDIUM"},
        "low": {"CRITICAL", "HIGH", "MEDIUM", "LOW"},
        "any": {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"},
    }
    threshold = fail_levels.get(args.fail_on, {"CRITICAL", "HIGH"})

    # Load config
    if args.config:
        from security_scanner.config import _parse_yaml, _dict_to_config
        raw = _parse_yaml(Path(args.config))
        config = _dict_to_config(raw) if raw else ScanConfig()
    else:
        config = load_config(root)

    # CLI overrides
    config.scan_mode = args.mode
    if args.base_ref:
        config.base_ref = args.base_ref
    if args.domains:
        config.domains = [d.strip() for d in args.domains.split(",") if d.strip()]
    if args.strict:
        config.strict = True
    if args.dashboard:
        config.dashboard = True
    if args.fix:
        config.fix = True

    print(f"Scanning {root} ...", file=sys.stderr)
    result = scan_project_v2(root, config)

    # Auto-fix if requested
    if config.fix:
        _run_fix(root, result)

    # Dashboard
    if config.dashboard:
        from security_scanner.dashboard import write_dashboard
        dash_path = write_dashboard(root, result)
        print(f"Dashboard written to {dash_path}", file=sys.stderr)

    output = formatters[args.format](result)
    if args.output:
        Path(args.output).write_text(output, encoding="utf-8")
        print(f"Report written to {args.output}", file=sys.stderr)
    else:
        print(output)

    if any(f.severity in threshold for f in result.findings):
        sys.exit(1)


def _run_fix(root: Path, result):
    """Run auto-fix for fixable issues (lint, formatting)."""
    import shutil
    import subprocess

    tools_run = []

    # Ruff lint fix — only if ruff findings exist
    if shutil.which("ruff") and any(f.rule_id.startswith("LINT-RUFF") for f in result.findings):
        print("  Fixing: ruff check ...", file=sys.stderr, end=" ")
        try:
            proc = subprocess.run(["ruff", "check", "--fix", str(root)],
                                  capture_output=True, text=True, timeout=120)
            print("done" if proc.returncode == 0 else "partial", file=sys.stderr)
            tools_run.append("ruff")
        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            print(f"failed: {e}", file=sys.stderr)

    # ESLint fix — only if eslint findings exist
    if shutil.which("eslint") and any(f.rule_id.startswith("LINT-ESLINT") for f in result.findings):
        print("  Fixing: eslint ...", file=sys.stderr, end=" ")
        try:
            proc = subprocess.run(["eslint", "--fix", str(root)],
                                  capture_output=True, text=True, timeout=120)
            print("done" if proc.returncode == 0 else "partial", file=sys.stderr)
            tools_run.append("eslint")
        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            print(f"failed: {e}", file=sys.stderr)

    if tools_run:
        print(f"  Auto-fixed with: {', '.join(tools_run)}", file=sys.stderr)


if __name__ == "__main__":
    main()
