"""
MCP stdio server for Claude Code integration.

Implements the Model Context Protocol over stdin/stdout JSON-RPC,
exposing scan tools that Claude Code can invoke directly.

Start with: security-scan serve
"""

import json
import sys
from pathlib import Path
from typing import Any, Dict


def run_mcp_server():
    """Main MCP server loop — reads JSON-RPC from stdin, writes to stdout."""
    # Send server info
    _write({"jsonrpc": "2.0", "method": "server/info", "params": {
        "name": "security-scan",
        "version": "0.3.0",
        "capabilities": {"tools": {}},
    }})

    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            request = json.loads(line)
        except json.JSONDecodeError:
            _log(f"Invalid JSON: {line[:100]}")
            continue

        method = request.get("method", "")
        req_id = request.get("id")
        params = request.get("params", {})

        if method == "initialize":
            _write({"jsonrpc": "2.0", "id": req_id, "result": {
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "security-scan", "version": "0.3.0"},
            }})

        elif method == "notifications/initialized":
            pass  # notification, no response needed

        elif method == "tools/list":
            _write({"jsonrpc": "2.0", "id": req_id, "result": {"tools": _get_tool_list()}})

        elif method == "tools/call":
            tool_name = params.get("name", "")
            args = params.get("arguments", {})
            result = _dispatch_tool(tool_name, args)
            if "error" in result:
                _write({"jsonrpc": "2.0", "id": req_id, "result": {
                    "content": [{"type": "text", "text": f"Error: {result['error']}"}],
                    "isError": True,
                }})
            else:
                _write({"jsonrpc": "2.0", "id": req_id, "result": {
                    "content": [{"type": "text", "text": json.dumps(result, indent=2)}],
                }})

        elif req_id is not None:
            _write({"jsonrpc": "2.0", "id": req_id, "error": {
                "code": -32601, "message": f"Unknown method: {method}",
            }})
        # else: notification without id — no response needed


def _write(obj: dict):
    sys.stdout.write(json.dumps(obj) + "\n")
    sys.stdout.flush()


def _log(msg: str):
    """Log to stderr (MCP servers use stdout for protocol, stderr for logs)."""
    sys.stderr.write(f"[security-scan] {msg}\n")
    sys.stderr.flush()


def _get_tool_list():
    return [
        {
            "name": "scan",
            "description": "Run a security and quality scan on the project. Returns findings grouped by severity with fix suggestions.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "Project path (default: current dir)", "default": "."},
                    "mode": {"type": "string", "enum": ["full", "incremental", "pr"], "default": "full"},
                    "domains": {"type": "string", "description": "Comma-separated domains (default: all available)", "default": ""},
                    "fix": {"type": "boolean", "description": "Auto-fix lint/formatting issues", "default": False},
                },
            },
        },
        {
            "name": "scan_file",
            "description": "Scan a single file for security issues.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "Project root path"},
                    "file": {"type": "string", "description": "Relative file path to scan"},
                },
                "required": ["path", "file"],
            },
        },
        {
            "name": "explain",
            "description": "Get detailed explanation and code context for a finding.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "Project root path"},
                    "rule_id": {"type": "string"},
                    "file": {"type": "string"},
                    "line": {"type": "integer"},
                },
                "required": ["path", "rule_id", "file", "line"],
            },
        },
        {
            "name": "status",
            "description": "Get project scan status: available domains, tools, and project info.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "path": {"type": "string", "default": "."},
                },
            },
        },
    ]


def _dispatch_tool(name: str, args: Dict[str, Any]) -> Dict[str, Any]:
    try:
        if name == "scan":
            return _tool_scan(args)
        elif name == "scan_file":
            return _tool_scan_file(args)
        elif name == "explain":
            return _tool_explain(args)
        elif name == "status":
            return _tool_status(args)
        else:
            return {"error": f"Unknown tool: {name}"}
    except Exception as e:
        return {"error": str(e)}


def _tool_scan(args: dict) -> dict:
    from security_scanner.scanner import scan_project_v2
    from security_scanner.config import load_config

    root = Path(args.get("path", ".")).resolve()
    config = load_config(root)
    if args.get("mode"):
        config.scan_mode = args["mode"]
    if args.get("domains"):
        config.domains = [d.strip() for d in args["domains"].split(",") if d.strip()]
    if args.get("fix"):
        config.fix = True

    result = scan_project_v2(root, config)

    return {
        "status": "pass" if result.passed else "fail",
        "scanned": result.scanned,
        "summary": {
            "critical": result.critical_count,
            "high": result.high_count,
            "medium": result.medium_count,
            "total": len(result.findings),
        },
        "domains": result.domain_results,
        "findings": [
            {
                "rule": f.rule_id,
                "severity": f.severity,
                "file": f.file,
                "line": f.line,
                "message": f.message,
                **({"fix": f.fix} if f.fix else {}),
            }
            for f in result.findings
        ],
    }


def _tool_scan_file(args: dict) -> dict:
    from security_scanner.scanner import scan_files

    root = Path(args["path"]).resolve()
    result = scan_files(root, [args["file"]])
    return {
        "file": args["file"],
        "passed": result.passed,
        "findings": [
            {"rule": f.rule_id, "severity": f.severity, "line": f.line,
             "message": f.message, **({"fix": f.fix} if f.fix else {})}
            for f in result.findings
        ],
    }


def _tool_explain(args: dict) -> dict:
    root = Path(args["path"]).resolve()
    fpath = root / args["file"]

    context = ""
    if fpath.is_file():
        try:
            lines = fpath.read_text(errors="replace").splitlines()
            line = args["line"]
            start = max(0, line - 5)
            end = min(len(lines), line + 5)
            context = "\n".join(f"{i+1:4d} | {lines[i]}" for i in range(start, end))
        except Exception:
            pass

    return {
        "rule_id": args["rule_id"],
        "file": args["file"],
        "line": args["line"],
        "context": context,
    }


def _tool_status(args: dict) -> dict:
    from security_scanner.domains import get_all_domains
    from security_scanner.config import load_config

    root = Path(args.get("path", ".")).resolve()
    config = load_config(root)
    domains = get_all_domains()

    return {
        "project": str(root),
        "config_found": (root / "ai-security-scan.yml").exists() or (root / ".ai-security-scan.yml").exists(),
        "domains": {
            name: {"available": d.is_available(), "description": d.description}
            for name, d in sorted(domains.items())
        },
        "config": {
            "scan_mode": config.scan_mode,
            "fail_on": config.fail_on,
            "domains": config.domains or "all",
        },
    }
