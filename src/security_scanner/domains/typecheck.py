"""
Type checking domain — wraps static type checkers.

Supported tools:
  - MyPy     (Python)
  - Pyright  (Python)
  - tsc      (TypeScript)
"""

import re
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from security_scanner.scanner import Finding, HIGH, MEDIUM

from .base import Domain, DomainResult
from .tool_runner import ToolRunner


class TypeCheckDomain(Domain):
    name = "typecheck"
    description = "Static type checking via MyPy, Pyright, and TypeScript compiler."

    def __init__(self):
        self._runner = ToolRunner()

    def is_available(self) -> bool:
        for tool in ("mypy", "pyright", "tsc"):
            if self._runner.find_tool(tool):
                return True
        return False

    def run(self, project_root: Path, paths: Optional[List[Path]] = None,
            config: Optional[Dict[str, Any]] = None) -> DomainResult:
        t0 = time.monotonic()
        findings: List[Finding] = []
        errors: List[str] = []
        tools_used = []

        has_py = any(project_root.rglob("*.py"))
        has_ts = any(project_root.rglob("*.ts")) or any(project_root.rglob("*.tsx"))

        if has_py:
            if self._runner.find_tool("mypy"):
                f, e = self._run_mypy(project_root, paths)
                findings.extend(f)
                errors.extend(e)
                tools_used.append("mypy")
            elif self._runner.find_tool("pyright"):
                f, e = self._run_pyright(project_root, paths)
                findings.extend(f)
                errors.extend(e)
                tools_used.append("pyright")

        if has_ts and self._runner.find_tool("tsc"):
            f, e = self._run_tsc(project_root)
            findings.extend(f)
            errors.extend(e)
            tools_used.append("tsc")

        return DomainResult(
            domain="typecheck",
            findings=findings,
            tool_name=", ".join(tools_used) or "none",
            execution_time=time.monotonic() - t0,
            errors=errors,
        )

    def _run_mypy(self, root: Path, paths: Optional[List[Path]]) -> tuple:
        tool = self._runner.find_tool("mypy")
        if not tool:
            return [], []

        cmd = [str(tool), "--no-error-summary", "--show-column-numbers"]
        if paths:
            py_files = [str(p) for p in paths if p.suffix == ".py"]
            if not py_files:
                return [], []
            cmd += py_files
        else:
            cmd.append(str(root))

        output = self._runner.run_tool(cmd, cwd=root, timeout=300)
        findings = []
        # Parse mypy line output: file:line:col: severity: message
        pattern = re.compile(r'^(.+?):(\d+):\d+: (error|warning|note): (.+)')
        for raw_line in output.stdout.splitlines():
            m = pattern.match(raw_line)
            if m:
                level = m.group(3)
                sev = HIGH if level == "error" else MEDIUM
                findings.append(Finding(
                    rule_id=f"TYPE-MYPY-{level}",
                    severity=sev,
                    file=m.group(1),
                    line=int(m.group(2)),
                    message=m.group(4),
                    domain="typecheck",
                    tool="mypy",
                    category="type-error",
                ))
        return findings, []

    def _run_pyright(self, root: Path, paths: Optional[List[Path]]) -> tuple:
        tool = self._runner.find_tool("pyright")
        if not tool:
            return [], []

        cmd = [str(tool), "--outputjson"]
        if paths:
            py_files = [str(p) for p in paths if p.suffix == ".py"]
            if not py_files:
                return [], []
            cmd += py_files

        parsed, output = self._runner.run_json(cmd, cwd=root)
        findings = []
        if parsed and isinstance(parsed, dict):
            for diag in parsed.get("generalDiagnostics", []):
                sev = HIGH if diag.get("severity") == "error" else MEDIUM
                findings.append(Finding(
                    rule_id=f"TYPE-PYRIGHT-{diag.get('rule', 'unknown')}",
                    severity=sev,
                    file=diag.get("file", ""),
                    line=diag.get("range", {}).get("start", {}).get("line", 0),
                    message=diag.get("message", ""),
                    domain="typecheck",
                    tool="pyright",
                    category="type-error",
                ))
        return findings, []

    def _run_tsc(self, root: Path) -> tuple:
        tool = self._runner.find_tool("tsc")
        if not tool:
            return [], []

        cmd = [str(tool), "--noEmit", "--pretty", "false"]
        output = self._runner.run_tool(cmd, cwd=root, timeout=300)
        findings = []
        # Parse tsc output: file(line,col): error TSxxxx: message
        pattern = re.compile(r'^(.+?)\((\d+),\d+\): (error|warning) (TS\d+): (.+)')
        for raw_line in output.stdout.splitlines():
            m = pattern.match(raw_line)
            if m:
                level = m.group(3)
                sev = HIGH if level == "error" else MEDIUM
                findings.append(Finding(
                    rule_id=f"TYPE-TSC-{m.group(4)}",
                    severity=sev,
                    file=m.group(1),
                    line=int(m.group(2)),
                    message=m.group(5),
                    domain="typecheck",
                    tool="tsc",
                    category="type-error",
                ))
        return findings, []
