"""
Linting domain — wraps language-specific linters.

Supported tools:
  - Ruff        (Python)
  - ESLint      (JavaScript / TypeScript)
  - Biome       (JavaScript / TypeScript / JSON / CSS)
  - Clippy      (Rust)
  - GoLangCI-Lint (Go)
"""

import json
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from security_scanner.scanner import Finding, HIGH, MEDIUM, LOW

from .base import Domain, DomainResult
from .tool_runner import ToolRunner

# Map file extensions to the linters that handle them
_LANG_LINTERS = {
    ".py": ["ruff"],
    ".js": ["eslint", "biome"],
    ".jsx": ["eslint", "biome"],
    ".ts": ["eslint", "biome"],
    ".tsx": ["eslint", "biome"],
    ".mjs": ["eslint", "biome"],
    ".cjs": ["eslint", "biome"],
    ".rs": ["clippy"],
    ".go": ["golangci-lint"],
}


def _detect_languages(project_root: Path) -> set:
    """Return the set of linter names relevant to this project."""
    linters = set()
    for fpath in project_root.rglob("*"):
        if fpath.is_file() and fpath.suffix in _LANG_LINTERS:
            linters.update(_LANG_LINTERS[fpath.suffix])
        if len(linters) >= 5:
            break
    return linters


class LintDomain(Domain):
    name = "lint"
    description = "Code linting across multiple languages using Ruff, ESLint, Biome, Clippy, GoLangCI-Lint."

    def __init__(self):
        self._runner = ToolRunner()

    def is_available(self) -> bool:
        for tool in ("ruff", "eslint", "biome", "cargo", "golangci-lint"):
            if self._runner.find_tool(tool):
                return True
        return False

    def run(self, project_root: Path, paths: Optional[List[Path]] = None,
            config: Optional[Dict[str, Any]] = None) -> DomainResult:
        t0 = time.monotonic()
        findings: List[Finding] = []
        errors: List[str] = []
        tools_used = []

        relevant = _detect_languages(project_root)

        if "ruff" in relevant:
            f, e = self._run_ruff(project_root, paths, config)
            findings.extend(f)
            errors.extend(e)
            if f or not e:
                tools_used.append("ruff")

        if relevant & {"eslint", "biome"}:
            if self._runner.find_tool("eslint"):
                f, e = self._run_eslint(project_root, paths, config)
                findings.extend(f)
                errors.extend(e)
                tools_used.append("eslint")
            elif self._runner.find_tool("biome"):
                f, e = self._run_biome(project_root, paths, config)
                findings.extend(f)
                errors.extend(e)
                tools_used.append("biome")

        if "clippy" in relevant and self._runner.find_tool("cargo"):
            f, e = self._run_clippy(project_root)
            findings.extend(f)
            errors.extend(e)
            tools_used.append("clippy")

        if "golangci-lint" in relevant and self._runner.find_tool("golangci-lint"):
            f, e = self._run_golangci(project_root)
            findings.extend(f)
            errors.extend(e)
            tools_used.append("golangci-lint")

        return DomainResult(
            domain="lint",
            findings=findings,
            tool_name=", ".join(tools_used) or "none",
            tool_version="",
            execution_time=time.monotonic() - t0,
            errors=errors,
        )

    # ── Ruff ──────────────────────────────────────────────────────────────

    def _run_ruff(self, root: Path, paths: Optional[List[Path]], config: Optional[dict]) -> tuple:
        tool = self._runner.find_tool("ruff")
        if not tool:
            return [], []

        cmd = [str(tool), "check", "--output-format", "json"]
        if config and "select" in config.get("ruff", {}):
            cmd += ["--select", ",".join(config["ruff"]["select"])]
        if paths:
            cmd += [str(p) for p in paths if p.suffix == ".py"]
            if len(cmd) <= 4:
                return [], []
        else:
            cmd.append(str(root))

        parsed, output = self._runner.run_json(cmd, cwd=root)
        findings = []
        if parsed and isinstance(parsed, list):
            for item in parsed:
                sev = MEDIUM if item.get("code", "").startswith("E") else LOW
                findings.append(Finding(
                    rule_id=f"LINT-RUFF-{item.get('code', 'UNKNOWN')}",
                    severity=sev,
                    file=item.get("filename", ""),
                    line=item.get("location", {}).get("row", 0),
                    message=item.get("message", ""),
                    snippet=item.get("code", ""),
                    fix=item.get("fix", {}).get("message", "") if item.get("fix") else "",
                    domain="lint",
                    tool="ruff",
                    category="style",
                ))
        return findings, []

    # ── ESLint ────────────────────────────────────────────────────────────

    def _run_eslint(self, root: Path, paths: Optional[List[Path]], config: Optional[dict]) -> tuple:
        tool = self._runner.find_tool("eslint")
        if not tool:
            return [], []

        js_exts = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}
        cmd = [str(tool), "--format", "json"]
        if paths:
            targets = [str(p) for p in paths if p.suffix in js_exts]
            if not targets:
                return [], []
            cmd += targets
        else:
            cmd.append(str(root))

        parsed, output = self._runner.run_json(cmd, cwd=root)
        findings = []
        if parsed and isinstance(parsed, list):
            for file_result in parsed:
                fpath = file_result.get("filePath", "")
                try:
                    fpath = str(Path(fpath).relative_to(root))
                except ValueError:
                    pass
                for msg in file_result.get("messages", []):
                    sev = HIGH if msg.get("severity") == 2 else MEDIUM
                    findings.append(Finding(
                        rule_id=f"LINT-ESLINT-{msg.get('ruleId', 'unknown')}",
                        severity=sev,
                        file=fpath,
                        line=msg.get("line", 0),
                        message=msg.get("message", ""),
                        snippet=msg.get("source", "")[:80] if msg.get("source") else "",
                        fix=msg.get("fix", {}).get("text", "") if msg.get("fix") else "",
                        domain="lint",
                        tool="eslint",
                        category="style",
                    ))
        return findings, []

    # ── Biome ─────────────────────────────────────────────────────────────

    def _run_biome(self, root: Path, paths: Optional[List[Path]], config: Optional[dict]) -> tuple:
        tool = self._runner.find_tool("biome")
        if not tool:
            return [], []

        cmd = [str(tool), "lint", "--reporter", "json"]
        if paths:
            cmd += [str(p) for p in paths]
        else:
            cmd.append(str(root))

        parsed, output = self._runner.run_json(cmd, cwd=root)
        findings = []
        if parsed and isinstance(parsed, dict):
            for diag in parsed.get("diagnostics", []):
                findings.append(Finding(
                    rule_id=f"LINT-BIOME-{diag.get('category', 'unknown')}",
                    severity=MEDIUM,
                    file=diag.get("file", {}).get("path", ""),
                    line=diag.get("location", {}).get("span", [0])[0] if diag.get("location") else 0,
                    message=diag.get("description", ""),
                    domain="lint",
                    tool="biome",
                    category="style",
                ))
        return findings, []

    # ── Clippy ────────────────────────────────────────────────────────────

    def _run_clippy(self, root: Path) -> tuple:
        tool = self._runner.find_tool("cargo")
        if not tool:
            return [], []

        cmd = [str(tool), "clippy", "--message-format=json", "--", "-W", "clippy::all"]
        output = self._runner.run_tool(cmd, cwd=root, timeout=600)
        findings = []
        if output.stdout:
            for raw_line in output.stdout.splitlines():
                try:
                    msg = json.loads(raw_line)
                except json.JSONDecodeError:
                    continue
                if msg.get("reason") != "compiler-message":
                    continue
                cm = msg.get("message", {})
                level = cm.get("level", "")
                if level not in ("warning", "error"):
                    continue
                spans = cm.get("spans", [{}])
                span = spans[0] if spans else {}
                findings.append(Finding(
                    rule_id=f"LINT-CLIPPY-{cm.get('code', {}).get('code', 'unknown')}",
                    severity=HIGH if level == "error" else MEDIUM,
                    file=span.get("file_name", ""),
                    line=span.get("line_start", 0),
                    message=cm.get("message", ""),
                    snippet=span.get("text", [{}])[0].get("text", "")[:80] if span.get("text") else "",
                    domain="lint",
                    tool="clippy",
                    category="style",
                ))
        return findings, []

    # ── GoLangCI-Lint ─────────────────────────────────────────────────────

    def _run_golangci(self, root: Path) -> tuple:
        tool = self._runner.find_tool("golangci-lint")
        if not tool:
            return [], []

        cmd = [str(tool), "run", "--out-format", "json"]
        parsed, output = self._runner.run_json(cmd, cwd=root, timeout=600)
        findings = []
        if parsed and isinstance(parsed, dict):
            for issue in parsed.get("Issues", []):
                findings.append(Finding(
                    rule_id=f"LINT-GO-{issue.get('FromLinter', 'unknown')}",
                    severity=MEDIUM,
                    file=issue.get("Pos", {}).get("Filename", ""),
                    line=issue.get("Pos", {}).get("Line", 0),
                    message=issue.get("Text", ""),
                    snippet=issue.get("SourceLines", [""])[0][:80] if issue.get("SourceLines") else "",
                    domain="lint",
                    tool="golangci-lint",
                    category="style",
                ))
        return findings, []
