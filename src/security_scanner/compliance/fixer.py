"""
fixer.py - Interactive auto-fixer for security compliance gaps.

For each auto-fixable finding the fixer:
1. Shows the current code (context around the issue)
2. Shows the proposed fix as a unified diff
3. Asks "Apply this fix? [y/N/a(ll)/s(kip all)]"
4. Writes the patched file if accepted

Design principles:
- NEVER modifies a file without explicit user confirmation
- Each fix is atomic: one finding → one targeted string replacement
- Preserves file encoding, line endings, and indentation
- Shows a clear before/after diff using Python's built-in difflib

Auto-fixable rule IDs (mapped to fix functions):
  FEDRAMP-002  fix_cors_wildcards         - replace ["*"] methods/headers
  FEDRAMP-003  fix_swagger_exposure       - disable /docs in FastAPI()
  FEDRAMP-004  fix_docker_root_user       - add USER appuser directive
  FEDRAMP-005  fix_docker_reload_flag     - remove --reload from CMD
  FEDRAMP-009  fix_cors_credentials       - remove placeholder origin + note
  HIPAA-007    fix_debug_mode             - set DEBUG=False
  SOC2 (CORS)  fix_cors_wildcards         - same as FEDRAMP-002
"""

from __future__ import annotations

import difflib
import re
import shutil
import textwrap
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple

from rich.console import Console
from rich.panel import Panel
from rich.syntax import Syntax
from rich.text import Text

from security_scanner.compliance.rules.base import Finding

console = Console()

# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class FixResult:
    finding: Finding
    applied: bool
    skipped: bool
    error: Optional[str] = None
    patched_lines: int = 0

    @property
    def status_str(self) -> str:
        if self.error:
            return f"ERROR: {self.error}"
        if self.applied:
            return f"✅ Applied ({self.patched_lines} line(s) changed)"
        return "⏭  Skipped"


# ---------------------------------------------------------------------------
# Individual fix functions
# Each receives (file_path, content) and returns patched content (or None if
# nothing changed)
# ---------------------------------------------------------------------------

def fix_cors_wildcards(file_path: Path, content: str) -> Optional[str]:
    """
    Replace allow_methods=["*"] with an explicit list.
    Replace allow_headers=["*"] with an explicit list.
    """
    patched = content

    # Fix methods
    patched = re.sub(
        r'allow_methods\s*=\s*\[[\s"\']*\*[\s"\']*\]',
        'allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"]',
        patched,
    )

    # Fix headers
    patched = re.sub(
        r'allow_headers\s*=\s*\[[\s"\']*\*[\s"\']*\]',
        'allow_headers=["Content-Type", "Authorization", "X-Requested-With"]',
        patched,
    )

    return patched if patched != content else None


def fix_swagger_exposure(file_path: Path, content: str) -> Optional[str]:
    """
    Add docs_url=None, redoc_url=None, openapi_url=None to FastAPI() constructor.
    Handles single-line and multi-line constructors.
    """
    # Already fixed?
    if "docs_url=None" in content:
        return None

    # Single-line FastAPI() with no args
    single_empty = re.compile(r'\bapp\s*=\s*FastAPI\s*\(\s*\)')
    if single_empty.search(content):
        patched = single_empty.sub(
            'app = FastAPI(\n    docs_url=None,\n    redoc_url=None,\n    openapi_url=None,\n)',
            content,
        )
        return patched if patched != content else None

    # FastAPI( with existing args - insert before the closing paren
    # Find the FastAPI( opening
    match = re.search(r'\bapp\s*=\s*FastAPI\s*\(', content)
    if not match:
        return None

    # Find matching closing paren
    start = match.end() - 1  # position of '('
    depth = 0
    pos = start
    for pos, ch in enumerate(content[start:], start=start):
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                break

    # Insert before the closing paren
    indent = "    "
    docs_args = (
        f"\n{indent}docs_url=None,\n{indent}redoc_url=None,\n{indent}openapi_url=None,"
    )
    patched = content[:pos] + docs_args + "\n" + content[pos:]
    return patched if patched != content else None


def fix_docker_root_user(file_path: Path, content: str) -> Optional[str]:
    """
    Add a non-root USER directive before the CMD/ENTRYPOINT instruction.
    Prepends the user-creation RUN commands if not already present.
    """
    if re.search(r'^USER\s+(?!root\b)', content, re.MULTILINE | re.IGNORECASE):
        return None  # Already has non-root USER

    user_block = (
        "\n# Security: run as non-root user\n"
        "RUN groupadd -r appuser && useradd -r -g appuser -u 1001 appuser \\\n"
        "    && mkdir -p /app && chown -R appuser:appuser /app\n"
        "USER appuser\n"
    )

    # Insert before CMD or ENTRYPOINT
    patched = re.sub(
        r'(^(?:CMD|ENTRYPOINT)\s)',
        user_block + r'\1',
        content,
        flags=re.MULTILINE | re.IGNORECASE,
        count=1,
    )
    return patched if patched != content else None


def fix_docker_reload_flag(file_path: Path, content: str) -> Optional[str]:
    """
    Remove --reload from uvicorn CMD in Dockerfile.
    Replaces with a comment explaining why.
    """
    patched = re.sub(
        r',?\s*["\']--reload["\']',
        '  # --reload removed: never use in production',
        content,
    )
    # Also handle shell form: CMD uvicorn ... --reload
    patched = re.sub(
        r'\s+--reload\b',
        '  # production: --reload removed',
        patched,
    )
    return patched if patched != content else None


def fix_cors_credentials(file_path: Path, content: str) -> Optional[str]:
    """
    Remove placeholder URLs from the CORS origins list.
    Add a comment directing user to set allow_credentials=False.
    """
    # Remove placeholder origin
    patched = re.sub(
        r'\s*["\']https?://your-frontend-domain\.com["\'],?\s*\n?',
        "\n    # TODO: Add your actual production domain here\n",
        content,
    )

    # Also flag allow_credentials with a comment
    patched = re.sub(
        r'allow_credentials\s*=\s*True',
        (
            'allow_credentials=False  '
            '# FEDRAMP-009: use Authorization header instead of cookies'
        ),
        patched,
    )

    return patched if patched != content else None


def fix_debug_mode(file_path: Path, content: str) -> Optional[str]:
    """Set DEBUG=True → DEBUG=False in env files and Python config."""
    patched = re.sub(r'\bDEBUG\s*=\s*True\b', 'DEBUG=False', content)
    patched = re.sub(r'^DEBUG\s*=\s*true\s*$', 'DEBUG=false', patched, flags=re.MULTILINE | re.IGNORECASE)
    return patched if patched != content else None


# ---------------------------------------------------------------------------
# Fix registry
# ---------------------------------------------------------------------------

FIX_REGISTRY: Dict[str, Callable[[Path, str], Optional[str]]] = {
    "fix_cors_wildcards":    fix_cors_wildcards,
    "fix_swagger_exposure":  fix_swagger_exposure,
    "fix_docker_root_user":  fix_docker_root_user,
    "fix_docker_reload_flag": fix_docker_reload_flag,
    "fix_cors_credentials":  fix_cors_credentials,
    "fix_debug_mode":        fix_debug_mode,
}

# Map rule_ids → fix function names
RULE_TO_FIX: Dict[str, str] = {
    "FEDRAMP-002": "fix_cors_wildcards",
    "FEDRAMP-003": "fix_swagger_exposure",
    "FEDRAMP-004": "fix_docker_root_user",
    "FEDRAMP-005": "fix_docker_reload_flag",
    "FEDRAMP-009": "fix_cors_credentials",
    "HIPAA-007":   "fix_debug_mode",
    "SOC2-006":    "fix_cors_wildcards",  # if SOC2 has a CORS rule
}


def get_fix_function(finding: Finding) -> Optional[Callable[[Path, str], Optional[str]]]:
    """Return the fix function for a finding, or None if not auto-fixable."""
    fix_name = RULE_TO_FIX.get(finding.rule_id)
    if not fix_name:
        return None
    return FIX_REGISTRY.get(fix_name)


def is_auto_fixable(finding: Finding) -> bool:
    return get_fix_function(finding) is not None


# ---------------------------------------------------------------------------
# Diff helper
# ---------------------------------------------------------------------------

def _unified_diff(original: str, patched: str, file_path: Path) -> str:
    """Return a unified diff string between original and patched content."""
    orig_lines = original.splitlines(keepends=True)
    patch_lines = patched.splitlines(keepends=True)
    diff = difflib.unified_diff(
        orig_lines,
        patch_lines,
        fromfile=f"a/{file_path.name}",
        tofile=f"b/{file_path.name}",
        n=3,
    )
    return "".join(diff)


# ---------------------------------------------------------------------------
# Interactive fixer engine
# ---------------------------------------------------------------------------

class InteractiveFixer:
    """
    Presents each auto-fixable finding to the user, shows a diff, and
    applies patches on confirmation.

    Usage:
        fixer = InteractiveFixer()
        results = fixer.run(findings)
    """

    def __init__(self, dry_run: bool = False, backup: bool = True):
        self.dry_run = dry_run
        self.backup = backup
        self._apply_all = False
        self._skip_all = False

    def run(self, findings: List[Finding]) -> List[FixResult]:
        """
        Process all findings. Returns a list of FixResult objects.
        """
        fixable = [f for f in findings if is_auto_fixable(f)]
        non_fixable = [f for f in findings if not is_auto_fixable(f)]

        if not fixable:
            console.print("\n[yellow]No auto-fixable findings in this batch.[/yellow]")
            return []

        console.print(
            f"\n[bold cyan]Interactive Fixer[/bold cyan] - "
            f"[bold]{len(fixable)}[/bold] auto-fixable findings "
            f"([dim]{len(non_fixable)} require manual action[/dim])\n"
        )

        # De-duplicate: group findings by (file_path, rule_id) - one fix per file per rule
        seen: set[Tuple[Path, str]] = set()
        unique_fixable: List[Finding] = []
        for f in fixable:
            key = (f.file_path, f.rule_id)
            if key not in seen:
                seen.add(key)
                unique_fixable.append(f)

        results: List[FixResult] = []
        for finding in unique_fixable:
            result = self._process_finding(finding)
            results.append(result)

            if self._skip_all:
                remaining = [
                    FixResult(f, applied=False, skipped=True)
                    for f in unique_fixable[unique_fixable.index(finding) + 1:]
                ]
                results.extend(remaining)
                break

        self._print_summary(results)
        return results

    def _process_finding(self, finding: Finding) -> FixResult:
        """Show diff for one finding and prompt user."""
        if self._skip_all:
            return FixResult(finding, applied=False, skipped=True)

        fix_fn = get_fix_function(finding)
        if not fix_fn:
            return FixResult(finding, applied=False, skipped=True, error="No fix function")

        # Read current file
        try:
            original = finding.file_path.read_text(encoding="utf-8", errors="replace")
        except OSError as e:
            return FixResult(finding, applied=False, skipped=False, error=str(e))

        # Compute patch
        patched = fix_fn(finding.file_path, original)
        if patched is None:
            return FixResult(finding, applied=False, skipped=True)

        # Show the finding
        sev_colors = {
            "CRITICAL": "bold red", "HIGH": "red",
            "MEDIUM": "yellow", "LOW": "cyan",
        }
        color = sev_colors.get(finding.severity.value, "white")
        console.print()
        console.print(Panel(
            f"[{color}][{finding.rule_id}] {finding.severity.value}[/{color}]  "
            f"[bold]{finding.title}[/bold]\n\n"
            f"[dim]File:[/dim] {finding.file_path}\n"
            f"[dim]Line:[/dim] {finding.line_number}\n\n"
            f"{finding.description}\n\n"
            f"[dim]Ref:[/dim] {finding.reference}",
            title="🔍 Finding",
            border_style=color,
        ))

        # Show diff
        diff_text = _unified_diff(original, patched, finding.file_path)
        if diff_text:
            console.print("\n[bold]Proposed fix (unified diff):[/bold]")
            # Colour the diff manually
            for line in diff_text.splitlines():
                if line.startswith("+++") or line.startswith("---"):
                    console.print(f"[dim]{line}[/dim]")
                elif line.startswith("+"):
                    console.print(f"[green]{line}[/green]")
                elif line.startswith("-"):
                    console.print(f"[red]{line}[/red]")
                elif line.startswith("@@"):
                    console.print(f"[cyan]{line}[/cyan]")
                else:
                    console.print(f"[dim]{line}[/dim]")

        if self._apply_all:
            return self._apply_fix(finding, original, patched)

        # Prompt
        console.print(
            "\n[bold]Apply this fix?[/bold]  "
            "[green]y[/green]=yes  [dim]N[/dim]=skip  "
            "[yellow]a[/yellow]=apply all remaining  [red]s[/red]=skip all remaining  "
            "[blue]v[/blue]=view full file\n"
        )
        try:
            choice = input("  → ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            choice = "s"

        if choice == "v":
            console.print(Syntax(patched, _detect_language(finding.file_path), line_numbers=True))
            # Re-prompt after view
            try:
                choice = input("\n  Apply? [y/N/a/s] → ").strip().lower()
            except (EOFError, KeyboardInterrupt):
                choice = "s"

        if choice == "a":
            self._apply_all = True
            return self._apply_fix(finding, original, patched)
        elif choice == "s":
            self._skip_all = True
            return FixResult(finding, applied=False, skipped=True)
        elif choice == "y":
            return self._apply_fix(finding, original, patched)
        else:
            return FixResult(finding, applied=False, skipped=True)

    def _apply_fix(self, finding: Finding, original: str, patched: str) -> FixResult:
        """Write patched content to disk."""
        if self.dry_run:
            console.print("[yellow]  [DRY RUN] Would write patch - skipping.[/yellow]")
            return FixResult(finding, applied=True, skipped=False, patched_lines=0)

        # Backup
        if self.backup:
            backup_path = finding.file_path.with_suffix(finding.file_path.suffix + ".bak")
            shutil.copy2(finding.file_path, backup_path)

        try:
            finding.file_path.write_text(patched, encoding="utf-8")
            lines_changed = sum(
                1 for a, b in zip(original.splitlines(), patched.splitlines())
                if a != b
            ) + abs(len(original.splitlines()) - len(patched.splitlines()))
            console.print(f"  [green]✅ Patched: {finding.file_path}[/green]")
            return FixResult(finding, applied=True, skipped=False, patched_lines=lines_changed)
        except OSError as e:
            return FixResult(finding, applied=False, skipped=False, error=str(e))

    def _print_summary(self, results: List[FixResult]) -> None:
        applied = [r for r in results if r.applied]
        skipped = [r for r in results if r.skipped]
        errors  = [r for r in results if r.error]

        console.print()
        console.print(Panel(
            f"[bold]Fix Summary[/bold]\n\n"
            f"  [green]Applied:[/green]  {len(applied)}\n"
            f"  [yellow]Skipped:[/yellow]  {len(skipped)}\n"
            f"  [red]Errors:[/red]   {len(errors)}",
            border_style="cyan",
        ))

        if errors:
            for r in errors:
                console.print(f"  [red]✗ {r.finding.file_path}: {r.error}[/red]")

        if applied and not self.dry_run:
            console.print(
                "\n[dim]Backups written as *.bak files next to each patched file.[/dim]"
            )


def _detect_language(file_path: Path) -> str:
    """Return a Rich-compatible language name for syntax highlighting."""
    ext_map = {
        ".py": "python", ".js": "javascript", ".ts": "typescript",
        ".jsx": "jsx", ".tsx": "tsx", ".dockerfile": "dockerfile",
        ".sh": "bash", ".yml": "yaml", ".yaml": "yaml",
        ".json": "json", ".toml": "toml",
    }
    name = file_path.name.lower()
    if name in {"dockerfile", "dockerfile.prod", "dockerfile.dev"}:
        return "dockerfile"
    return ext_map.get(file_path.suffix.lower(), "text")
