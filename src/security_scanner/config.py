"""
Configuration loader for ai-security-scan.

Looks for ``ai-security-scan.yml`` (or ``.ai-security-scan.yml``) in the
project root.  Falls back to sensible defaults when no config file is found.

YAML parsing uses PyYAML when available, otherwise a tiny safe-subset parser
that handles the simple structures we need (keeps the package zero-dep).
"""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

CONFIG_FILENAMES = ("ai-security-scan.yml", ".ai-security-scan.yml")


@dataclass
class ScanConfig:
    """User-facing configuration.

    Designed to be minimal — most users need only ``domains`` and ``fail_on``.
    """

    # Which domains to run (empty = all available)
    domains: List[str] = field(default_factory=lambda: [])

    # Scan scope
    scan_mode: str = "full"  # "full" | "incremental" | "pr"
    base_ref: str = ""       # for PR mode, e.g. "origin/main"

    # Failure thresholds
    fail_on: str = "high"    # "critical" | "high" | "medium" | "low" | "any"
    strict: bool = False     # missing tool → HIGH finding

    # File filtering
    exclude_patterns: List[str] = field(default_factory=lambda: [
        "node_modules", ".git", "dist", "build", ".next",
        "__pycache__", ".venv", "venv",
    ])

    # Dashboard
    dashboard: bool = False

    # Auto-fix
    fix: bool = False  # auto-fix fixable issues (lint, formatting)

    # Per-domain overrides  { "lint": {"ruff": {"select": ["E", "F"]}} }
    tool_overrides: Dict[str, Dict[str, Any]] = field(default_factory=dict)


def load_config(project_root: Path) -> ScanConfig:
    """Load configuration from the project root, or return defaults."""
    for name in CONFIG_FILENAMES:
        cfg_path = project_root / name
        if cfg_path.is_file():
            raw = _parse_yaml(cfg_path)
            if raw and isinstance(raw, dict):
                return _dict_to_config(raw)
    return ScanConfig()


def _dict_to_config(d: Dict[str, Any]) -> ScanConfig:
    """Map a parsed YAML dict onto a ScanConfig, ignoring unknown keys."""
    cfg = ScanConfig()
    for key in (
        "domains", "scan_mode", "base_ref", "fail_on", "strict",
        "exclude_patterns", "dashboard", "fix", "tool_overrides",
    ):
        if key in d:
            setattr(cfg, key, d[key])
    return cfg


# ── YAML parsing ─────────────────────────────────────────────────────────────

def _parse_yaml(path: Path) -> Any:
    """Parse a YAML file.  Uses PyYAML when available, else a minimal parser."""
    text = path.read_text(encoding="utf-8")
    try:
        import yaml  # type: ignore[import-untyped]
        return yaml.safe_load(text)
    except ImportError:
        return _mini_yaml_parse(text)


def _mini_yaml_parse(text: str) -> Dict[str, Any]:
    """Tiny safe-subset YAML parser.

    Handles:
      key: value              → str/int/float/bool
      key:                    → None
        - item                → list
      key:                    → None
        nested_key: value     → dict (one level deep)
    """
    result: Dict[str, Any] = {}
    current_key: Optional[str] = None
    current_list: Optional[list] = None
    current_dict: Optional[dict] = None

    def _flush():
        nonlocal current_key, current_list, current_dict
        if current_key is not None:
            if current_list is not None:
                result[current_key] = current_list
            elif current_dict is not None:
                result[current_key] = current_dict
            else:
                result[current_key] = None
        current_key = None
        current_list = None
        current_dict = None

    for raw_line in text.splitlines():
        # Skip blanks and full-line comments
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        indent = len(raw_line) - len(raw_line.lstrip())

        # Top-level key
        if indent == 0 and ":" in stripped:
            _flush()

            key, _, val = stripped.partition(":")
            key = key.strip()
            val = _strip_comment(val.strip())

            if val:
                result[key] = _coerce(val)
                current_key = None
            else:
                current_key = key
        elif indent > 0 and stripped.startswith("- "):
            # List item
            if current_list is None:
                current_list = []
            current_list.append(_coerce(_strip_comment(stripped[2:].strip())))
        elif indent > 0 and ":" in stripped:
            # Nested dict
            if current_dict is None:
                current_dict = {}
            k, _, v = stripped.partition(":")
            current_dict[k.strip()] = _coerce(_strip_comment(v.strip()))

    _flush()
    return result


def _strip_comment(val: str) -> str:
    """Remove inline ``# comment`` from a YAML value (respecting quoted strings)."""
    if not val:
        return val
    # If value is quoted, strip comment after closing quote
    if val and val[0] in ('"', "'"):
        close = val.find(val[0], 1)
        if close > 0:
            return val[:close + 1]
        return val
    # Unquoted: strip from first #
    idx = val.find(" #")
    if idx >= 0:
        return val[:idx].rstrip()
    return val


def _coerce(val: str) -> Any:
    """Coerce a YAML scalar string into a Python type."""
    if not val:
        return None
    if val in ("true", "True", "yes", "on"):
        return True
    if val in ("false", "False", "no", "off"):
        return False
    if val in ("null", "~", "None"):
        return None
    # Remove quotes
    if len(val) >= 2 and val[0] == val[-1] and val[0] in ('"', "'"):
        return val[1:-1]
    try:
        return int(val)
    except ValueError:
        pass
    try:
        return float(val)
    except ValueError:
        pass
    return val
