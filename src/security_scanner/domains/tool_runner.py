"""
Subprocess runner for external tool domains.

Provides a thin wrapper around ``subprocess.run`` with:
  - timeout handling
  - JSON output capture
  - tool binary resolution (managed tools dir → PATH)
"""

import json
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional


@dataclass
class ToolOutput:
    """Raw output from an external tool invocation."""

    stdout: str = ""
    stderr: str = ""
    returncode: int = -1
    duration: float = 0.0


class ToolRunner:
    """Locate and execute external scanning tools."""

    def __init__(self, managed_dir: Optional[Path] = None):
        if managed_dir is None:
            managed_dir = Path.home() / ".ai-security-scan" / "tools"
        self.managed_dir = managed_dir

    def find_tool(self, name: str) -> Optional[Path]:
        """Resolve a tool binary.

        Checks, in order:
          1. Managed tools directory  (``~/.ai-security-scan/tools/<name>``)
          2. System PATH              (via ``shutil.which``)
        """
        # Check managed dir first
        if self.managed_dir.is_dir():
            for candidate in (
                self.managed_dir / name,
                self.managed_dir / name / name,
                self.managed_dir / name / "bin" / name,
            ):
                if candidate.is_file() and candidate.stat().st_mode & 0o111:
                    return candidate

        # Fall back to system PATH
        found = shutil.which(name)
        return Path(found) if found else None

    def run_tool(
        self,
        cmd: List[str],
        cwd: Optional[Path] = None,
        timeout: int = 300,
        env: Optional[Dict[str, str]] = None,
    ) -> ToolOutput:
        """Execute an external tool and capture its output.

        Args:
            cmd:     Command + arguments.
            cwd:     Working directory for the subprocess.
            timeout: Max seconds before killing (default 300s).
            env:     Optional environment variables (merged with os.environ).

        Returns:
            ToolOutput with stdout/stderr/returncode/duration.
        """
        import os
        import time

        merged_env = None
        if env:
            merged_env = {**os.environ, **env}

        t0 = time.monotonic()
        try:
            proc = subprocess.run(
                cmd,
                cwd=cwd,
                capture_output=True,
                text=True,
                timeout=timeout,
                env=merged_env,
            )
            return ToolOutput(
                stdout=proc.stdout,
                stderr=proc.stderr,
                returncode=proc.returncode,
                duration=time.monotonic() - t0,
            )
        except subprocess.TimeoutExpired:
            return ToolOutput(
                stderr=f"Tool timed out after {timeout}s: {' '.join(cmd)}",
                returncode=-1,
                duration=time.monotonic() - t0,
            )
        except FileNotFoundError:
            return ToolOutput(
                stderr=f"Tool not found: {cmd[0]}",
                returncode=-1,
                duration=time.monotonic() - t0,
            )

    def run_json(
        self,
        cmd: List[str],
        cwd: Optional[Path] = None,
        timeout: int = 300,
        env: Optional[Dict[str, str]] = None,
    ) -> tuple:
        """Run a tool and parse its stdout as JSON.

        Returns:
            (parsed_json, tool_output)  — parsed_json is None on parse failure.
        """
        output = self.run_tool(cmd, cwd=cwd, timeout=timeout, env=env)
        parsed = None
        if output.stdout:
            try:
                parsed = json.loads(output.stdout)
            except json.JSONDecodeError:
                pass
        return parsed, output
