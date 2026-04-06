"""
Tool provisioner — downloads, verifies, and extracts managed tool binaries.

All operations use stdlib only (urllib, tarfile, zipfile, hashlib).
"""

import hashlib
import stat
import tarfile
import zipfile
from pathlib import Path
from typing import List, Optional, Tuple
from urllib.request import urlretrieve

from .manifest import MANAGED_TOOLS, ToolManifest, _platform_key


class ToolProvisioner:
    """Download and manage external tool binaries."""

    def __init__(self, tools_dir: Optional[Path] = None):
        if tools_dir is None:
            tools_dir = Path.home() / ".ai-security-scan" / "tools"
        self.tools_dir = tools_dir

    def ensure_tool(self, name: str) -> Optional[Path]:
        """Return the path to a managed tool, downloading if needed.

        Returns None if the tool has no manifest or cannot be installed on
        this platform.
        """
        manifest = MANAGED_TOOLS.get(name)
        if manifest is None:
            return None

        existing = self._installed_path(manifest)
        if existing and existing.is_file():
            return existing

        return self._download_tool(manifest)

    def is_provisioned(self, name: str) -> bool:
        manifest = MANAGED_TOOLS.get(name)
        if manifest is None:
            return False
        path = self._installed_path(manifest)
        return path is not None and path.is_file()

    def list_provisioned(self) -> List[Tuple[str, str, Path]]:
        """Return (name, version, path) for all installed managed tools."""
        result = []
        for name, manifest in MANAGED_TOOLS.items():
            path = self._installed_path(manifest)
            if path and path.is_file():
                result.append((name, manifest.version, path))
        return result

    def clean(self) -> int:
        """Remove all managed tools. Returns number of files removed."""
        count = 0
        if self.tools_dir.is_dir():
            import shutil
            for child in self.tools_dir.iterdir():
                if child.is_dir():
                    shutil.rmtree(child)
                else:
                    child.unlink()
                count += 1
        return count

    # ── Internal ──────────────────────────────────────────────────────────

    def _installed_path(self, manifest: ToolManifest) -> Optional[Path]:
        """Check if a tool is already installed and return its binary path."""
        tool_dir = self.tools_dir / manifest.name / manifest.version
        binary = tool_dir / manifest.binary_name
        if binary.is_file() and binary.stat().st_mode & 0o111:
            return binary
        return None

    def _download_tool(self, manifest: ToolManifest) -> Optional[Path]:
        """Download, verify, and install a managed tool."""
        platform = _platform_key()
        url = manifest.platform_urls.get(platform)
        if not url:
            return None

        tool_dir = self.tools_dir / manifest.name / manifest.version
        tool_dir.mkdir(parents=True, exist_ok=True)

        # Download
        filename = url.rsplit("/", 1)[-1]
        download_path = tool_dir / filename

        try:
            urlretrieve(url, download_path)
        except Exception:
            return None

        # Verify SHA-256 if available
        expected_sha = manifest.sha256.get(platform)
        if expected_sha:
            actual_sha = self._sha256(download_path)
            if actual_sha != expected_sha.removeprefix("sha256:"):
                download_path.unlink(missing_ok=True)
                return None

        # Extract or move binary
        binary_path = tool_dir / manifest.binary_name

        if filename.endswith(".tar.gz") or filename.endswith(".tgz"):
            self._extract_tar(download_path, tool_dir, manifest)
        elif filename.endswith(".zip"):
            self._extract_zip(download_path, tool_dir, manifest)
        else:
            # Direct binary download (e.g., biome)
            download_path.rename(binary_path)

        # Ensure executable
        if binary_path.is_file():
            binary_path.chmod(binary_path.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)

        # Cleanup archive
        if download_path.is_file() and download_path != binary_path:
            download_path.unlink(missing_ok=True)

        return binary_path if binary_path.is_file() else None

    def _extract_tar(self, archive: Path, dest: Path, manifest: ToolManifest) -> None:
        with tarfile.open(archive, "r:gz") as tf:
            if manifest.extract_path:
                # Extract only the binary
                for member in tf.getmembers():
                    if member.name.endswith(manifest.binary_name) or member.name == manifest.extract_path:
                        member.name = manifest.binary_name
                        tf.extract(member, dest)
                        return
            # Fall back to extracting everything with path traversal protection
            dest_resolved = dest.resolve()
            for member in tf.getmembers():
                target = (dest / member.name).resolve()
                if not str(target).startswith(str(dest_resolved)):
                    continue  # Skip paths that escape the destination
                tf.extract(member, dest)

    def _extract_zip(self, archive: Path, dest: Path, manifest: ToolManifest) -> None:
        with zipfile.ZipFile(archive, "r") as zf:
            if manifest.extract_path:
                for name in zf.namelist():
                    if name.endswith(manifest.binary_name):
                        data = zf.read(name)
                        (dest / manifest.binary_name).write_bytes(data)
                        return
            zf.extractall(dest)

    @staticmethod
    def _sha256(path: Path) -> str:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            while True:
                chunk = f.read(8192)
                if not chunk:
                    break
                h.update(chunk)
        return h.hexdigest()
