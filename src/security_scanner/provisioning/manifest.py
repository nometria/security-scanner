"""
Tool manifest - pinned versions and download URLs for managed tools.

Each entry describes a single external binary with per-platform download URLs,
SHA-256 checksums, and extraction paths.
"""

from dataclasses import dataclass, field
from typing import Dict


@dataclass(frozen=True)
class ToolManifest:
    """Describes one managed tool binary."""

    name: str
    version: str
    # { "linux_amd64": "https://...", "darwin_arm64": "https://..." }
    platform_urls: Dict[str, str] = field(default_factory=dict)
    # { "linux_amd64": "sha256:...", "darwin_arm64": "sha256:..." }
    sha256: Dict[str, str] = field(default_factory=dict)
    binary_name: str = ""
    # Relative path inside the archive where the binary lives
    extract_path: str = ""


def _platform_key() -> str:
    """Return the platform key for the current system."""
    import platform
    system = platform.system().lower()
    machine = platform.machine().lower()
    if machine in ("x86_64", "amd64"):
        arch = "amd64"
    elif machine in ("arm64", "aarch64"):
        arch = "arm64"
    else:
        arch = machine
    return f"{system}_{arch}"


MANAGED_TOOLS: Dict[str, ToolManifest] = {
    "trivy": ToolManifest(
        name="trivy",
        version="0.62.1",
        platform_urls={
            "linux_amd64": "https://github.com/aquasecurity/trivy/releases/download/v0.62.1/trivy_0.62.1_Linux-64bit.tar.gz",
            "linux_arm64": "https://github.com/aquasecurity/trivy/releases/download/v0.62.1/trivy_0.62.1_Linux-ARM64.tar.gz",
            "darwin_amd64": "https://github.com/aquasecurity/trivy/releases/download/v0.62.1/trivy_0.62.1_macOS-64bit.tar.gz",
            "darwin_arm64": "https://github.com/aquasecurity/trivy/releases/download/v0.62.1/trivy_0.62.1_macOS-ARM64.tar.gz",
        },
        binary_name="trivy",
        extract_path="trivy",
    ),
    "opengrep": ToolManifest(
        name="opengrep",
        version="1.16.5",
        platform_urls={
            "linux_amd64": "https://github.com/opengrep/opengrep/releases/download/v1.16.5/opengrep-v1.16.5-linux-x86_64.tar.gz",
            "darwin_amd64": "https://github.com/opengrep/opengrep/releases/download/v1.16.5/opengrep-v1.16.5-osx-x86_64.tar.gz",
            "darwin_arm64": "https://github.com/opengrep/opengrep/releases/download/v1.16.5/opengrep-v1.16.5-osx-arm64.tar.gz",
        },
        binary_name="opengrep",
        extract_path="opengrep",
    ),
    "ruff": ToolManifest(
        name="ruff",
        version="0.11.5",
        platform_urls={
            "linux_amd64": "https://github.com/astral-sh/ruff/releases/download/0.11.5/ruff-x86_64-unknown-linux-gnu.tar.gz",
            "linux_arm64": "https://github.com/astral-sh/ruff/releases/download/0.11.5/ruff-aarch64-unknown-linux-gnu.tar.gz",
            "darwin_amd64": "https://github.com/astral-sh/ruff/releases/download/0.11.5/ruff-x86_64-apple-darwin.tar.gz",
            "darwin_arm64": "https://github.com/astral-sh/ruff/releases/download/0.11.5/ruff-aarch64-apple-darwin.tar.gz",
        },
        binary_name="ruff",
        extract_path="ruff",
    ),
    "biome": ToolManifest(
        name="biome",
        version="1.9.4",
        platform_urls={
            "linux_amd64": "https://github.com/biomejs/biome/releases/download/cli%2Fv1.9.4/biome-linux-x64",
            "linux_arm64": "https://github.com/biomejs/biome/releases/download/cli%2Fv1.9.4/biome-linux-arm64",
            "darwin_amd64": "https://github.com/biomejs/biome/releases/download/cli%2Fv1.9.4/biome-darwin-x64",
            "darwin_arm64": "https://github.com/biomejs/biome/releases/download/cli%2Fv1.9.4/biome-darwin-arm64",
        },
        binary_name="biome",
        extract_path="",  # direct binary, not an archive
    ),
    "jscpd": ToolManifest(
        name="jscpd",
        version="4.0.5",
        platform_urls={},  # installed via npm: npx jscpd
        binary_name="jscpd",
    ),
}
