"""
Diff analysis agent — maps changed files to relevant scan domains.

Basic mode (default): rule-based mapping from file extensions to domains.
Advanced mode (optional): sends diff summary to an LLM for risk-area identification.
"""

from pathlib import Path
from typing import Dict, List, Set

from .models import ScanPlan

# Extension → domains mapping
_EXT_DOMAIN_MAP: Dict[str, List[str]] = {
    ".py":         ["security", "lint", "typecheck", "sast"],
    ".js":         ["security", "lint", "sast"],
    ".jsx":        ["security", "lint", "sast"],
    ".ts":         ["security", "lint", "typecheck", "sast"],
    ".tsx":        ["security", "lint", "typecheck", "sast"],
    ".mjs":        ["security", "lint", "sast"],
    ".cjs":        ["security", "lint", "sast"],
    ".go":         ["security", "lint", "sast"],
    ".rs":         ["security", "lint"],
    ".java":       ["security", "lint", "sast"],
    ".kt":         ["security", "lint"],
    ".rb":         ["security", "lint", "sast"],
    ".php":        ["security", "lint", "sast"],
    ".env":        ["security"],
}

# Special filenames → domains
_FILE_DOMAIN_MAP: Dict[str, List[str]] = {
    "dockerfile":        ["container"],
    "docker-compose.yml": ["container", "iac"],
    "docker-compose.yaml": ["container", "iac"],
    "package.json":      ["sca"],
    "package-lock.json": ["sca"],
    "yarn.lock":         ["sca"],
    "pnpm-lock.yaml":    ["sca"],
    "requirements.txt":  ["sca"],
    "poetry.lock":       ["sca"],
    "pipfile.lock":      ["sca"],
    "go.sum":            ["sca"],
    "cargo.lock":        ["sca"],
    "gemfile.lock":      ["sca"],
    "composer.lock":     ["sca"],
}

# IaC file patterns
_IAC_EXTENSIONS = {".tf", ".tfvars", ".hcl", ".yaml", ".yml"}
_IAC_DIRS = {"terraform", "infrastructure", "infra", "cloudformation", "pulumi"}


class DiffAnalyzer:
    """Map changed files to relevant scan domains."""

    def analyze(self, changed_files: List[str], diff_content: str = "") -> ScanPlan:
        """Produce a ScanPlan from a list of changed file paths.

        Args:
            changed_files: Relative paths of changed files.
            diff_content:  Optional unified diff text (for advanced analysis).
        """
        domains: Set[str] = set()
        priority_files: List[str] = []

        for fpath in changed_files:
            p = Path(fpath)
            name_lower = p.name.lower()
            ext = p.suffix.lower()

            # Check special filenames first
            if name_lower in _FILE_DOMAIN_MAP:
                domains.update(_FILE_DOMAIN_MAP[name_lower])

            # Check extensions
            if ext in _EXT_DOMAIN_MAP:
                domains.update(_EXT_DOMAIN_MAP[ext])

            # IaC detection
            if ext in _IAC_EXTENSIONS:
                parts_lower = [part.lower() for part in p.parts]
                if any(d in parts_lower for d in _IAC_DIRS):
                    domains.add("iac")

            # Priority: security-sensitive files
            if self._is_security_sensitive(fpath):
                priority_files.append(fpath)

        # Always include security for any code change
        if changed_files:
            domains.add("security")

        # Heuristic reasoning
        reasoning_parts = []
        if priority_files:
            reasoning_parts.append(
                f"Security-sensitive files changed: {', '.join(priority_files[:5])}"
            )
        if "sca" in domains:
            reasoning_parts.append("Dependency files changed — SCA scan recommended")
        if "iac" in domains:
            reasoning_parts.append("Infrastructure files changed — IaC scan recommended")
        if "container" in domains:
            reasoning_parts.append("Docker files changed — container scan recommended")

        return ScanPlan(
            domains=sorted(domains),
            files=changed_files,
            priority_files=priority_files,
            reasoning="; ".join(reasoning_parts) if reasoning_parts else "Standard code changes",
        )

    def analyze_with_ai(
        self,
        changed_files: List[str],
        diff_content: str,
        ai_client=None,
    ) -> ScanPlan:
        """Enhanced analysis using an LLM for risk identification.

        Falls back to basic analysis if AI client is not available.
        """
        # Start with basic analysis
        plan = self.analyze(changed_files, diff_content)

        if ai_client is None:
            return plan

        # Ask the LLM for additional risk assessment
        prompt = (
            "Analyze the following code diff and identify security risk areas.\n"
            "Changed files:\n"
            + "\n".join(f"  - {f}" for f in changed_files[:20])
            + "\n\nDiff (first 3000 chars):\n"
            + diff_content[:3000]
            + "\n\nRespond with a JSON object: "
            '{"additional_domains": ["domain1"], "risk_areas": ["area1"], "priority_files": ["file1"]}'
        )

        try:
            response = ai_client.complete(prompt, max_tokens=500)
            import json
            data = json.loads(response)

            # Merge AI suggestions
            for domain in data.get("additional_domains", []):
                if domain not in plan.domains:
                    plan.domains.append(domain)
            for f in data.get("priority_files", []):
                if f not in plan.priority_files and f in changed_files:
                    plan.priority_files.append(f)
            if data.get("risk_areas"):
                plan.reasoning += f"; AI risk areas: {', '.join(data['risk_areas'][:5])}"
        except Exception:
            pass  # AI failure is non-fatal, basic plan is already complete

        return plan

    @staticmethod
    def _is_security_sensitive(fpath: str) -> bool:
        """Heuristic: is this file likely security-sensitive?"""
        lower = fpath.lower()
        sensitive_patterns = [
            "auth", "login", "session", "token", "credential",
            "password", "secret", "crypto", "encrypt", "key",
            "middleware", "guard", "policy", "permission",
            ".env", "config/database", "config/secrets",
        ]
        return any(p in lower for p in sensitive_patterns)
