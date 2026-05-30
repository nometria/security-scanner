"""
Language and framework auto-detection.

Detects project languages, frameworks, and existing tool configurations
to auto-select appropriate scan domains and tools.
"""

from pathlib import Path
from typing import Dict, List, Set


# Extension → language mapping
_EXT_LANG: Dict[str, str] = {
    ".py": "python", ".pyw": "python", ".pyi": "python",
    ".js": "javascript", ".mjs": "javascript", ".cjs": "javascript",
    ".jsx": "javascript",
    ".ts": "typescript", ".tsx": "typescript", ".mts": "typescript",
    ".go": "go",
    ".rs": "rust",
    ".java": "java",
    ".kt": "kotlin", ".kts": "kotlin",
    ".cs": "csharp",
    ".c": "c", ".h": "c",
    ".cpp": "cpp", ".cc": "cpp", ".cxx": "cpp", ".hpp": "cpp",
    ".rb": "ruby",
    ".php": "php",
    ".scala": "scala", ".sc": "scala",
    ".swift": "swift",
}

# Marker files → language
_MARKER_LANG: Dict[str, str] = {
    "pyproject.toml": "python", "setup.py": "python", "requirements.txt": "python",
    "Pipfile": "python", "poetry.lock": "python",
    "package.json": "javascript", "tsconfig.json": "typescript",
    "go.mod": "go", "go.sum": "go",
    "Cargo.toml": "rust", "Cargo.lock": "rust",
    "pom.xml": "java", "build.gradle": "java", "build.gradle.kts": "kotlin",
    "Gemfile": "ruby", "Rakefile": "ruby",
    "composer.json": "php",
    "build.sbt": "scala",
    "Package.swift": "swift",
    "*.csproj": "csharp", "*.sln": "csharp",
}

# Framework detection via dependency manifests
_PY_FRAMEWORKS = {
    "fastapi": "fastapi", "flask": "flask", "django": "django",
    "starlette": "starlette", "tornado": "tornado",
    "pytest": "pytest", "unittest": "unittest",
}

_JS_FRAMEWORKS = {
    "react": "react", "next": "nextjs", "vue": "vue", "nuxt": "nuxt",
    "svelte": "svelte", "angular": "angular", "express": "express",
    "fastify": "fastify", "hono": "hono", "nestjs": "nestjs",
    "jest": "jest", "vitest": "vitest", "mocha": "mocha",
    "@playwright/test": "playwright", "cypress": "cypress",
}

# Existing tool configuration detection
_TOOL_CONFIGS: Dict[str, str] = {
    ".eslintrc": "eslint", ".eslintrc.js": "eslint", ".eslintrc.json": "eslint",
    ".eslintrc.yml": "eslint", "eslint.config.js": "eslint", "eslint.config.mjs": "eslint",
    ".prettierrc": "prettier", ".prettierrc.json": "prettier",
    "biome.json": "biome", "biome.jsonc": "biome",
    "ruff.toml": "ruff",
    ".mypy.ini": "mypy", "mypy.ini": "mypy",
    "pyrightconfig.json": "pyright",
    "tsconfig.json": "tsc",
    ".checkov.yml": "checkov", ".checkov.yaml": "checkov",
    "trivy.yaml": "trivy",
    ".semgrepignore": "semgrep",
}


class ProjectContext:
    """Detected project context - languages, frameworks, existing tools."""

    def __init__(self, project_root: Path):
        self.root = project_root
        self.languages: Set[str] = set()
        self.frameworks: Set[str] = set()
        self.existing_tools: Set[str] = set()
        self.has_dockerfile = False
        self.has_iac = False
        self.has_tests = False
        self._detect()

    def _detect(self) -> None:
        """Run all detection heuristics."""
        self._detect_languages()
        self._detect_frameworks()
        self._detect_tools()
        self._detect_infrastructure()

    def _detect_languages(self) -> None:
        # Marker files (fast check)
        for marker, lang in _MARKER_LANG.items():
            if (self.root / marker).exists():
                self.languages.add(lang)

        # File extensions (sample up to 200 files)
        count = 0
        for fpath in self.root.rglob("*"):
            if count > 200:
                break
            if fpath.is_file() and fpath.suffix in _EXT_LANG:
                parts = fpath.relative_to(self.root).parts
                if any(d in parts for d in ("node_modules", ".git", "dist", "build", ".venv", "venv")):
                    continue
                self.languages.add(_EXT_LANG[fpath.suffix])
                count += 1

    def _detect_frameworks(self) -> None:
        # Python
        if "python" in self.languages:
            for req_file in ("requirements.txt", "pyproject.toml", "Pipfile"):
                path = self.root / req_file
                if path.is_file():
                    try:
                        content = path.read_text(errors="replace").lower()
                        for pkg, fw in _PY_FRAMEWORKS.items():
                            if pkg in content:
                                self.frameworks.add(fw)
                    except Exception:
                        pass

        # JavaScript/TypeScript
        pkg_json = self.root / "package.json"
        if pkg_json.is_file():
            try:
                import json
                data = json.loads(pkg_json.read_text())
                all_deps = {**data.get("dependencies", {}), **data.get("devDependencies", {})}
                for pkg, fw in _JS_FRAMEWORKS.items():
                    if pkg in all_deps:
                        self.frameworks.add(fw)
            except Exception:
                pass

        # Test detection
        test_markers = ("test_", "_test.", ".test.", ".spec.", "tests/", "__tests__/")
        for fpath in self.root.rglob("*"):
            if fpath.is_file() and any(m in fpath.name.lower() for m in test_markers):
                self.has_tests = True
                break

    def _detect_tools(self) -> None:
        for config_file, tool in _TOOL_CONFIGS.items():
            if (self.root / config_file).exists():
                self.existing_tools.add(tool)

        # Check pyproject.toml for tool sections
        pyproject = self.root / "pyproject.toml"
        if pyproject.is_file():
            try:
                content = pyproject.read_text()
                if "[tool.ruff" in content:
                    self.existing_tools.add("ruff")
                if "[tool.mypy" in content:
                    self.existing_tools.add("mypy")
                if "[tool.pytest" in content:
                    self.existing_tools.add("pytest")
            except Exception:
                pass

    def _detect_infrastructure(self) -> None:
        iac_patterns = (".tf", ".tfvars", ".hcl")
        for fpath in self.root.rglob("*"):
            if not fpath.is_file():
                continue
            name = fpath.name.lower()
            if name == "dockerfile" or name.startswith("dockerfile.") or name.endswith(".dockerfile"):
                self.has_dockerfile = True
            if name in ("docker-compose.yml", "docker-compose.yaml"):
                self.has_dockerfile = True
            if fpath.suffix in iac_patterns:
                self.has_iac = True
            if self.has_dockerfile and self.has_iac:
                break

    @property
    def has_python(self) -> bool:
        return "python" in self.languages

    @property
    def has_javascript(self) -> bool:
        return "javascript" in self.languages or "typescript" in self.languages

    @property
    def has_go(self) -> bool:
        return "go" in self.languages

    @property
    def has_rust(self) -> bool:
        return "rust" in self.languages

    @property
    def primary_language(self) -> str:
        """Best guess at the project's primary language."""
        if "typescript" in self.languages:
            return "typescript"
        if "javascript" in self.languages:
            return "javascript"
        if "python" in self.languages:
            return "python"
        if self.languages:
            return sorted(self.languages)[0]
        return "unknown"

    def recommended_domains(self) -> List[str]:
        """Return domain names that should be enabled for this project.

        Only recommends domains that are actually registered in the scanner.
        """
        domains = ["security"]  # always

        if self.languages:
            domains.append("lint")
            domains.append("sast")

        if self.has_python or "typescript" in self.languages:
            domains.append("typecheck")

        # Dependency scanning for any language with manifests
        if any((self.root / f).exists() for f in (
            "package.json", "requirements.txt", "Cargo.toml", "go.sum",
            "Gemfile.lock", "composer.lock",
        )):
            domains.append("sca")

        if self.has_dockerfile:
            domains.append("container")

        if self.has_iac:
            domains.append("iac")

        return domains

    def summary(self) -> Dict:
        return {
            "languages": sorted(self.languages),
            "frameworks": sorted(self.frameworks),
            "existing_tools": sorted(self.existing_tools),
            "has_dockerfile": self.has_dockerfile,
            "has_iac": self.has_iac,
            "has_tests": self.has_tests,
            "primary_language": self.primary_language,
            "recommended_domains": self.recommended_domains(),
        }
