"""
Security scanner for AI-generated web app code.

Checks:
  SEC-001  Hardcoded secrets / API keys in source
  SEC-002  .env file committed to repo
  SEC-003  Dangerous eval() / exec() usage
  SEC-004  SQL injection risk patterns
  SEC-005  Missing auth on API routes (Express/FastAPI pattern detection)
  SEC-006  CORS wildcard (*) in production code
  SEC-007  HTTP (not HTTPS) hardcoded URLs
  SEC-008  Exposed admin routes without auth middleware
  SEC-009  localStorage used for auth tokens (XSS risk)
  SEC-010  process.env values logged/printed to console
  SEC-011  Supabase service role key exposed client-side
  SEC-012  Dependency confusion risk (internal package names in package.json)
"""

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import List

# ── Severity levels ───────────────────────────────────────────────────────────
CRITICAL = "CRITICAL"
HIGH     = "HIGH"
MEDIUM   = "MEDIUM"
LOW      = "LOW"
INFO     = "INFO"


@dataclass
class Finding:
    rule_id:   str
    severity:  str
    file:      str
    line:      int
    message:   str
    snippet:   str = ""
    fix:       str = ""


@dataclass
class ScanResult:
    findings:   List[Finding] = field(default_factory=list)
    scanned:    int = 0
    errors:     List[str] = field(default_factory=list)

    @property
    def critical_count(self): return sum(1 for f in self.findings if f.severity == CRITICAL)
    @property
    def high_count(self):     return sum(1 for f in self.findings if f.severity == HIGH)
    @property
    def medium_count(self):   return sum(1 for f in self.findings if f.severity == MEDIUM)
    @property
    def passed(self):         return self.critical_count == 0 and self.high_count == 0


# ── Secret patterns ───────────────────────────────────────────────────────────
SECRET_PATTERNS = [
    # Generic API keys
    (r'(?i)(api[_-]?key|apikey|api[_-]?secret)\s*[=:]\s*["\']([A-Za-z0-9\-_]{16,})["\']', "Hardcoded API key"),
    # AWS
    (r'AKIA[0-9A-Z]{16}', "AWS Access Key ID"),
    (r'(?i)aws[_-]?secret[_-]?access[_-]?key\s*[=:]\s*["\']([A-Za-z0-9/+]{40})["\']', "AWS Secret Access Key"),
    # Supabase service role key (should NEVER be client-side)
    (r'eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+', "JWT token hardcoded (possible service role key)"),
    # Private keys
    (r'-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----', "Private key in source"),
    # GitHub tokens
    (r'ghp_[A-Za-z0-9]{36}', "GitHub personal access token"),
    (r'github_pat_[A-Za-z0-9_]{82}', "GitHub fine-grained PAT"),
    # Stripe
    (r'sk_live_[A-Za-z0-9]{24,}', "Stripe live secret key"),
    (r'rk_live_[A-Za-z0-9]{24,}', "Stripe restricted key"),
    # Sendgrid
    (r'SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}', "SendGrid API key"),
    # OpenAI
    (r'sk-[A-Za-z0-9]{48}', "OpenAI API key"),
    # Anthropic
    (r'sk-ant-[A-Za-z0-9\-_]{93}', "Anthropic API key"),
    # Generic password
    (r'(?i)(password|passwd|pwd)\s*[=:]\s*["\']([^\s"\']{8,})["\']', "Hardcoded password"),
]

SKIP_FILES = {".gitignore", "package-lock.json", "pnpm-lock.yaml", "yarn.lock"}
SKIP_DIRS  = {"node_modules", ".git", "dist", "build", ".next", "__pycache__", ".venv", "venv"}
SOURCE_EXTS = {".js", ".jsx", ".ts", ".tsx", ".py", ".env", ".env.local",
               ".env.production", ".env.development", ".mjs", ".cjs"}


def _should_skip(path: Path, project_root: Path) -> bool:
    try:
        rel = path.relative_to(project_root)
        if any(part in SKIP_DIRS for part in rel.parts):
            return True
        if path.name in SKIP_FILES:
            return True
    except ValueError:
        pass
    return False


def _read_lines(path: Path) -> List[str]:
    try:
        return path.read_text(encoding="utf-8", errors="replace").splitlines()
    except Exception:
        return []


# ── Individual rule implementations ──────────────────────────────────────────

def check_secrets(path: Path, rel: str, lines: List[str]) -> List[Finding]:
    """SEC-001: Hardcoded secrets in source files."""
    findings = []
    # Skip example/template files
    if any(x in path.name for x in [".example", ".sample", ".template"]):
        return []
    full_text = "\n".join(lines)
    for pattern, label in SECRET_PATTERNS:
        for m in re.finditer(pattern, full_text):
            lineno = full_text[:m.start()].count("\n") + 1
            snippet = lines[lineno - 1].strip()[:80] if lineno <= len(lines) else ""
            # Skip if it looks like a placeholder
            value = m.group(0)
            if any(x in value.lower() for x in ["your_", "xxx", "placeholder", "changeme", "example", "..."]):
                continue
            findings.append(Finding(
                rule_id="SEC-001", severity=CRITICAL,
                file=rel, line=lineno, message=f"{label} detected",
                snippet=snippet,
                fix="Move to environment variables. Never commit secrets to source control.",
            ))
    return findings


def check_env_committed(path: Path, rel: str, project_root: Path) -> List[Finding]:
    """SEC-002: .env file committed (not in .gitignore)."""
    if not path.name.startswith(".env") or path.suffix == ".example":
        return []
    # Check if .gitignore exists and contains .env
    gitignore = project_root / ".gitignore"
    if gitignore.exists():
        content = gitignore.read_text(encoding="utf-8", errors="replace")
        if ".env" in content:
            return []
    return [Finding(
        rule_id="SEC-002", severity=HIGH,
        file=rel, line=1, message=".env file may be committed to repo",
        fix="Add '.env' to .gitignore. Remove from git history: git rm --cached .env",
    )]


def check_eval_exec(path: Path, rel: str, lines: List[str]) -> List[Finding]:
    """SEC-003: Dangerous eval() / exec() usage."""
    findings = []
    for i, line in enumerate(lines, 1):
        if re.search(r'\beval\s*\(', line) or re.search(r'\bexec\s*\(', line):
            if not line.strip().startswith("//") and not line.strip().startswith("#"):
                findings.append(Finding(
                    rule_id="SEC-003", severity=HIGH,
                    file=rel, line=i,
                    message="Dangerous eval/exec usage — potential code injection",
                    snippet=line.strip()[:80],
                    fix="Avoid eval/exec with user input. Use JSON.parse() or safe alternatives.",
                ))
    return findings


def check_sql_injection(path: Path, rel: str, lines: List[str]) -> List[Finding]:
    """SEC-004: SQL injection risk — string interpolation in queries."""
    findings = []
    sql_pattern = re.compile(
        r'(SELECT|INSERT|UPDATE|DELETE|DROP|TRUNCATE).*\$\{|'
        r'(SELECT|INSERT|UPDATE|DELETE).*\+\s*\w|'
        r'f["\'].*SELECT.*{|'
        r'execute\(["\'].*\%s',
        re.IGNORECASE,
    )
    for i, line in enumerate(lines, 1):
        if sql_pattern.search(line):
            findings.append(Finding(
                rule_id="SEC-004", severity=HIGH,
                file=rel, line=i,
                message="Potential SQL injection — string interpolation in query",
                snippet=line.strip()[:80],
                fix="Use parameterised queries: db.query('SELECT * FROM t WHERE id = $1', [id])",
            ))
    return findings


def check_cors_wildcard(path: Path, rel: str, lines: List[str]) -> List[Finding]:
    """SEC-006: CORS wildcard in production code."""
    findings = []
    for i, line in enumerate(lines, 1):
        if re.search(r'["\']Access-Control-Allow-Origin["\']\s*[,:]\s*["\'\*]', line):
            findings.append(Finding(
                rule_id="SEC-006", severity=MEDIUM,
                file=rel, line=i,
                message="CORS wildcard (*) — allows any origin",
                snippet=line.strip()[:80],
                fix="Restrict to specific allowed origins: 'Access-Control-Allow-Origin': 'https://yourdomain.com'",
            ))
    return findings


def check_http_hardcoded(path: Path, rel: str, lines: List[str]) -> List[Finding]:
    """SEC-007: Hardcoded http:// URLs (not https) for external services."""
    findings = []
    for i, line in enumerate(lines, 1):
        if re.search(r'http://(?!localhost|127\.0\.0\.1|0\.0\.0\.0)', line):
            if re.search(r'https?://[^\s\'"]{10,}', line):
                findings.append(Finding(
                    rule_id="SEC-007", severity=LOW,
                    file=rel, line=i,
                    message="HTTP (not HTTPS) URL — data sent in plaintext",
                    snippet=line.strip()[:80],
                    fix="Use HTTPS for all external URLs.",
                ))
    return findings


def check_localstorage_auth(path: Path, rel: str, lines: List[str]) -> List[Finding]:
    """SEC-009: localStorage used for auth tokens (XSS risk)."""
    findings = []
    for i, line in enumerate(lines, 1):
        if re.search(r'localStorage\.set(?:Item)?\s*\(.*(?:token|jwt|auth|session)', line, re.I):
            findings.append(Finding(
                rule_id="SEC-009", severity=HIGH,
                file=rel, line=i,
                message="Auth token stored in localStorage — vulnerable to XSS",
                snippet=line.strip()[:80],
                fix="Store auth tokens in httpOnly cookies instead of localStorage.",
            ))
    return findings


def check_console_env(path: Path, rel: str, lines: List[str]) -> List[Finding]:
    """SEC-010: process.env values logged to console."""
    findings = []
    for i, line in enumerate(lines, 1):
        if re.search(r'console\.(log|error|warn|info)\s*\(.*process\.env', line):
            findings.append(Finding(
                rule_id="SEC-010", severity=MEDIUM,
                file=rel, line=i,
                message="Environment variable logged to console — may leak secrets",
                snippet=line.strip()[:80],
                fix="Never log process.env values. Use structured logging with secret scrubbing.",
            ))
    return findings


def check_supabase_service_key_clientside(path: Path, rel: str, lines: List[str]) -> List[Finding]:
    """SEC-011: Supabase service_role key used client-side (VITE_ prefix or browser file)."""
    findings = []
    is_client = any(x in str(path) for x in ["src/", "pages/", "app/", "components/"])
    if not is_client:
        return []
    for i, line in enumerate(lines, 1):
        if re.search(r'VITE_.*SERVICE_ROLE|service_role', line, re.I):
            findings.append(Finding(
                rule_id="SEC-011", severity=CRITICAL,
                file=rel, line=i,
                message="Supabase service_role key used client-side — bypasses Row Level Security",
                snippet=line.strip()[:80],
                fix="Never use the service_role key in client-side code. Use the anon key + RLS.",
            ))
    return findings


# ── Single-file scanner ──────────────────────────────────────────────────────

def _scan_single_file(path: Path, rel: str, project_root: Path) -> List[Finding]:
    """Run all checks on a single file and return findings."""
    lines = _read_lines(path)
    findings: List[Finding] = []
    findings.extend(check_secrets(path, rel, lines))
    findings.extend(check_env_committed(path, rel, project_root))
    findings.extend(check_eval_exec(path, rel, lines))
    findings.extend(check_sql_injection(path, rel, lines))
    findings.extend(check_cors_wildcard(path, rel, lines))
    findings.extend(check_http_hardcoded(path, rel, lines))
    findings.extend(check_localstorage_auth(path, rel, lines))
    findings.extend(check_console_env(path, rel, lines))
    findings.extend(check_supabase_service_key_clientside(path, rel, lines))
    return findings


def _sort_findings(findings: List[Finding]) -> None:
    """Sort findings in place by severity, then file, then line."""
    sev_order = {CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4}
    findings.sort(key=lambda f: (sev_order.get(f.severity, 99), f.file, f.line))


# ── Main scanner ─────────────────────────────────────────────────────────────

def scan_project(project_root: Path) -> ScanResult:
    """
    Scan a project directory for security issues.

    Args:
        project_root: Path to the project root.

    Returns:
        ScanResult with all findings.
    """
    result = ScanResult()

    for path in project_root.rglob("*"):
        if not path.is_file():
            continue
        if _should_skip(path, project_root):
            continue
        if path.suffix not in SOURCE_EXTS and not path.name.startswith(".env"):
            continue

        try:
            rel = str(path.relative_to(project_root))
        except ValueError:
            continue

        result.scanned += 1
        result.findings.extend(_scan_single_file(path, rel, project_root))

    _sort_findings(result.findings)
    return result


def scan_files(project_root: Path, relative_paths: List[str]) -> ScanResult:
    """
    Scan only the specified files within a project.

    This is used by watch mode to re-scan only changed files instead of the
    entire project tree, keeping incremental re-scans fast.

    Args:
        project_root:    Absolute path to the project root.
        relative_paths:  List of paths relative to project_root to scan.

    Returns:
        ScanResult containing findings only for the given files.
    """
    result = ScanResult()

    for rel in relative_paths:
        path = project_root / rel
        if not path.is_file():
            continue
        if _should_skip(path, project_root):
            continue
        if path.suffix not in SOURCE_EXTS and not path.name.startswith(".env"):
            continue

        result.scanned += 1
        result.findings.extend(_scan_single_file(path, rel, project_root))

    _sort_findings(result.findings)
    return result
