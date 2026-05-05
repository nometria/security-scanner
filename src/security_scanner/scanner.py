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
  SEC-013  XSS risk: innerHTML / document.write / dangerouslySetInnerHTML
  SEC-014  Path traversal — unvalidated file paths in sendFile/readFile
  SEC-015  SSRF / Open redirect — user-controlled URLs in fetch/redirect
  SEC-016  NoSQL injection — unsanitised user input in MongoDB queries
  SEC-017  Missing CSRF protection on state-changing routes (CWE-352)
  SEC-018  Deserialization of untrusted data (CWE-502)
  SEC-019  Unrestricted file upload without type validation (CWE-434)
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
    # Extended fields (backward-compatible defaults)
    domain:    str = "security"
    tool:      str = "builtin"
    category:  str = ""
    url:       str = ""


@dataclass
class ScanResult:
    findings:   List[Finding] = field(default_factory=list)
    scanned:    int = 0
    errors:     List[str] = field(default_factory=list)
    domain_results: dict = field(default_factory=dict)

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
    (r'eyJ[A-Za-z0-9\-_]{20,}\.eyJ[A-Za-z0-9\-_]{20,}\.[A-Za-z0-9\-_]{20,}', "JWT token hardcoded (possible service role key)"),
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
# Additional files to always scan regardless of extension
EXTRA_SCAN_FILES = {"package.json"}


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
            if lineno > len(lines):
                continue
            snippet = lines[lineno - 1].strip()[:80]
            # Skip comment lines
            stripped_line = snippet.lstrip()
            if stripped_line.startswith("//") or stripped_line.startswith("#") or stripped_line.startswith("*"):
                continue
            # Skip if it looks like a placeholder
            value = m.group(0)
            if any(x in value.lower() for x in ["your_", "xxx", "placeholder", "changeme",
                                                  "example", "...", "test", "dummy", "sample",
                                                  "fake", "mock"]):
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
    # Check if .gitignore exists and has an active .env pattern
    gitignore = project_root / ".gitignore"
    if gitignore.exists():
        for line in gitignore.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if line.startswith("#") or not line:
                continue
            # Match common .env patterns: .env, .env*, .env.local, etc.
            if line in (".env", ".env*") or line == path.name:
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


def check_missing_auth_middleware(path: Path, rel: str, lines: List[str]) -> List[Finding]:
    """SEC-005: Missing auth on API routes (Express/FastAPI pattern detection)."""
    findings = []
    if path.suffix not in (".js", ".ts", ".mjs", ".cjs", ".py"):
        return []

    # Express: app.get/post/put/delete/patch without auth middleware
    # Exclude Python decorator lines (starts with @)
    express_route = re.compile(
        r'(?<!@)(?:app|router)\.(get|post|put|delete|patch)\s*\(\s*["\']/(api|admin|user|account|payment|order)',
        re.IGNORECASE,
    )
    for i, line in enumerate(lines, 1):
        if line.strip().startswith("@"):
            continue  # Skip Python decorators
        if express_route.search(line):
            # Check if auth middleware is present in the same line or adjacent lines
            context = "\n".join(lines[max(0, i - 2):min(len(lines), i + 1)])
            if not re.search(r'\bauth|\bprotect(?!ed\b)|\bverify|\bguard|\bmiddleware\b|\bisAuthenticated\b|\brequireAuth\b', context, re.I):
                findings.append(Finding(
                    rule_id="SEC-005", severity=HIGH,
                    file=rel, line=i,
                    message="API route may be missing authentication middleware",
                    snippet=line.strip()[:80],
                    fix="Add auth middleware: app.get('/api/...', authMiddleware, handler)",
                ))

    # FastAPI: @app.get/post without Depends(auth)
    fastapi_route = re.compile(r'@(?:app|router)\.(get|post|put|delete|patch)\s*\(\s*["\']/(api|admin|user|account)')
    for i, line in enumerate(lines, 1):
        if fastapi_route.search(line):
            # Check decorator line + next 5 lines for auth dependency
            context = "\n".join(lines[max(0, i - 1):min(len(lines), i + 5)])
            if not re.search(r'Depends|Security|auth|current_user|get_current|verify_token', context, re.I):
                findings.append(Finding(
                    rule_id="SEC-005", severity=HIGH,
                    file=rel, line=i,
                    message="FastAPI route may be missing authentication dependency",
                    snippet=line.strip()[:80],
                    fix="Add auth dependency: @app.get('/api/...') def handler(user=Depends(get_current_user)):",
                ))
    return findings


def check_exposed_admin_routes(path: Path, rel: str, lines: List[str]) -> List[Finding]:
    """SEC-008: Exposed admin routes without auth middleware."""
    findings = []
    if path.suffix not in (".js", ".ts", ".mjs", ".cjs", ".py"):
        return []
    admin_route = re.compile(
        r'(?:app|router)\.(get|post|put|delete|patch)\s*\(\s*["\']/?(?:.*/)?(admin|dashboard|manage|internal)',
        re.IGNORECASE,
    )
    for i, line in enumerate(lines, 1):
        if admin_route.search(line):
            context = "\n".join(lines[max(0, i - 2):min(len(lines), i + 1)])
            # Strip URL strings from context to avoid matching "admin" in the path
            context_no_urls = re.sub(r'["\'][^"\']*["\']', '', context)
            if not re.search(r'\bauth|\bprotect(?!ed\b)|\bguard|\bmiddleware\b|\bisAdmin\b|\brequireAdmin\b|\bcheckRole\b|\bisAuthorized\b', context_no_urls, re.I):
                findings.append(Finding(
                    rule_id="SEC-008", severity=HIGH,
                    file=rel, line=i,
                    message="Admin route may be exposed without authentication",
                    snippet=line.strip()[:80],
                    fix="Add admin auth middleware to protect administrative routes.",
                ))
    return findings


def check_dependency_confusion(path: Path, rel: str, project_root: Path) -> List[Finding]:
    """SEC-012: Dependency confusion risk — internal package names in package.json."""
    findings = []
    if path.name != "package.json":
        return []
    import json as _json
    try:
        data = _json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return []

    all_deps = {
        **data.get("dependencies", {}),
        **data.get("devDependencies", {}),
        **data.get("peerDependencies", {}),
        **data.get("optionalDependencies", {}),
    }

    # Skip workspace protocol dependencies (monorepo internal)
    workspace_deps = {k for k, v in all_deps.items() if isinstance(v, str) and "workspace:" in v}

    # Check for unscoped packages with internal-looking names
    for pkg_name in all_deps:
        if pkg_name in workspace_deps:
            continue
        if not pkg_name.startswith("@") and any(x in pkg_name for x in [
            "-internal", "-private", "-core-", "-infra-",
        ]):
            findings.append(Finding(
                rule_id="SEC-012", severity=MEDIUM,
                file=rel, line=0,
                message=f"Package '{pkg_name}' looks like an internal package — dependency confusion risk",
                snippet=f"{pkg_name}: {all_deps[pkg_name]}",
                fix="Use scoped packages (@org/name) and configure a private registry for internal packages.",
            ))

    # Well-known public scopes (not suspicious)
    _PUBLIC_SCOPES = (
        "@types/", "@babel/", "@testing-library/", "@emotion/", "@tanstack/",
        "@radix-ui/", "@mui/", "@next/", "@prisma/", "@trpc/", "@vitejs/",
        "@sveltejs/", "@angular/", "@nestjs/", "@nuxt/", "@vue/", "@reduxjs/",
        "@storybook/", "@vercel/", "@aws-sdk/", "@google-cloud/", "@azure/",
        "@stripe/", "@sentry/", "@supabase/", "@clerk/", "@auth/",
        "@playwright/", "@jest/", "@eslint/", "@typescript-eslint/",
        "@rollup/", "@esbuild/", "@swc/", "@tailwindcss/", "@headlessui/",
        "@heroicons/", "@fortawesome/", "@fontsource/",
        "@nometria-ai/",
    )

    # Check if .npmrc configures a private registry
    npmrc = project_root / ".npmrc"
    if not npmrc.is_file() and any(p.startswith("@") for p in all_deps):
        scoped = [
            p for p in all_deps
            if p.startswith("@")
            and p not in workspace_deps
            and not p.startswith(_PUBLIC_SCOPES)
        ]
        if scoped:
            findings.append(Finding(
                rule_id="SEC-012", severity=MEDIUM,
                file=rel, line=0,
                message=f"Scoped packages found ({len(scoped)}) but no .npmrc — ensure registry is correct",
                snippet=", ".join(scoped[:5]),
                fix="Create .npmrc with the correct registry for your scoped packages.",
            ))
    return findings



def check_xss(path: Path, rel: str, lines: List[str]) -> List[Finding]:
    """SEC-013: XSS risk — innerHTML, document.write, dangerouslySetInnerHTML, etc."""
    findings = []
    if path.suffix not in (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"):
        return []
    xss_patterns = [
        (r'\.innerHTML\s*=', "innerHTML assignment — XSS risk if value contains user input"),
        (r'\.outerHTML\s*=', "outerHTML assignment — XSS risk if value contains user input"),
        (r'document\.write\s*\(', "document.write() — XSS risk with dynamic content"),
        (r'dangerouslySetInnerHTML', "dangerouslySetInnerHTML — renders raw HTML (XSS risk)"),
        (r'\.insertAdjacentHTML\s*\(', "insertAdjacentHTML — XSS risk with unsanitised HTML"),
    ]
    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        if stripped.startswith("//") or stripped.startswith("*"):
            continue
        for pattern, message in xss_patterns:
            if re.search(pattern, line):
                findings.append(Finding(
                    rule_id="SEC-013", severity=MEDIUM,
                    file=rel, line=i,
                    message=message,
                    snippet=stripped[:80],
                    fix="Use textContent instead of innerHTML. Sanitise HTML with DOMPurify before rendering.",
                ))
                break  # one finding per line
    return findings


def check_path_traversal(path: Path, rel: str, lines: List[str]) -> List[Finding]:
    """SEC-014: Path traversal — unvalidated user input in file operations."""
    findings = []
    if path.suffix not in (".js", ".ts", ".mjs", ".cjs", ".py"):
        return []
    pt_patterns = [
        (r'(?:sendFile|readFile|readFileSync|createReadStream)\s*\(\s*(?:req\.|params|query)', "File operation with unsanitised user input — path traversal risk"),
        (r'(?:sendFile|readFile|readFileSync|createReadStream)\s*\(\s*(?:filePath|file_path|filepath)', "File operation with variable path — verify input is validated"),
    ]
    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        if stripped.startswith("//") or stripped.startswith("#"):
            continue
        for pattern, message in pt_patterns:
            if re.search(pattern, line, re.I):
                findings.append(Finding(
                    rule_id="SEC-014", severity=HIGH,
                    file=rel, line=i,
                    message=message,
                    snippet=stripped[:80],
                    fix="Validate and sanitise file paths. Use path.resolve() and check against a whitelist or base directory.",
                ))
                break
    return findings


def check_ssrf_redirect(path: Path, rel: str, lines: List[str]) -> List[Finding]:
    """SEC-015: SSRF / Open redirect — user-controlled URLs in fetch, redirect, etc."""
    findings = []
    if path.suffix not in (".js", ".ts", ".mjs", ".cjs", ".py"):
        return []
    ssrf_patterns = [
        (r'(?:fetch|axios\.get|axios\.post|http\.get|https\.get|request)\s*\(\s*(?:req\.|params|query)', "Server-Side Request Forgery — fetching user-supplied URL"),
        (r'(?:fetch|axios\.get|axios\.post|http\.get|https\.get|request)\s*\(\s*(?:url|target|endpoint)\b', "Potential SSRF — fetching from variable URL (verify it is validated)"),
    ]
    redirect_patterns = [
        (r'(?:res\.redirect|redirect)\s*\(\s*(?:req\.|params|query)', "Open redirect — redirecting to user-supplied URL"),
        (r'(?:res\.redirect|redirect)\s*\(\s*(?:url|target|next|returnUrl|return_url|callback)\b', "Potential open redirect — redirecting to variable URL (verify validation)"),
    ]
    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        if stripped.startswith("//") or stripped.startswith("#"):
            continue
        for pattern, message in ssrf_patterns:
            if re.search(pattern, line, re.I):
                findings.append(Finding(
                    rule_id="SEC-015", severity=HIGH,
                    file=rel, line=i,
                    message=message,
                    snippet=stripped[:80],
                    fix="Validate URLs against an allowlist of trusted domains. Never fetch arbitrary user-supplied URLs.",
                ))
                break
        for pattern, message in redirect_patterns:
            if re.search(pattern, line, re.I):
                findings.append(Finding(
                    rule_id="SEC-015", severity=MEDIUM,
                    file=rel, line=i,
                    message=message,
                    snippet=stripped[:80],
                    fix="Validate redirect targets against an allowlist. Use relative paths or domain-checked URLs.",
                ))
                break
    return findings


def check_nosql_injection(path: Path, rel: str, lines: List[str]) -> List[Finding]:
    """SEC-016: NoSQL injection — unsanitised user input in MongoDB/Mongoose queries."""
    findings = []
    if path.suffix not in (".js", ".ts", ".mjs", ".cjs", ".py"):
        return []
    nosql_patterns = [
        (r'\.(?:find|findOne|findById|updateOne|updateMany|deleteOne|deleteMany|aggregate|countDocuments)\s*\(\s*\{[^}]*(?:req\.body|req\.query|req\.params)', "NoSQL injection — user input passed directly to MongoDB query"),
        (r'\.(?:find|findOne|findById|updateOne|updateMany|deleteOne|deleteMany)\s*\(\s*(?:req\.body|req\.query)', "NoSQL injection — user input used as query object"),
    ]
    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        if stripped.startswith("//") or stripped.startswith("#"):
            continue
        for pattern, message in nosql_patterns:
            if re.search(pattern, line, re.I):
                findings.append(Finding(
                    rule_id="SEC-016", severity=HIGH,
                    file=rel, line=i,
                    message=message,
                    snippet=stripped[:80],
                    fix="Sanitise user input before passing to MongoDB queries. Use mongo-sanitize or validate input schema.",
                ))
                break
    return findings



def check_csrf(path: Path, rel: str, lines: List[str]) -> List[Finding]:
    """SEC-017: Missing CSRF protection on state-changing routes (CWE-352)."""
    findings = []
    if path.suffix not in (".js", ".ts", ".mjs", ".cjs", ".py"):
        return []
    full_text = "\n".join(lines)

    # Express: POST/PUT/DELETE routes without csrf middleware
    state_change = re.compile(
        r"""(?:app|router)\.(post|put|delete|patch)\s*\(\s*["']/""",
        re.IGNORECASE,
    )
    has_csrf_middleware = bool(re.search(r'\bcsurf\b|\bcsrf\b|\b_csrf\b|\bcsrfProtection\b|\bcsrfToken\b', full_text, re.I))

    has_auth_middleware = bool(re.search(r'\bauth\b|\bverify\b|\bguard\b|\bprotect\b|\bmiddleware\b|\bjwt\b|\bbearer\b', full_text, re.I))
    if not has_csrf_middleware and not has_auth_middleware:
        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith("//") or stripped.startswith("#"):
                continue
            if state_change.search(line):
                # Also skip if auth middleware is on this specific line
                if re.search(r'\bauth\b|\bverify\b|\bguard\b|\bprotect\b|\bmiddleware\b', line, re.I):
                    continue
                findings.append(Finding(
                    rule_id="SEC-017", severity=MEDIUM,
                    file=rel, line=i,
                    message="State-changing route without CSRF protection",
                    snippet=stripped[:80],
                    fix="Add CSRF middleware (csurf) or use SameSite cookies with token-based verification.",
                ))

    # Python: form POST handling without CSRF token
    py_form_post = re.compile(r'@(?:app|router)\.(post|put|delete|patch)\s*\(', re.I)
    has_csrf_py = bool(re.search(r'csrf|CSRFProtect|WTF|csrf_token|CsrfViewMiddleware', full_text))
    if path.suffix == ".py" and not has_csrf_py:
        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            if py_form_post.search(line):
                findings.append(Finding(
                    rule_id="SEC-017", severity=MEDIUM,
                    file=rel, line=i,
                    message="State-changing route without CSRF protection",
                    snippet=stripped[:80],
                    fix="Use CSRF middleware (e.g., Flask-WTF CSRFProtect or Django CsrfViewMiddleware).",
                ))
    return findings


def check_deserialization(path: Path, rel: str, lines: List[str]) -> List[Finding]:
    """SEC-018: Deserialization of untrusted data (CWE-502)."""
    findings = []
    if path.suffix not in (".js", ".ts", ".mjs", ".cjs", ".py"):
        return []
    deser_patterns = [
        # Python pickle
        (r'pickle\.loads?\s*\(', "Unsafe deserialization with pickle — arbitrary code execution risk"),
        (r'pickle\.Unpickler\s*\(', "Unsafe deserialization with pickle.Unpickler — arbitrary code execution risk"),
        (r'cPickle\.loads?\s*\(', "Unsafe deserialization with cPickle — arbitrary code execution risk"),
        (r'shelve\.open\s*\(', "shelve uses pickle internally — arbitrary code execution risk"),
        # Python yaml.load without SafeLoader
        (r'yaml\.load\s*\([^)]*(?!Loader\s*=\s*(?:yaml\.)?SafeLoader)', "yaml.load without SafeLoader — arbitrary code execution risk"),
        # JS unserialize
        (r'(?:unserialize|deserialize)\s*\(\s*(?:req\.|params|query|body)', "Deserialization of user-controlled data — code injection risk"),
        # Node.js node-serialize
        (r'serialize\.unserialize\s*\(', "node-serialize unserialize — known remote code execution vulnerability"),
    ]
    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        if stripped.startswith("//") or stripped.startswith("#"):
            continue
        for pattern, message in deser_patterns:
            if re.search(pattern, line, re.I):
                findings.append(Finding(
                    rule_id="SEC-018", severity=HIGH,
                    file=rel, line=i,
                    message=message,
                    snippet=stripped[:80],
                    fix="Avoid deserializing untrusted data. Use JSON instead of pickle/serialize. For YAML use yaml.safe_load().",
                ))
                break
    return findings


def check_unrestricted_upload(path: Path, rel: str, lines: List[str]) -> List[Finding]:
    """SEC-019: Unrestricted file upload (CWE-434)."""
    findings = []
    if path.suffix not in (".js", ".ts", ".mjs", ".cjs", ".py"):
        return []
    full_text = "\n".join(lines)

    upload_patterns = [
        # Multer without file filter
        (r'multer\s*\(\s*\{[^}]*(?:dest|storage)\s*:', r'fileFilter', "Multer upload without fileFilter — unrestricted file types accepted"),
        # Express file upload without extension check
        (r'req\.files?\b', r'(?:mimetype|extension|ext|allowedTypes|fileFilter|whitelist)', "File upload handler without type validation"),
        # Python Flask/FastAPI file upload without extension check
        (r'(?:request\.files|UploadFile|FileStorage)', r'(?:allowed_extensions|ALLOWED_EXTENSIONS|content_type|secure_filename|filename\.endswith)', "File upload without extension/type validation"),
    ]
    for upload_re, guard_re, message in upload_patterns:
        if re.search(upload_re, full_text, re.I):
            has_guard = bool(re.search(guard_re, full_text, re.I))
            if not has_guard:
                # Find the line where the upload pattern appears
                for i, line in enumerate(lines, 1):
                    stripped = line.strip()
                    if stripped.startswith("//") or stripped.startswith("#"):
                        continue
                    if re.search(upload_re, line, re.I):
                        findings.append(Finding(
                            rule_id="SEC-019", severity=HIGH,
                            file=rel, line=i,
                            message=message,
                            snippet=stripped[:80],
                            fix="Validate file type (extension + MIME type), limit file size, and store outside webroot.",
                        ))
                        break  # one finding per pattern
    return findings


# ── Single-file scanner ──────────────────────────────────────────────────────

def _scan_single_file(path: Path, rel: str, project_root: Path) -> List[Finding]:
    """Run all checks on a single file and return findings."""
    findings: List[Finding] = []

    # JSON files only get dependency-specific checks
    if path.suffix == ".json":
        findings.extend(check_dependency_confusion(path, rel, project_root))
        return findings

    lines = _read_lines(path)
    findings.extend(check_secrets(path, rel, lines))
    findings.extend(check_env_committed(path, rel, project_root))
    findings.extend(check_eval_exec(path, rel, lines))
    findings.extend(check_sql_injection(path, rel, lines))
    findings.extend(check_missing_auth_middleware(path, rel, lines))
    findings.extend(check_cors_wildcard(path, rel, lines))
    findings.extend(check_http_hardcoded(path, rel, lines))
    findings.extend(check_exposed_admin_routes(path, rel, lines))
    findings.extend(check_localstorage_auth(path, rel, lines))
    findings.extend(check_console_env(path, rel, lines))
    findings.extend(check_supabase_service_key_clientside(path, rel, lines))
    findings.extend(check_xss(path, rel, lines))
    findings.extend(check_path_traversal(path, rel, lines))
    findings.extend(check_ssrf_redirect(path, rel, lines))
    findings.extend(check_nosql_injection(path, rel, lines))
    findings.extend(check_csrf(path, rel, lines))
    findings.extend(check_deserialization(path, rel, lines))
    findings.extend(check_unrestricted_upload(path, rel, lines))
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
        if path.suffix not in SOURCE_EXTS and not path.name.startswith(".env") and path.name not in EXTRA_SCAN_FILES:
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
        if path.suffix not in SOURCE_EXTS and not path.name.startswith(".env") and path.name not in EXTRA_SCAN_FILES:
            continue

        result.scanned += 1
        result.findings.extend(_scan_single_file(path, rel, project_root))

    _sort_findings(result.findings)
    return result


# ── Multi-domain scanner ────────────────────────────────────────────────────

def scan_project_v2(project_root: Path, config=None) -> ScanResult:
    """Run one or more scan domains and merge results into a single ScanResult.

    Features:
      - Auto-detects project languages to select relevant domains
      - Parallel domain execution via ThreadPoolExecutor
      - Graceful error handling per domain
      - Quality history tracking when dashboard is enabled

    When *config* is ``None`` (or specifies no domains) only the built-in
    security domain runs — preserving identical behaviour to ``scan_project``.

    Args:
        project_root: Absolute path to the project root.
        config:       Optional ``ScanConfig`` from ``security_scanner.config``.

    Returns:
        A unified ScanResult aggregating findings from every enabled domain.
    """
    from concurrent.futures import ThreadPoolExecutor, as_completed
    from security_scanner.config import load_config
    from security_scanner.domains import discover_domains, get_domain, get_all_domains

    if config is None:
        config = load_config(project_root)

    # Make sure plugins are loaded
    discover_domains()

    # Auto-detect project context for smart domain selection
    project_context = None
    if not config.domains:
        try:
            from security_scanner.detection import ProjectContext
            project_context = ProjectContext(project_root)
        except Exception:
            pass

    # Determine which domains to run
    if config.domains:
        domains = {}
        for name in config.domains:
            d = get_domain(name)
            if d is not None:
                domains[name] = d
    elif project_context:
        # Use auto-detected recommended domains
        recommended = project_context.recommended_domains()
        domains = {}
        for name in recommended:
            d = get_domain(name)
            if d is not None:
                domains[name] = d
    else:
        domains = get_all_domains()

    # Resolve file list based on scan mode
    scan_paths = None  # None = full scan
    if config.scan_mode == "incremental":
        try:
            from security_scanner.git_utils import get_uncommitted_files
            files = get_uncommitted_files(project_root)
            if files:
                scan_paths = [project_root / f for f in files]
        except Exception:
            pass  # fall back to full scan
    elif config.scan_mode == "pr":
        try:
            from security_scanner.git_utils import get_pr_changed_files
            base = config.base_ref or _detect_base_ref()
            files = get_pr_changed_files(project_root, base)
            if files:
                scan_paths = [project_root / f for f in files]
        except Exception:
            pass

    # Filter to available domains (collect unavailable for strict mode)
    available = {}
    unavailable = []
    for name, domain in domains.items():
        if domain.is_available():
            available[name] = domain
        else:
            unavailable.append(name)

    result = ScanResult()

    # Report unavailable domains in strict mode
    for name in unavailable:
        if config.strict:
            result.findings.append(Finding(
                rule_id=f"TOOL-MISSING-{name.upper()}",
                severity=HIGH,
                file="",
                line=0,
                message=f"Domain '{name}' is enabled but its tool is not installed",
                fix=f"Install the required tool or run: security-scan tools install {name}",
                domain=name,
                tool="",
                category="tooling",
            ))

    # Execute domains in parallel (ThreadPoolExecutor)
    def _run_domain(name, domain):
        domain_config = config.tool_overrides.get(name)
        try:
            return name, domain.run(project_root, paths=scan_paths, config=domain_config), None
        except Exception as exc:
            return name, None, exc

    max_workers = min(4, len(available)) if len(available) > 1 else 1
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(_run_domain, name, domain): name
            for name, domain in available.items()
        }
        for future in as_completed(futures):
            name, dr, exc = future.result()
            if exc is not None:
                result.errors.append(f"Domain '{name}' crashed: {exc}")
                result.domain_results[name] = {
                    "tool": name,
                    "version": "",
                    "time": 0,
                    "findings": 0,
                    "passed": False,
                    "error": str(exc),
                }
            else:
                result.findings.extend(dr.findings)
                result.scanned += dr.metadata.get("scanned_files", 0)
                result.errors.extend(dr.errors)
                result.domain_results[name] = {
                    "tool": dr.tool_name,
                    "version": dr.tool_version,
                    "time": dr.execution_time,
                    "findings": len(dr.findings),
                    "passed": dr.passed,
                }

    # Handle missing configured domains in strict mode
    if config.domains and config.strict:
        for name in config.domains:
            if name not in domains and name not in result.domain_results:
                result.findings.append(Finding(
                    rule_id=f"DOMAIN-UNKNOWN-{name.upper()}",
                    severity=HIGH,
                    file="",
                    line=0,
                    message=f"Unknown domain '{name}' specified in configuration",
                    fix="Check your ai-security-scan.yml — valid domains: security, lint, typecheck, sast, sca, iac, container",
                    domain=name,
                    tool="",
                    category="config",
                ))

    _sort_findings(result.findings)
    return result


def _detect_base_ref() -> str:
    """Try to detect a sensible base branch for PR mode."""
    import os
    for var in ("GITHUB_BASE_REF", "CI_MERGE_REQUEST_TARGET_BRANCH_NAME"):
        val = os.environ.get(var)
        if val:
            return val
    return "origin/main"
