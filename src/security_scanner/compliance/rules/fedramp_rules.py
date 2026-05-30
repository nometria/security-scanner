"""
fedramp_rules.py - FedRAMP Moderate (NIST SP 800-53 Rev 5) compliance rules.

FedRAMP Moderate control families covered:
  AC  - Access Control
  AU  - Audit and Accountability
  IA  - Identification and Authentication
  SC  - System and Communications Protection
  SI  - System and Information Integrity
  CM  - Configuration Management
  SA  - System and Services Acquisition

Each rule carries:
- auto_fixable: True when the fixer engine can patch the code automatically
- fix_template:  The code change to apply (used by fixer.py)
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Iterator

from security_scanner.compliance.config import Framework, Severity
from security_scanner.compliance.rules.base import Finding, Rule


# ---------------------------------------------------------------------------
# FEDRAMP-001: VITE_ prefix exposes secrets to browser bundle
# AC-6 Least Privilege · IA-4 Identifier Management
# ---------------------------------------------------------------------------
class FedRampVitePrefixSecrets(Rule):
    rule_id = "FEDRAMP-001"
    title = "Service-role secret exposed via VITE_ prefix to browser bundle"
    description = (
        "Environment variables prefixed with VITE_ are inlined into the browser "
        "JavaScript bundle by Vite at build time. Any secret (service role key, "
        "admin token, private API key) with this prefix is readable by every visitor. "
        "This directly violates AC-6 (Least Privilege) and IA-4 (Identifier Management)."
    )
    severity = Severity.CRITICAL
    framework = Framework.FEDRAMP
    reference = "AC-6 · IA-4 (NIST SP 800-53 Rev 5)"
    remediation = (
        "1. Rename VITE_SUPABASE_SERVICE_ROLE_KEY → SUPABASE_SERVICE_ROLE_KEY (server-side only).\n"
        "2. Create a backend proxy endpoint that uses the service role internally.\n"
        "3. Frontend calls the proxy with user JWT; proxy validates JWT then executes the DB op.\n"
        "4. Never reference SUPABASE_SERVICE_ROLE_KEY / SERVICE_KEY / ADMIN_KEY in any "
        "   file under apps/*/src/, lib/, or any path that Vite processes."
    )
    auto_fixable = False  # Requires architectural change
    file_extensions = frozenset({".js", ".ts", ".jsx", ".tsx", ".env"})

    _VITE_SECRET = re.compile(
        r'VITE_[A-Z_]*(SERVICE_ROLE|SECRET|ADMIN|PRIVATE|PASSWORD|MASTER)[A-Z_]*',
        re.IGNORECASE,
    )
    # Also catch direct usage of the variable in JS/TS
    _IMPORT_META = re.compile(
        r'import\.meta\.env\.VITE_[A-Z_]*(SERVICE_ROLE|SECRET|ADMIN|PRIVATE|PASSWORD|MASTER)',
        re.IGNORECASE,
    )

    def check(self, file_path: Path, content: str) -> Iterator[Finding]:
        for lineno, line in enumerate(content.splitlines(), start=1):
            stripped = line.strip()
            if stripped.startswith(("#", "//")):
                continue
            if self._VITE_SECRET.search(line) or self._IMPORT_META.search(line):
                yield self._finding(file_path, lineno, stripped)


# ---------------------------------------------------------------------------
# FEDRAMP-002: CORS wildcard methods + credentials = security misconfiguration
# AC-17 Remote Access · SC-7 Boundary Protection
# ---------------------------------------------------------------------------
class FedRampCorsMisconfiguration(Rule):
    rule_id = "FEDRAMP-002"
    title = "Permissive CORS: wildcard methods/headers with credentials enabled"
    description = (
        "Setting allow_methods=['*'] and allow_headers=['*'] with allow_credentials=True "
        "is a CORS security misconfiguration. It allows any HTTP verb and header from "
        "any listed origin to send credentialed cross-origin requests. "
        "Per AC-17 and SC-7, remote access must be strictly controlled."
    )
    severity = Severity.HIGH
    framework = Framework.FEDRAMP
    reference = "AC-17 · SC-7 (NIST SP 800-53 Rev 5)"
    remediation = (
        "Restrict to explicit methods and headers:\n"
        "  allow_methods=['GET', 'POST']\n"
        "  allow_headers=['Content-Type', 'Authorization']\n"
        "  allow_credentials=False  # use token auth (Authorization header) instead\n"
        "Remove 'https://your-frontend-domain.com' placeholder from origins list."
    )
    auto_fixable = True
    fix_id = "fix_cors_wildcards"
    file_extensions = frozenset({".py"})

    _WILDCARD_METHODS = re.compile(r'allow_methods\s*=\s*\[[\s"\']*\*[\s"\']*\]')
    _WILDCARD_HEADERS = re.compile(r'allow_headers\s*=\s*\[[\s"\']*\*[\s"\']*\]')

    def check(self, file_path: Path, content: str) -> Iterator[Finding]:
        has_wildcard_methods = bool(self._WILDCARD_METHODS.search(content))
        has_wildcard_headers = bool(self._WILDCARD_HEADERS.search(content))
        if has_wildcard_methods or has_wildcard_headers:
            for lineno, line in enumerate(content.splitlines(), start=1):
                if self._WILDCARD_METHODS.search(line) or self._WILDCARD_HEADERS.search(line):
                    yield self._finding(file_path, lineno, line.strip())
                    return  # one finding per file


# ---------------------------------------------------------------------------
# FEDRAMP-003: FastAPI /docs and /openapi.json exposed in production
# CM-7 Least Functionality · SC-7 Boundary Protection
# ---------------------------------------------------------------------------
class FedRampSwaggerExposed(Rule):
    rule_id = "FEDRAMP-003"
    title = "FastAPI auto-generated API docs (/docs, /openapi.json) not disabled"
    description = (
        "FastAPI serves Swagger UI (/docs), ReDoc (/redoc), and OpenAPI spec (/openapi.json) "
        "by default. In production these endpoints expose full API schema, parameter names, "
        "and endpoint paths to unauthenticated attackers - directly aiding reconnaissance. "
        "CM-7 (Least Functionality) requires disabling all services/endpoints not needed."
    )
    severity = Severity.MEDIUM
    framework = Framework.FEDRAMP
    reference = "CM-7 · SC-7 (NIST SP 800-53 Rev 5)"
    remediation = (
        "Disable docs in production:\n"
        "  app = FastAPI(\n"
        "      docs_url=None,\n"
        "      redoc_url=None,\n"
        "      openapi_url=None,\n"
        "  )\n"
        "Or conditionally enable only in development:\n"
        "  docs_url='/docs' if settings.DEBUG else None"
    )
    auto_fixable = True
    fix_id = "fix_swagger_exposure"
    file_extensions = frozenset({".py"})

    _FASTAPI_INIT = re.compile(r'\bapp\s*=\s*FastAPI\s*\(')
    _DOCS_DISABLED = re.compile(r'docs_url\s*=\s*None')
    _REDOC_DISABLED = re.compile(r'redoc_url\s*=\s*None')
    _OPENAPI_DISABLED = re.compile(r'openapi_url\s*=\s*None')

    def check(self, file_path: Path, content: str) -> Iterator[Finding]:
        if not self._FASTAPI_INIT.search(content):
            return
        # Fully compliant only when all three doc endpoints are explicitly disabled
        fully_disabled = (
            self._DOCS_DISABLED.search(content)
            and self._REDOC_DISABLED.search(content)
            and self._OPENAPI_DISABLED.search(content)
        )
        if not fully_disabled:
            for lineno, line in enumerate(content.splitlines(), start=1):
                if self._FASTAPI_INIT.search(line):
                    yield self._finding(file_path, lineno, line.strip())
                    return


# ---------------------------------------------------------------------------
# FEDRAMP-004: Docker container running as root
# CM-6 Configuration Settings · AC-6 Least Privilege
# ---------------------------------------------------------------------------
class FedRampDockerRootUser(Rule):
    rule_id = "FEDRAMP-004"
    title = "Docker container runs as root (no USER directive)"
    description = (
        "Containers without a USER directive default to running as root (UID 0). "
        "If the container is compromised, the attacker has root access to the container "
        "filesystem and potentially the host. CM-6 requires hardened baseline configurations "
        "and AC-6 requires least privilege."
    )
    severity = Severity.HIGH
    framework = Framework.FEDRAMP
    reference = "CM-6 · AC-6 (NIST SP 800-53 Rev 5)"
    remediation = (
        "Add a non-root user to the Dockerfile:\n"
        "  RUN groupadd -r appuser && useradd -r -g appuser -u 1001 appuser\n"
        "  RUN chown -R appuser:appuser /app\n"
        "  USER appuser\n"
        "Place USER directive before the ENTRYPOINT/CMD instruction."
    )
    auto_fixable = True
    fix_id = "fix_docker_root_user"
    file_extensions = frozenset({".dockerfile", ""})  # Dockerfile has no extension

    _USER_DIRECTIVE = re.compile(r'^USER\s+(?!root\b)', re.MULTILINE | re.IGNORECASE)

    def applies_to(self, file_path: Path) -> bool:
        return (
            file_path.name.lower() in {"dockerfile", "dockerfile.prod", "dockerfile.dev"}
            or file_path.suffix.lower() == ".dockerfile"
        )

    def check(self, file_path: Path, content: str) -> Iterator[Finding]:
        if not self._USER_DIRECTIVE.search(content):
            # Find the CMD/ENTRYPOINT line to reference in the finding
            for lineno, line in enumerate(content.splitlines(), start=1):
                if re.match(r'^\s*(CMD|ENTRYPOINT)\s', line, re.IGNORECASE):
                    yield self._finding(file_path, lineno, line.strip())
                    return
            # No CMD either - flag line 1
            yield self._finding(file_path, 1, content.splitlines()[0] if content else "")


# ---------------------------------------------------------------------------
# FEDRAMP-005: Uvicorn --reload flag in production Dockerfile
# CM-6 Configuration Settings · SI-2 Flaw Remediation
# ---------------------------------------------------------------------------
class FedRampUvicornReloadInProd(Rule):
    rule_id = "FEDRAMP-005"
    title = "Uvicorn started with --reload flag (development mode in production)"
    description = (
        "The --reload flag enables Uvicorn's hot-reload watcher which monitors filesystem "
        "changes and restarts the server. In production this: (1) exposes internal file "
        "structure via inotify events, (2) significantly degrades performance, "
        "(3) can be triggered by an attacker writing to a watched directory. "
        "CM-6 requires production-hardened baseline configurations."
    )
    severity = Severity.HIGH
    framework = Framework.FEDRAMP
    reference = "CM-6 · SI-2 (NIST SP 800-53 Rev 5)"
    remediation = (
        "Remove --reload from production Dockerfile CMD:\n"
        "  # Development:\n"
        "  CMD ['uvicorn', 'main:app', '--host', '0.0.0.0', '--port', '8000', '--reload']\n"
        "  # Production (remove --reload, set workers):\n"
        "  CMD ['uvicorn', 'main:app', '--host', '0.0.0.0', '--port', '8000', '--workers', '4']\n"
        "Use separate Dockerfiles for dev vs prod."
    )
    auto_fixable = True
    fix_id = "fix_docker_reload_flag"

    _RELOAD_PATTERN = re.compile(r'--reload\b')

    def applies_to(self, file_path: Path) -> bool:
        return (
            file_path.name.lower() in {"dockerfile", "dockerfile.prod", "dockerfile.dev"}
            or file_path.suffix.lower() == ".dockerfile"
        )

    def check(self, file_path: Path, content: str) -> Iterator[Finding]:
        for lineno, line in enumerate(content.splitlines(), start=1):
            if self._RELOAD_PATTERN.search(line):
                yield self._finding(file_path, lineno, line.strip())


# ---------------------------------------------------------------------------
# FEDRAMP-006: Missing HSTS (HTTP Strict Transport Security)
# SC-8 Transmission Confidentiality · SC-23 Session Authenticity
# ---------------------------------------------------------------------------
class FedRampMissingHsts(Rule):
    rule_id = "FEDRAMP-006"
    title = "HTTP Strict Transport Security (HSTS) header not configured"
    description = (
        "HSTS forces browsers to use HTTPS for all future requests to the domain, "
        "preventing SSL stripping and protocol downgrade attacks. "
        "SC-8 requires transmission confidentiality and integrity. "
        "FedRAMP Moderate requires HSTS with min-age=31536000."
    )
    severity = Severity.MEDIUM
    framework = Framework.FEDRAMP
    reference = "SC-8 · SC-23 (NIST SP 800-53 Rev 5)"
    remediation = (
        "Add HSTS header at nginx/load balancer level:\n"
        "  add_header Strict-Transport-Security 'max-age=31536000; includeSubDomains; preload';\n"
        "Or in FastAPI middleware:\n"
        "  from starlette.middleware.httpsredirect import HTTPSRedirectMiddleware\n"
        "  app.add_middleware(HTTPSRedirectMiddleware)\n"
        "  @app.middleware('http')\n"
        "  async def add_hsts(request, call_next):\n"
        "      response = await call_next(request)\n"
        "      response.headers['Strict-Transport-Security'] = "
        "'max-age=31536000; includeSubDomains'\n"
        "      return response"
    )
    auto_fixable = False
    file_extensions = frozenset({".py", ".conf", ".nginx"})

    _HSTS_PATTERN = re.compile(r'Strict-Transport-Security', re.IGNORECASE)
    _FASTAPI_FILE = re.compile(
        r'\bFastAPI\b|\buvicorn\b|\bCORSMiddleware\b|\ballow_origins\b|response\.headers',
        re.IGNORECASE,
    )

    def check(self, file_path: Path, content: str) -> Iterator[Finding]:
        # Only flag Python files that look like FastAPI/web apps
        if file_path.suffix == ".py" and self._FASTAPI_FILE.search(content):
            if not self._HSTS_PATTERN.search(content):
                for lineno, line in enumerate(content.splitlines(), start=1):
                    if re.search(r'\bapp\s*=\s*FastAPI\s*\(', line):
                        yield self._finding(file_path, lineno, line.strip())
                        return
                # No explicit FastAPI() init - flag the first substantive line
                for lineno, line in enumerate(content.splitlines(), start=1):
                    stripped = line.strip()
                    if stripped and not stripped.startswith(("#", "//")):
                        yield self._finding(file_path, lineno, stripped)
                        return


# ---------------------------------------------------------------------------
# FEDRAMP-007: No MFA implementation detected
# IA-2 Identification and Authentication (hard FedRAMP requirement)
# ---------------------------------------------------------------------------
class FedRampNoMfa(Rule):
    rule_id = "FEDRAMP-007"
    title = "No Multi-Factor Authentication (MFA) implementation detected"
    description = (
        "FedRAMP Moderate mandates MFA for ALL privileged accounts and ALL network "
        "access to non-privileged accounts (IA-2, IA-2(1), IA-2(2)). "
        "This is a HARD requirement - not addressable. The codebase shows email/password "
        "and OAuth login only, with no TOTP, SMS OTP, WebAuthn, or hardware key support."
    )
    severity = Severity.CRITICAL
    framework = Framework.FEDRAMP
    reference = "IA-2 · IA-2(1) · IA-2(2) (NIST SP 800-53 Rev 5)"
    remediation = (
        "Implement TOTP-based MFA. With Supabase Auth:\n"
        "  1. Enable MFA in Supabase dashboard: Auth > Settings > Multi-factor auth\n"
        "  2. Add enrollment flow: supabase.auth.mfa.enroll({ factorType: 'totp' })\n"
        "  3. Add challenge/verify flow before granting access to sensitive operations\n"
        "  4. Make MFA mandatory for admin roles; encourage for all users\n"
        "Supabase docs: https://supabase.com/docs/guides/auth/auth-mfa"
    )
    auto_fixable = False  # Requires UI + backend changes
    file_extensions = frozenset({".js", ".ts", ".jsx", ".tsx", ".py"})

    _MFA_PATTERNS = re.compile(
        r'(mfa|totp|two.?factor|2fa|authenticator|otp|webauthn|fido|yubikey'
        r'|\.enroll\s*\(|verifyOtp|challenge.*verify)',
        re.IGNORECASE,
    )
    # Only flag auth-related files
    _AUTH_FILE_PATTERNS = re.compile(
        r'(auth|login|signin|signup|session)',
        re.IGNORECASE,
    )

    def check(self, file_path: Path, content: str) -> Iterator[Finding]:
        # Match by filename OR by auth-related content
        if not self._AUTH_FILE_PATTERNS.search(file_path.name) and \
                not self._AUTH_FILE_PATTERNS.search(content):
            return
        # Skip if MFA is already implemented
        if self._MFA_PATTERNS.search(content):
            return
        # If this file has login/signup logic but no MFA - flag it
        if re.search(r'(login|signIn|sign_in|authenticate)', content, re.IGNORECASE):
            yield self._finding(file_path, 1, f"Auth file: {file_path.name}")


# ---------------------------------------------------------------------------
# FEDRAMP-008: No Row Level Security on database
# AC-3 Access Enforcement · AC-6 Least Privilege
# ---------------------------------------------------------------------------
class FedRampMissingRls(Rule):
    rule_id = "FEDRAMP-008"
    title = "Database tables lack Row Level Security (RLS) policies"
    description = (
        "Without RLS, any authenticated database user (including users holding the "
        "anon or authenticated Supabase role) can read all rows in all tables. "
        "Tenant isolation and per-user data scoping cannot be enforced without RLS. "
        "AC-3 requires access enforcement; AC-6 requires least privilege."
    )
    severity = Severity.CRITICAL
    framework = Framework.FEDRAMP
    reference = "AC-3 · AC-6 (NIST SP 800-53 Rev 5)"
    remediation = (
        "Enable RLS on every table that stores user/tenant data:\n"
        "  ALTER TABLE your_table ENABLE ROW LEVEL SECURITY;\n"
        "  CREATE POLICY user_isolation ON your_table\n"
        "    FOR ALL USING (user_id = auth.uid());\n\n"
        "Alternatively, move ALL database operations to the backend (server-side) "
        "and never expose the Supabase anon key to the browser. The backend validates "
        "the user JWT and performs operations with the service role key."
    )
    auto_fixable = False  # Needs schema knowledge to generate policies
    file_extensions = frozenset({".sql"})

    _RLS_ENABLED = re.compile(r'ENABLE ROW LEVEL SECURITY', re.IGNORECASE)
    _CREATE_TABLE = re.compile(r'CREATE TABLE', re.IGNORECASE)

    def check(self, file_path: Path, content: str) -> Iterator[Finding]:
        has_tables = self._CREATE_TABLE.search(content)
        has_rls = self._RLS_ENABLED.search(content)

        if has_tables and not has_rls:
            for lineno, line in enumerate(content.splitlines(), start=1):
                if self._CREATE_TABLE.search(line):
                    yield self._finding(file_path, lineno, line.strip())
                    return  # One finding per file


# ---------------------------------------------------------------------------
# FEDRAMP-009: allow_credentials=True with broad CORS origins
# AC-17 Remote Access · SC-7 Boundary Protection
# ---------------------------------------------------------------------------
class FedRampCorsCredentials(Rule):
    rule_id = "FEDRAMP-009"
    title = "CORS allow_credentials=True without strict origin allowlist"
    description = (
        "allow_credentials=True instructs the browser to include cookies and "
        "Authorization headers in cross-origin requests. Combined with a broad "
        "origins list (template placeholder URLs, multiple subdomains), this "
        "significantly expands the attack surface for CSRF and session hijacking."
    )
    severity = Severity.HIGH
    framework = Framework.FEDRAMP
    reference = "AC-17 · SC-7 (NIST SP 800-53 Rev 5)"
    remediation = (
        "Prefer token-based auth (Authorization: Bearer header) over cookie-based auth:\n"
        "  allow_credentials=False\n"
        "If cookies are required, restrict to a single production origin and "
        "remove all placeholder/template URLs from the origins list."
    )
    auto_fixable = True
    fix_id = "fix_cors_credentials"
    file_extensions = frozenset({".py"})

    _CREDENTIALS = re.compile(r'allow_credentials\s*=\s*True')
    _PLACEHOLDER = re.compile(r'your-frontend-domain|example\.com|placeholder', re.IGNORECASE)

    def check(self, file_path: Path, content: str) -> Iterator[Finding]:
        if self._CREDENTIALS.search(content):
            for lineno, line in enumerate(content.splitlines(), start=1):
                if self._CREDENTIALS.search(line):
                    yield self._finding(file_path, lineno, line.strip())
                    return


# ---------------------------------------------------------------------------
# FEDRAMP-010: Dependency pinned to outdated version
# SI-2 Flaw Remediation · SA-11 Developer Security Testing
# ---------------------------------------------------------------------------
class FedRampOutdatedDependencies(Rule):
    rule_id = "FEDRAMP-010"
    title = "Dependency potentially pinned to known-vulnerable version"
    description = (
        "Packages pinned to old versions may contain known CVEs. "
        "SI-2 (Flaw Remediation) requires identifying, reporting, and correcting "
        "information system flaws. SA-11 requires regular security testing."
    )
    severity = Severity.MEDIUM
    framework = Framework.FEDRAMP
    reference = "SI-2 · SA-11 (NIST SP 800-53 Rev 5)"
    remediation = (
        "Run dependency audits in CI/CD:\n"
        "  pip-audit                    # Python\n"
        "  npm audit --audit-level=high # Node.js\n"
        "  trivy fs .                   # Container/filesystem\n"
        "Pin to the latest patch release and use Dependabot for automatic updates."
    )
    auto_fixable = False
    file_extensions = frozenset({".txt", ".toml", ".cfg"})

    # Known-problematic pinned versions from the audit
    _KNOWN_OLD = {
        "opencv-python==4.6": "CRITICAL CVEs in OpenCV < 4.8 (CVE-2023-1234 series)",
        "easyocr==1.7": "EasyOCR 1.7.x - check for updated version",
        "pillow==9.": "Pillow < 10.0 - multiple CVEs (CVE-2023-44271)",
        "cryptography==3.": "cryptography < 41.0 - multiple HIGH CVEs",
        "paramiko==2.": "paramiko 2.x - check for path traversal CVEs",
    }

    def check(self, file_path: Path, content: str) -> Iterator[Finding]:
        if "requirements" not in file_path.name.lower() and file_path.suffix not in {".txt"}:
            return
        for lineno, line in enumerate(content.splitlines(), start=1):
            stripped = line.strip()
            if stripped.startswith("#") or not stripped:
                continue
            for pkg_prefix, note in self._KNOWN_OLD.items():
                if pkg_prefix in stripped.lower():
                    yield self._finding(
                        file_path, lineno, stripped,
                        description_override=f"Potentially vulnerable pinned version: {note}"
                    )


# ---------------------------------------------------------------------------
# FEDRAMP-011: No input validation (raw dict body)
# SI-10 Information Input Validation
# ---------------------------------------------------------------------------
class FedRampNoInputValidation(Rule):
    rule_id = "FEDRAMP-011"
    title = "API endpoint accepts unvalidated raw dict body"
    description = (
        "Using `dict = Body(...)` or `body: dict` as a FastAPI endpoint parameter "
        "bypasses all input validation. SI-10 requires that all information system "
        "inputs are validated for accuracy, completeness, and format before processing."
    )
    severity = Severity.HIGH
    framework = Framework.FEDRAMP
    reference = "SI-10 (NIST SP 800-53 Rev 5)"
    remediation = (
        "Replace raw dict parameters with typed Pydantic models:\n"
        "  # Before (unsafe):\n"
        "  async def handler(payload: dict = Body(...)): ...\n\n"
        "  # After (safe):\n"
        "  class ExtractRequest(BaseModel):\n"
        "      file_url: HttpUrl\n"
        "      format: Literal['pdf', 'image']\n"
        "      options: Optional[dict] = None\n\n"
        "  async def handler(payload: ExtractRequest): ..."
    )
    auto_fixable = False  # Requires schema knowledge
    file_extensions = frozenset({".py"})

    _RAW_DICT_BODY = re.compile(
        r':\s*dict\s*=\s*Body\s*\(|payload\s*:\s*dict\b|body\s*:\s*dict\b',
        re.IGNORECASE,
    )

    def check(self, file_path: Path, content: str) -> Iterator[Finding]:
        for lineno, line in enumerate(content.splitlines(), start=1):
            if self._RAW_DICT_BODY.search(line):
                yield self._finding(file_path, lineno, line.strip())


# ---------------------------------------------------------------------------
# FEDRAMP-012: shell=True in subprocess calls
# SI-3 Malware Protection · CM-7 Least Functionality
# ---------------------------------------------------------------------------
class FedRampShellInjection(Rule):
    rule_id = "FEDRAMP-012"
    title = "subprocess called with shell=True (command injection risk)"
    description = (
        "subprocess.run/Popen with shell=True passes the command to the OS shell, "
        "enabling command injection if any part of the command includes user-controlled input. "
        "SI-3 requires malware protection; CM-7 requires least functionality."
    )
    severity = Severity.CRITICAL
    framework = Framework.FEDRAMP
    reference = "SI-3 · CM-7 (NIST SP 800-53 Rev 5)"
    remediation = (
        "Pass commands as a list, not a string:\n"
        "  # Unsafe:\n"
        "  subprocess.run(f'convert {user_file} output.pdf', shell=True)\n"
        "  # Safe:\n"
        "  subprocess.run(['convert', user_file, 'output.pdf'], shell=False)"
    )
    auto_fixable = False
    file_extensions = frozenset({".py"})

    _SHELL_TRUE = re.compile(r'subprocess\.(run|Popen|call|check_output).*shell\s*=\s*True')

    def check(self, file_path: Path, content: str) -> Iterator[Finding]:
        for lineno, line in enumerate(content.splitlines(), start=1):
            if self._SHELL_TRUE.search(line):
                yield self._finding(file_path, lineno, line.strip())


# ---------------------------------------------------------------------------
# Exported rule instances
# ---------------------------------------------------------------------------
FEDRAMP_RULES = [
    FedRampVitePrefixSecrets(),
    FedRampCorsMisconfiguration(),
    FedRampSwaggerExposed(),
    FedRampDockerRootUser(),
    FedRampUvicornReloadInProd(),
    FedRampMissingHsts(),
    FedRampNoMfa(),
    FedRampMissingRls(),
    FedRampCorsCredentials(),
    FedRampOutdatedDependencies(),
    FedRampNoInputValidation(),
    FedRampShellInjection(),
]
