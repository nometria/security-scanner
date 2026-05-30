"""
soc2_rules.py - SOC 2 Type II compliance rules.

Covers the five Trust Services Criteria (TSC):
  CC6  - Logical and Physical Access Controls
  CC7  - System Operations & Vulnerability Management
  CC8  - Change Management
  PI1  - Processing Integrity
  C1   - Confidentiality
  P1   - Privacy
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Iterator

from security_scanner.compliance.config import Framework, Severity
from security_scanner.compliance.rules.base import Finding, Rule


# ---------------------------------------------------------------------------
# SOC2-001: No rate limiting on public endpoints
# ---------------------------------------------------------------------------
class Soc2NoRateLimiting(Rule):
    rule_id = "SOC2-001"
    title = "No rate limiting detected on API endpoints"
    description = (
        "Publicly accessible endpoints without rate limiting are vulnerable to "
        "brute-force attacks, credential stuffing, and DoS - violating CC6.1 (Availability)."
    )
    severity = Severity.MEDIUM
    framework = Framework.SOC2
    reference = "CC6.1 - Logical Access Controls"
    remediation = (
        "Add rate limiting middleware (e.g. slowapi for FastAPI, express-rate-limit for Node.js). "
        "Apply per-IP and per-user limits on authentication and sensitive endpoints."
    )
    file_extensions = frozenset({".py", ".js", ".ts"})

    _ROUTE = re.compile(r'@app\.(get|post|put|delete|patch)\s*\(')
    _RATE_LIMIT = re.compile(
        r'RateLimiter|rate_limit|@limiter|slowapi|express-rate-limit|ratelimit'
        r'|throttle|Throttling|RateLimit',
        re.IGNORECASE,
    )

    def check(self, file_path: Path, content: str) -> Iterator[Finding]:
        if not self._ROUTE.search(content):
            return

        # If the whole file has no rate limiting construct, flag the first route
        if not self._RATE_LIMIT.search(content):
            for lineno, line in enumerate(content.splitlines(), start=1):
                if self._ROUTE.search(line):
                    yield self._finding(file_path, lineno, line.strip())
                    return  # One finding per file is enough


# ---------------------------------------------------------------------------
# SOC2-002: Hardcoded AWS / cloud credentials
# ---------------------------------------------------------------------------
class Soc2HardcodedCloudCredentials(Rule):
    rule_id = "SOC2-002"
    title = "Hardcoded cloud provider credentials"
    description = (
        "AWS, GCP, or Azure credentials hardcoded in source code can lead to "
        "unauthorised resource access - violating CC6.1 and C1.1 (Confidentiality)."
    )
    severity = Severity.CRITICAL
    framework = Framework.SOC2
    reference = "CC6.1 - Logical Access Controls / C1.1 - Confidentiality"
    remediation = (
        "Use IAM roles and instance profiles instead of static credentials. "
        "For local dev, use AWS_PROFILE with ~/.aws/credentials. "
        "For CI/CD, use OIDC-based auth (no static keys)."
    )
    file_extensions = frozenset({
        ".py", ".js", ".ts", ".jsx", ".tsx", ".env", ".yaml", ".yml",
    })

    _AWS_KEY = re.compile(r'(?<![A-Z0-9])AKIA[0-9A-Z]{16}(?![A-Z0-9])')
    _AWS_SECRET = re.compile(
        r'(?i)(aws_secret_access_key|aws_secret)\s*[=:]\s*["\']?[A-Za-z0-9+/]{40}["\']?'
    )
    _GCP_KEY = re.compile(r'"private_key"\s*:\s*"-----BEGIN [A-Z]+ PRIVATE KEY-----')
    _AZURE_KEY = re.compile(
        r'(?i)(AccountKey|SharedAccessSignature)\s*[=:]\s*[A-Za-z0-9+/=]{20,}'
    )

    def check(self, file_path: Path, content: str) -> Iterator[Finding]:
        patterns = [self._AWS_KEY, self._AWS_SECRET, self._GCP_KEY, self._AZURE_KEY]
        for lineno, line in enumerate(content.splitlines(), start=1):
            stripped = line.strip()
            if stripped.startswith(("#", "//", "*")):
                continue
            for p in patterns:
                if p.search(line):
                    safe_line = re.sub(r'(["\'])([A-Za-z0-9+/=]{6}).*?(["\'])', r'\1\2***\3', line)
                    yield self._finding(file_path, lineno, safe_line)
                    break


# ---------------------------------------------------------------------------
# SOC2-003: SQL queries with string interpolation (SQLi risk)
# ---------------------------------------------------------------------------
class Soc2SqlInjectionRisk(Rule):
    rule_id = "SOC2-003"
    title = "SQL query built with string interpolation"
    description = (
        "Constructing SQL queries with f-strings or string concatenation is vulnerable "
        "to SQL injection - violating CC7.1 (Vulnerability Management) and PI1.1 (Processing Integrity)."
    )
    severity = Severity.CRITICAL
    framework = Framework.SOC2
    reference = "CC7.1 - Vulnerability Management / PI1.1 - Processing Integrity"
    remediation = (
        "Use parameterised queries or an ORM. "
        "Example (Python): `cursor.execute('SELECT * FROM t WHERE id = %s', (user_id,))` "
        "Never build SQL from user-supplied strings."
    )
    file_extensions = frozenset({".py", ".js", ".ts"})

    _SQL_KEYWORDS = re.compile(
        r'\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC)\b',
        re.IGNORECASE,
    )
    _STRING_INTERP = re.compile(
        r'f["\'].*\{|["\'] *\+|\.format\(|% *["\']|`.*\$\{'
    )

    def check(self, file_path: Path, content: str) -> Iterator[Finding]:
        for lineno, line in enumerate(content.splitlines(), start=1):
            if self._SQL_KEYWORDS.search(line) and self._STRING_INTERP.search(line):
                yield self._finding(file_path, lineno, line.strip())


# ---------------------------------------------------------------------------
# SOC2-004: Missing input validation on API handlers
# ---------------------------------------------------------------------------
class Soc2MissingInputValidation(Rule):
    rule_id = "SOC2-004"
    title = "API handler may lack input validation"
    description = (
        "API endpoint handlers that directly use raw payload data without validation "
        "risk injection attacks and data integrity violations (PI1.1)."
    )
    severity = Severity.MEDIUM
    framework = Framework.SOC2
    reference = "PI1.1 - Processing Integrity"
    remediation = (
        "Use Pydantic models for FastAPI request bodies instead of raw `dict = Body(...)`. "
        "For Node.js, use Zod or Joi for validation before processing."
    )
    file_extensions = frozenset({".py"})

    # Look for endpoints that use raw dict body without Pydantic
    _RAW_BODY = re.compile(r'payload\s*:\s*dict\s*=\s*Body\s*\(')
    _PYDANTIC_MODEL = re.compile(r'class\s+\w+\s*\(\s*(BaseModel|Schema)\s*\)')

    def check(self, file_path: Path, content: str) -> Iterator[Finding]:
        if not self._PYDANTIC_MODEL.search(content):
            for lineno, line in enumerate(content.splitlines(), start=1):
                if self._RAW_BODY.search(line):
                    yield self._finding(file_path, lineno, line.strip())


# ---------------------------------------------------------------------------
# SOC2-005: eval() / exec() usage
# ---------------------------------------------------------------------------
class Soc2EvalUsage(Rule):
    rule_id = "SOC2-005"
    title = "Use of eval() or exec() with dynamic input"
    description = (
        "eval() and exec() with user-supplied input enable arbitrary code execution - "
        "a critical violation of CC7.1 (Vulnerability Management)."
    )
    severity = Severity.CRITICAL
    framework = Framework.SOC2
    reference = "CC7.1 - Vulnerability Management"
    remediation = (
        "Remove all uses of eval()/exec() on user-supplied data. "
        "Use safe alternatives: JSON.parse() for JSON, "
        "ast.literal_eval() for Python literals (never untrusted code)."
    )
    file_extensions = frozenset({".py", ".js", ".ts", ".jsx", ".tsx"})

    _PATTERN = re.compile(r'\b(eval|exec)\s*\(')

    def check(self, file_path: Path, content: str) -> Iterator[Finding]:
        for lineno, line in enumerate(content.splitlines(), start=1):
            stripped = line.strip()
            if stripped.startswith(("#", "//")):
                continue
            if self._PATTERN.search(line):
                yield self._finding(file_path, lineno, stripped)


# ---------------------------------------------------------------------------
# SOC2-006: Sensitive data in client-side storage
# ---------------------------------------------------------------------------
class Soc2SensitiveDataInLocalStorage(Rule):
    rule_id = "SOC2-006"
    title = "Sensitive data stored in localStorage or sessionStorage"
    description = (
        "Storing tokens, session data, or sensitive info in localStorage/sessionStorage "
        "exposes them to XSS attacks - violating C1.1 (Confidentiality)."
    )
    severity = Severity.HIGH
    framework = Framework.SOC2
    reference = "C1.1 - Confidentiality"
    remediation = (
        "Store authentication tokens in HttpOnly cookies instead of localStorage. "
        "For session state, use secure cookie-based sessions with SameSite=Strict."
    )
    file_extensions = frozenset({".js", ".ts", ".jsx", ".tsx"})

    _STORAGE_PATTERN = re.compile(
        r'(localStorage|sessionStorage)\.(setItem|getItem)\s*\(\s*["\']'
        r'(token|access_token|auth_token|password|secret|api_key)',
        re.IGNORECASE,
    )

    def check(self, file_path: Path, content: str) -> Iterator[Finding]:
        for lineno, line in enumerate(content.splitlines(), start=1):
            if self._STORAGE_PATTERN.search(line):
                yield self._finding(file_path, lineno, line.strip())


# ---------------------------------------------------------------------------
# SOC2-007: CORS wildcard origin
# ---------------------------------------------------------------------------
class Soc2CorsWildcard(Rule):
    rule_id = "SOC2-007"
    title = "CORS configured with wildcard origin (*)"
    description = (
        "Using '*' as an allowed CORS origin permits any website to make "
        "cross-origin requests to your API - violating CC6.1 (Access Controls)."
    )
    severity = Severity.HIGH
    framework = Framework.SOC2
    reference = "CC6.1 - Logical Access Controls"
    remediation = (
        "Replace `allow_origins=['*']` with an explicit list of allowed origins. "
        "In FastAPI: `allow_origins=['https://app.example.com']`"
    )
    file_extensions = frozenset({".py", ".js", ".ts"})

    _PATTERN = re.compile(
        r'allow_origins\s*=\s*\[\s*["\']?\*["\']?\s*\]'
        r'|Access-Control-Allow-Origin\s*:\s*\*',
        re.IGNORECASE,
    )

    def check(self, file_path: Path, content: str) -> Iterator[Finding]:
        for lineno, line in enumerate(content.splitlines(), start=1):
            if self._PATTERN.search(line):
                yield self._finding(file_path, lineno, line.strip())


# ---------------------------------------------------------------------------
# Exported rule instances
# ---------------------------------------------------------------------------
SOC2_RULES = [
    Soc2NoRateLimiting(),
    Soc2HardcodedCloudCredentials(),
    Soc2SqlInjectionRisk(),
    Soc2MissingInputValidation(),
    Soc2EvalUsage(),
    Soc2SensitiveDataInLocalStorage(),
    Soc2CorsWildcard(),
]
