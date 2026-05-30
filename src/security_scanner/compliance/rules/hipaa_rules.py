"""
hipaa_rules.py - HIPAA Technical Safeguard compliance rules.

References: 45 CFR Part 164, Subpart C (Technical Safeguards)
  § 164.312(a)(1)  - Access Control
  § 164.312(a)(2)  - Authentication
  § 164.312(b)     - Audit Controls
  § 164.312(c)     - Integrity
  § 164.312(d)     - Person or Entity Authentication
  § 164.312(e)     - Transmission Security
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Iterator

from security_scanner.compliance.config import Framework, Severity
from security_scanner.compliance.rules.base import Finding, Rule


# ---------------------------------------------------------------------------
# HIPAA-001: Hardcoded credentials / secrets
# ---------------------------------------------------------------------------
class HipaaHardcodedCredentials(Rule):
    rule_id = "HIPAA-001"
    title = "Hardcoded credential detected"
    description = (
        "Hardcoded passwords, API keys, or secrets in source code violate "
        "HIPAA's access control requirements and risk unauthorized PHI access."
    )
    severity = Severity.CRITICAL
    framework = Framework.HIPAA
    reference = "§ 164.312(a)(2)(i) - Unique User Identification"
    remediation = (
        "Move all secrets to environment variables or a secrets manager "
        "(e.g. AWS Secrets Manager, HashiCorp Vault). Never commit credentials."
    )
    file_extensions = frozenset({
        ".py", ".js", ".ts", ".jsx", ".tsx",
        ".env", ".yaml", ".yml", ".json", ".sh",
    })

    # Patterns that indicate a credential assignment
    _PATTERNS = [
        # password = "something"
        re.compile(
            r'(?i)(password|passwd|secret|api_key|apikey|token|auth_token|access_token'
            r'|secret_key|private_key|db_password|database_password)\s*[=:]\s*["\'](?!.*\${)(.{4,})["\']',
            re.MULTILINE,
        ),
        # AWS access keys
        re.compile(r'AKIA[0-9A-Z]{16}'),
        # Generic long base64 secret-looking strings assigned to a variable
        re.compile(
            r'(?i)(secret|key|token)\s*[=:]\s*["\'][A-Za-z0-9+/=_\-]{20,}["\']',
            re.MULTILINE,
        ),
        # OpenAI key pattern
        re.compile(r'sk-[A-Za-z0-9\-_]{20,}'),
        # Supabase service role key (JWT) - header can be short, payload must be long
        re.compile(r'eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]{50,}\.[A-Za-z0-9\-_]{20,}'),
    ]

    # Whitelisted values (test/example values that are not real secrets)
    _WHITELIST = {
        "your-secret-here", "changeme", "placeholder",
        "test-secret", "example", "<secret>", "sk-test-fake-key-for-testing-only",
        "test-anon-key", "test-token",
    }

    def check(self, file_path: Path, content: str) -> Iterator[Finding]:
        lines = content.splitlines()
        for lineno, line in enumerate(lines, start=1):
            # Skip comments
            stripped = line.strip()
            if stripped.startswith(("#", "//", "*", "<!--")):
                continue

            for pattern in self._PATTERNS:
                if pattern.search(line):
                    # Skip whitelisted values - use word boundaries to avoid substring
                    # false positives (e.g. "example" inside "akiaiosfodnn7example")
                    lower = line.lower()
                    if any(
                        re.search(r'\b' + re.escape(w) + r'\b', lower)
                        for w in self._WHITELIST
                    ):
                        continue
                    # Redact the actual secret in the output
                    safe_line = re.sub(
                        r'(["\'])([^"\']{4}).*?(["\'])',
                        r'\1\2***REDACTED***\3',
                        line,
                    )
                    yield self._finding(file_path, lineno, safe_line)
                    break  # One finding per line is enough


# ---------------------------------------------------------------------------
# HIPAA-002: PHI in log statements
# ---------------------------------------------------------------------------
class HipaaPhiInLogs(Rule):
    rule_id = "HIPAA-002"
    title = "Potential PHI data in log statement"
    description = (
        "Logging statements that include PHI field names (ssn, dob, patient_id, etc.) "
        "risk exposing protected health information in log files."
    )
    severity = Severity.HIGH
    framework = Framework.HIPAA
    reference = "§ 164.312(b) - Audit Controls"
    remediation = (
        "Remove PHI from log statements. Use anonymized identifiers. "
        "If audit logs are required, store them in a HIPAA-compliant audit trail, "
        "not in application logs."
    )
    file_extensions = frozenset({".py", ".js", ".ts", ".jsx", ".tsx"})

    _PHI_FIELDS = re.compile(
        r'(?i)\b(ssn|social_security|dob|date_of_birth|patient_id|patient_name'
        r'|medical_record|diagnosis|medication|prescription|insurance_id'
        r'|health_plan|beneficiary|medicare|medicaid|hipaa)\b',
    )

    _LOG_CALL = re.compile(
        r'(?i)(print|console\.log|console\.error|console\.warn|logger\.(info|debug|warning|error'
        r'|critical)|logging\.(info|debug|warning|error|critical))\s*\(',
    )

    def check(self, file_path: Path, content: str) -> Iterator[Finding]:
        for lineno, line in enumerate(content.splitlines(), start=1):
            if self._LOG_CALL.search(line) and self._PHI_FIELDS.search(line):
                yield self._finding(file_path, lineno, line.strip())


# ---------------------------------------------------------------------------
# HIPAA-003: Unencrypted HTTP endpoints
# ---------------------------------------------------------------------------
class HipaaUnencryptedHttp(Rule):
    rule_id = "HIPAA-003"
    title = "Unencrypted HTTP endpoint (non-HTTPS)"
    description = (
        "HTTP (non-TLS) endpoints for data transmission violate HIPAA transmission "
        "security requirements. All PHI must be transmitted over encrypted channels."
    )
    severity = Severity.HIGH
    framework = Framework.HIPAA
    reference = "§ 164.312(e)(2)(ii) - Encryption in Transit"
    remediation = (
        "Replace all http:// production URLs with https://. "
        "Use HSTS headers and enforce TLS 1.2+. "
        "HTTP on localhost/127.0.0.1 is acceptable for development only."
    )
    file_extensions = frozenset({
        ".py", ".js", ".ts", ".jsx", ".tsx", ".env", ".yaml", ".yml",
    })

    _HTTP_PATTERN = re.compile(
        r'http://(?!localhost|127\.0\.0\.1|0\.0\.0\.0|::1)',
        re.IGNORECASE,
    )

    def check(self, file_path: Path, content: str) -> Iterator[Finding]:
        for lineno, line in enumerate(content.splitlines(), start=1):
            stripped = line.strip()
            if stripped.startswith(("#", "//", "*")):
                continue
            if self._HTTP_PATTERN.search(line):
                yield self._finding(file_path, lineno, stripped)


# ---------------------------------------------------------------------------
# HIPAA-004: Missing authentication guard
# ---------------------------------------------------------------------------
class HipaaMissingAuthGuard(Rule):
    rule_id = "HIPAA-004"
    title = "API endpoint may lack authentication"
    description = (
        "FastAPI route handlers without an explicit auth dependency "
        "may expose PHI without verifying user identity."
    )
    severity = Severity.HIGH
    framework = Framework.HIPAA
    reference = "§ 164.312(d) - Person or Entity Authentication"
    remediation = (
        "Add a security dependency to every route that handles PHI data: "
        "`Depends(get_current_user)` or similar. "
        "Use OAuth2 or JWT-based authentication."
    )
    file_extensions = frozenset({".py"})

    # Routes that handle potentially sensitive operations
    _SENSITIVE_ROUTE = re.compile(
        r'@app\.(get|post|put|delete|patch)\s*\(\s*["\'](?!.*health)(?!.*ping).*["\']'
    )
    # Signs that this route has an auth dependency
    _AUTH_DEPENDENCY = re.compile(
        r'Depends\s*\(|current_user|get_current_user|oauth2_scheme|bearer_token'
        r'|require_auth|authenticated|jwt_required|login_required',
        re.IGNORECASE,
    )

    def check(self, file_path: Path, content: str) -> Iterator[Finding]:
        lines = content.splitlines()
        for i, line in enumerate(lines, start=1):
            if not self._SENSITIVE_ROUTE.search(line):
                continue
            # Look ahead in the next ~20 lines for auth dependency
            context = "\n".join(lines[i - 1: i + 20])
            if not self._AUTH_DEPENDENCY.search(context):
                yield self._finding(file_path, i, line.strip())


# ---------------------------------------------------------------------------
# HIPAA-005: Sensitive data in error responses
# ---------------------------------------------------------------------------
class HipaaSensitiveDataInErrors(Rule):
    rule_id = "HIPAA-005"
    title = "Internal error details exposed in HTTP response"
    description = (
        "Returning raw exception messages or stack traces in HTTP responses "
        "can leak system internals and PHI to clients."
    )
    severity = Severity.MEDIUM
    framework = Framework.HIPAA
    reference = "§ 164.312(c)(1) - Integrity"
    remediation = (
        "Catch exceptions at the boundary and return generic error messages. "
        "Log the full error internally but never expose it in the API response."
    )
    file_extensions = frozenset({".py"})

    _PATTERN = re.compile(
        r'raise\s+HTTPException\s*\(.*detail\s*=\s*f?["\'].*\{(e|err|error|ex|exception|str\()',
        re.IGNORECASE,
    )

    def check(self, file_path: Path, content: str) -> Iterator[Finding]:
        for lineno, line in enumerate(content.splitlines(), start=1):
            if self._PATTERN.search(line):
                yield self._finding(file_path, lineno, line.strip())


# ---------------------------------------------------------------------------
# HIPAA-006: Disabled TLS verification
# ---------------------------------------------------------------------------
class HipaaDisabledTlsVerification(Rule):
    rule_id = "HIPAA-006"
    title = "TLS certificate verification disabled"
    description = (
        "Disabling SSL/TLS certificate verification (verify=False) exposes "
        "data to man-in-the-middle attacks - a direct HIPAA transmission security violation."
    )
    severity = Severity.CRITICAL
    framework = Framework.HIPAA
    reference = "§ 164.312(e)(1) - Transmission Security"
    remediation = (
        "Remove verify=False. If using self-signed certs in dev, "
        "provide the CA bundle path instead: verify='/path/to/ca.crt'."
    )
    file_extensions = frozenset({".py", ".js", ".ts"})

    _PATTERN = re.compile(r'\bverify\s*=\s*False\b', re.IGNORECASE)
    _PATTERN_JS = re.compile(r'rejectUnauthorized\s*:\s*false', re.IGNORECASE)

    def check(self, file_path: Path, content: str) -> Iterator[Finding]:
        patterns = [self._PATTERN]
        if file_path.suffix in {".js", ".ts", ".jsx", ".tsx"}:
            patterns.append(self._PATTERN_JS)

        for lineno, line in enumerate(content.splitlines(), start=1):
            for p in patterns:
                if p.search(line):
                    yield self._finding(file_path, lineno, line.strip())
                    break


# ---------------------------------------------------------------------------
# HIPAA-007: Debug mode in production config
# ---------------------------------------------------------------------------
class HipaaDebugMode(Rule):
    rule_id = "HIPAA-007"
    title = "Debug mode enabled in application config"
    description = (
        "Running with DEBUG=True or debug=True in production exposes stack traces "
        "and internal state, risking PHI leakage."
    )
    severity = Severity.MEDIUM
    framework = Framework.HIPAA
    reference = "§ 164.312(b) - Audit Controls"
    remediation = (
        "Set DEBUG=False in all production environments. "
        "Use environment-specific config (e.g. ENVIRONMENT=production) "
        "and only enable debug in local dev."
    )
    file_extensions = frozenset({".py", ".env", ".yaml", ".yml"})

    _PATTERN = re.compile(r'\bDEBUG\s*=\s*True\b', re.IGNORECASE)
    _PATTERN_ENV = re.compile(r'^DEBUG\s*=\s*true\s*$', re.IGNORECASE | re.MULTILINE)

    def check(self, file_path: Path, content: str) -> Iterator[Finding]:
        pattern = self._PATTERN_ENV if file_path.suffix == ".env" else self._PATTERN
        for lineno, line in enumerate(content.splitlines(), start=1):
            if pattern.search(line):
                yield self._finding(file_path, lineno, line.strip())


# ---------------------------------------------------------------------------
# Exported rule instances
# ---------------------------------------------------------------------------
HIPAA_RULES = [
    HipaaHardcodedCredentials(),
    HipaaPhiInLogs(),
    HipaaUnencryptedHttp(),
    HipaaMissingAuthGuard(),
    HipaaSensitiveDataInErrors(),
    HipaaDisabledTlsVerification(),
    HipaaDebugMode(),
]
