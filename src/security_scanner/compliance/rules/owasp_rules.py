"""
owasp_rules.py - OWASP Top 10 (2021) compliance rules.

A01 - Broken Access Control
A02 - Cryptographic Failures
A03 - Injection
A04 - Insecure Design
A05 - Security Misconfiguration
A06 - Vulnerable and Outdated Components
A07 - Identification and Authentication Failures
A08 - Software and Data Integrity Failures
A09 - Security Logging and Monitoring Failures
A10 - Server-Side Request Forgery (SSRF)
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Iterator

from security_scanner.compliance.config import Framework, Severity
from security_scanner.compliance.rules.base import Finding, Rule


# ---------------------------------------------------------------------------
# OWASP-A02: Weak / outdated cryptographic algorithms
# ---------------------------------------------------------------------------
class OwaspWeakCrypto(Rule):
    rule_id = "OWASP-A02"
    title = "Weak or deprecated cryptographic algorithm"
    description = (
        "MD5, SHA1, DES, and RC4 are broken algorithms that must not be used "
        "for password hashing, data signing, or encryption (OWASP A02)."
    )
    severity = Severity.HIGH
    framework = Framework.OWASP
    reference = "OWASP A02:2021 - Cryptographic Failures"
    remediation = (
        "Use SHA-256 or SHA-3 for hashing, AES-256-GCM for encryption, "
        "bcrypt/scrypt/argon2 for password hashing. "
        "Never use MD5 or SHA1 in a security context."
    )
    file_extensions = frozenset({".py", ".js", ".ts", ".jsx", ".tsx"})

    _PATTERNS = [
        re.compile(r'\bhashlib\.md5\b', re.IGNORECASE),
        re.compile(r'\bhashlib\.sha1\b', re.IGNORECASE),
        re.compile(r'\bMD5\s*\(', re.IGNORECASE),
        re.compile(r'\bSHA1\s*\(|\bSHA-1\b', re.IGNORECASE),
        re.compile(r'\bDES\b.*encrypt|\bTripleDES\b', re.IGNORECASE),
        re.compile(r'\bcreateHash\(["\']md5["\']\)', re.IGNORECASE),
        re.compile(r'\bcreateHash\(["\']sha1["\']\)', re.IGNORECASE),
    ]

    def check(self, file_path: Path, content: str) -> Iterator[Finding]:
        for lineno, line in enumerate(content.splitlines(), start=1):
            stripped = line.strip()
            if stripped.startswith(("#", "//")):
                continue
            for p in self._PATTERNS:
                if p.search(line):
                    yield self._finding(file_path, lineno, stripped)
                    break


# ---------------------------------------------------------------------------
# OWASP-A03: Command injection via subprocess
# ---------------------------------------------------------------------------
class OwaspCommandInjection(Rule):
    rule_id = "OWASP-A03"
    title = "Potential command injection via subprocess with shell=True"
    description = (
        "Using subprocess.run/Popen with `shell=True` and user-supplied input "
        "enables command injection - OWASP A03 (Injection)."
    )
    severity = Severity.CRITICAL
    framework = Framework.OWASP
    reference = "OWASP A03:2021 - Injection"
    remediation = (
        "Use shell=False (the default) and pass arguments as a list. "
        "If shell=True is unavoidable, sanitise all user input with shlex.quote()."
    )
    file_extensions = frozenset({".py"})

    _PATTERN = re.compile(
        r'\bsubprocess\.(run|Popen|call|check_output|check_call)\s*\('
        r'[^)]*shell\s*=\s*True',
        re.DOTALL,
    )

    def check(self, file_path: Path, content: str) -> Iterator[Finding]:
        for lineno, line in enumerate(content.splitlines(), start=1):
            if self._PATTERN.search(line):
                yield self._finding(file_path, lineno, line.strip())


# ---------------------------------------------------------------------------
# OWASP-A03: Path traversal
# ---------------------------------------------------------------------------
class OwaspPathTraversal(Rule):
    rule_id = "OWASP-A03-PT"
    title = "Potential path traversal vulnerability"
    description = (
        "Constructing file paths from user input without sanitisation can allow "
        "path traversal attacks that read/write arbitrary files (OWASP A03)."
    )
    severity = Severity.HIGH
    framework = Framework.OWASP
    reference = "OWASP A03:2021 - Injection (Path Traversal)"
    remediation = (
        "Validate and sanitise all user-supplied file paths. "
        "Use pathlib.Path.resolve() and check the path is within the expected directory. "
        "Reject paths containing '..' or absolute paths from user input."
    )
    file_extensions = frozenset({".py", ".js", ".ts"})

    _PATTERN = re.compile(
        r'(open|os\.path\.join|Path)\s*\(.*'
        r'(request\.|req\.|payload\.|body\.|params\.|query\.)',
        re.IGNORECASE,
    )

    def check(self, file_path: Path, content: str) -> Iterator[Finding]:
        for lineno, line in enumerate(content.splitlines(), start=1):
            if self._PATTERN.search(line):
                yield self._finding(file_path, lineno, line.strip())


# ---------------------------------------------------------------------------
# OWASP-A05: Security misconfiguration - debug/test endpoints
# ---------------------------------------------------------------------------
class OwaspTestEndpointsInProd(Rule):
    rule_id = "OWASP-A05"
    title = "Debug or test endpoint present in production code"
    description = (
        "Routes named /debug, /test, /healthcheck-internal, /admin-backdoor etc. "
        "must not be accessible in production (OWASP A05 - Security Misconfiguration)."
    )
    severity = Severity.MEDIUM
    framework = Framework.OWASP
    reference = "OWASP A05:2021 - Security Misconfiguration"
    remediation = (
        "Remove debug endpoints from production code, or gate them behind "
        "IP allowlists and strong authentication. "
        "Do not expose /debug or /admin without proper access controls."
    )
    file_extensions = frozenset({".py", ".js", ".ts"})

    _PATTERN = re.compile(
        r'@app\.(get|post)\s*\(\s*["\']/(debug|test|internal|admin(?!.*login)|'
        r'backdoor|devtools|phpinfo|eval)["\']',
        re.IGNORECASE,
    )

    def check(self, file_path: Path, content: str) -> Iterator[Finding]:
        for lineno, line in enumerate(content.splitlines(), start=1):
            if self._PATTERN.search(line):
                yield self._finding(file_path, lineno, line.strip())


# ---------------------------------------------------------------------------
# OWASP-A07: Insecure session configuration
# ---------------------------------------------------------------------------
class OwaspInsecureSession(Rule):
    rule_id = "OWASP-A07"
    title = "Session cookie missing Secure or HttpOnly flag"
    description = (
        "Cookies without the Secure and HttpOnly flags are accessible via JavaScript "
        "and transmittable over HTTP - OWASP A07 (Authentication Failures)."
    )
    severity = Severity.HIGH
    framework = Framework.OWASP
    reference = "OWASP A07:2021 - Identification and Authentication Failures"
    remediation = (
        "Always set cookies with: httponly=True, secure=True, samesite='Strict'. "
        "In FastAPI/Starlette: `response.set_cookie(key, value, httponly=True, secure=True)`"
    )
    file_extensions = frozenset({".py", ".js", ".ts"})

    _SET_COOKIE = re.compile(r'set_cookie\s*\(|setcookie\s*\(|res\.cookie\s*\(', re.IGNORECASE)
    _HTTPONLY = re.compile(r'httponly\s*=\s*True|HttpOnly', re.IGNORECASE)
    _SECURE = re.compile(r'\bsecure\s*=\s*True\b|\bSecure\b')

    def check(self, file_path: Path, content: str) -> Iterator[Finding]:
        lines = content.splitlines()
        for i, line in enumerate(lines, start=1):
            if not self._SET_COOKIE.search(line):
                continue
            # Check the same line and ±3 lines for secure/httponly
            context = "\n".join(lines[max(0, i - 2): i + 3])
            missing = []
            if not self._HTTPONLY.search(context):
                missing.append("httponly=True")
            if not self._SECURE.search(context):
                missing.append("secure=True")
            if missing:
                yield self._finding(
                    file_path, i, line.strip(),
                    description_override=f"Cookie missing: {', '.join(missing)}",
                )


# ---------------------------------------------------------------------------
# OWASP-A10: Server-Side Request Forgery (SSRF)
# ---------------------------------------------------------------------------
class OwaspSsrf(Rule):
    rule_id = "OWASP-A10"
    title = "Potential SSRF - user-supplied URL passed to HTTP client"
    description = (
        "Passing user-supplied URLs directly to requests.get() or fetch() without "
        "validation enables Server-Side Request Forgery (OWASP A10)."
    )
    severity = Severity.HIGH
    framework = Framework.OWASP
    reference = "OWASP A10:2021 - Server-Side Request Forgery"
    remediation = (
        "Validate URLs against an allowlist of permitted hosts/schemes. "
        "Block private IP ranges (10.x, 172.16.x, 192.168.x, 127.x, 169.254.x). "
        "Never forward raw user-supplied URLs to internal services."
    )
    file_extensions = frozenset({".py", ".js", ".ts"})

    _REQUESTS = re.compile(
        r'requests\.(get|post|put|delete|head)\s*\('
        r'|fetch\s*\('
        r'|axios\.(get|post|put|delete)\s*\(',
        re.IGNORECASE,
    )
    _USER_INPUT = re.compile(
        r'(request\.|req\.|payload\.|body\.|params\.|query\.|form\.|data\.)'
        r'(url|file_url|target|endpoint|host|href)',
        re.IGNORECASE,
    )

    def check(self, file_path: Path, content: str) -> Iterator[Finding]:
        lines = content.splitlines()
        for i, line in enumerate(lines, start=1):
            if self._REQUESTS.search(line) and self._USER_INPUT.search(line):
                yield self._finding(file_path, i, line.strip())


# ---------------------------------------------------------------------------
# OWASP-A08: Pickle / deserialization of untrusted data
# ---------------------------------------------------------------------------
class OwaspInsecureDeserialization(Rule):
    rule_id = "OWASP-A08"
    title = "Insecure deserialization - pickle.loads() with untrusted data"
    description = (
        "pickle.loads() on untrusted data can execute arbitrary Python code "
        "(OWASP A08 - Software and Data Integrity Failures)."
    )
    severity = Severity.CRITICAL
    framework = Framework.OWASP
    reference = "OWASP A08:2021 - Software and Data Integrity Failures"
    remediation = (
        "Never use pickle.loads() on data received over the network or from users. "
        "Use JSON, MessagePack, or Protocol Buffers instead."
    )
    file_extensions = frozenset({".py"})

    _PATTERN = re.compile(r'\bpickle\.loads?\s*\(')

    def check(self, file_path: Path, content: str) -> Iterator[Finding]:
        for lineno, line in enumerate(content.splitlines(), start=1):
            if self._PATTERN.search(line):
                yield self._finding(file_path, lineno, line.strip())


# ---------------------------------------------------------------------------
# Exported rule instances
# ---------------------------------------------------------------------------
OWASP_RULES = [
    OwaspWeakCrypto(),
    OwaspCommandInjection(),
    OwaspPathTraversal(),
    OwaspTestEndpointsInProd(),
    OwaspInsecureSession(),
    OwaspSsrf(),
    OwaspInsecureDeserialization(),
]
