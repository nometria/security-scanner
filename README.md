# security-scan

> Static security scanner purpose-built for AI-generated web app code.

AI code generators (Lovable, Bolt, v0, Cursor, Copilot) frequently produce code with
hardcoded secrets, missing auth guards, SQL injection patterns, and CORS misconfigs.
This scanner catches those before they hit production.

**Zero dependencies. Pure Python stdlib.**

---

## Rules

| Rule | Severity | Catches |
|------|----------|---------|
| SEC-001 | 🔴 CRITICAL | Hardcoded API keys, tokens, passwords, JWT secrets |
| SEC-002 | 🟠 HIGH | `.env` file committed without `.gitignore` entry |
| SEC-003 | 🟠 HIGH | Dangerous `eval()` / `exec()` usage |
| SEC-004 | 🟠 HIGH | SQL injection (string interpolation in queries) |
| SEC-005 | 🟠 HIGH | Missing auth middleware on API routes |
| SEC-006 | 🟡 MEDIUM | CORS wildcard `*` in production code |
| SEC-007 | 🔵 LOW | HTTP (not HTTPS) hardcoded URLs |
| SEC-008 | 🟠 HIGH | Exposed admin routes without auth |
| SEC-009 | 🟠 HIGH | Auth tokens stored in `localStorage` (XSS risk) |
| SEC-010 | 🟡 MEDIUM | `process.env` values logged to console |
| SEC-011 | 🔴 CRITICAL | Supabase `service_role` key used client-side |
| SEC-012 | 🟡 MEDIUM | Dependency confusion risk in `package.json` |

---

## Install

```bash
pip install security-scan        # PyPI (coming soon)

# From source:
git clone https://github.com/YOUR_ORG/security-scanner
cd security-scanner
pip install -e .
```

---

## Usage

```bash
# Scan current directory
security-scan .

# Scan a specific project
security-scan ./my-vite-app

# JSON output (for CI pipelines)
security-scan . --format json --output report.json

# SARIF output (GitHub Code Scanning)
security-scan . --format sarif --output results.sarif

# Markdown report
security-scan . --format markdown --output security-report.md

# Only fail on critical issues (default: high+)
security-scan . --fail-on critical

# No color (CI-friendly)
security-scan . --no-color
```

---

## GitHub Actions integration

```yaml
# .github/workflows/security-scan.yml
name: Security Scan
on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: { python-version: '3.11' }
      - run: pip install security-scan
      - run: security-scan . --format sarif --output results.sarif --fail-on high
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: results.sarif
```

---

## Use as a library

```python
from security_scanner import scan_project

result = scan_project("./my-app")

print(f"Passed: {result.passed}")
print(f"Critical: {result.critical_count}")

for finding in result.findings:
    print(f"[{finding.severity}] {finding.rule_id}: {finding.file}:{finding.line}")
    print(f"  {finding.message}")
    print(f"  Fix: {finding.fix}")
```

---

## Add custom rules

```python
from security_scanner.scanner import Finding, HIGH

def check_no_http_fetch(path, rel, lines):
    findings = []
    for i, line in enumerate(lines, 1):
        if 'fetch(\"http://' in line:
            findings.append(Finding(
                rule_id="CUSTOM-001", severity=HIGH,
                file=rel, line=i,
                message="fetch() called with HTTP URL",
                fix="Use HTTPS for all fetch calls."
            ))
    return findings

# Register in scanner.py scan_project() loop
```

---

## Immediate next steps
1. Publish to PyPI: `pip install security-scan`
2. Publish to npm as `npx security-scan` wrapper
3. Submit to GitHub Marketplace as an Action
4. Add SEC-005 (missing auth middleware) — requires AST parsing
5. Add `--watch` mode for IDE integration

---

## Commercial viability
- **Open source** it — "security scanner for AI-generated code" is high SEO value
- Drive inbound: every AI app builder user is a potential Nometria customer
- Upsell: "scan found issues → let us help you fix and self-host securely"
- GitHub App: auto-scan every PR, post findings as PR review comments — $9–19/mo/repo
