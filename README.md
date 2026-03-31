# security-scan

<p align="center">
  <b>Built by <a href="https://nometria.com">Nometria</a></b> — We take AI-built apps to production.
</p>

> Static security scanner purpose-built for AI-generated web app code.

AI code generators (Lovable, Bolt, v0, Cursor, Copilot) frequently produce code with
hardcoded secrets, missing auth guards, SQL injection patterns, and CORS misconfigs.
This scanner catches those before they hit production.

**Zero dependencies. Pure Python stdlib.**

---

## Quick start

```bash
# Clone and install
git clone https://github.com/nometria/security-scanner
cd security-scanner
pip install -e .

# Scan your project
security-scan ./my-app

# Scan a directory and output JSON
security-scan ./my-app --format json

# Scan the included example file
security-scan examples/ --no-color
```

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
git clone https://github.com/nometria/security-scanner
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

# Watch mode — re-scans on file changes (polls every 2s)
security-scan . --watch

# Watch with JSON output
security-scan ./my-app --watch --format json
```

### Watch mode

The `--watch` flag monitors your project for file changes and re-runs the scan automatically.
Uses lightweight mtime polling (every 2 seconds) with zero extra dependencies -- no `watchdog` needed.

On each change only the modified files are re-scanned (incremental), while the full findings
list is kept up to date. The terminal is cleared and refreshed so you always see a clean report.

```
$ security-scan ./my-app --watch

[14:31:55] Full scan

══════════════════════════════════════════════════════════════════════
  SECURITY SCAN — 12 files scanned, 3 findings
══════════════════════════════════════════════════════════════════════
  ...

Watching for changes... (Ctrl+C to stop)

[14:32:07] Re-scanned 1 changed file(s)

══════════════════════════════════════════════════════════════════════
  SECURITY SCAN — 13 files scanned, 2 findings
══════════════════════════════════════════════════════════════════════
  ...

Watching for changes... (Ctrl+C to stop)
```

In watch mode the process runs continuously and does not exit on findings, making it suitable
for IDE integration and development workflows.

### IDE integration

Run the scanner in a side terminal while you code -- findings update live as you save files.

**VS Code** -- open a terminal pane (`Ctrl+`` `) and run:
```bash
security-scan --watch .
```
Split the terminal so the scan output is always visible beside your editor.

**JetBrains (WebStorm / PyCharm)** -- add an *External Tool* or *Run Configuration*:
- Program: `security-scan`
- Arguments: `--watch $ProjectFileDir$`
- Working directory: `$ProjectFileDir$`

**Neovim / tmux** -- keep a tmux split running:
```bash
tmux split-window -h 'security-scan --watch .'
```

**CI / pre-commit** -- for one-shot scans in CI, omit `--watch`:
```bash
security-scan . --format sarif --output results.sarif --fail-on high
```

---

## GitHub Action

Use the composite GitHub Action for a turnkey CI integration with PR comments, SARIF upload, and configurable failure thresholds.

```yaml
# .github/workflows/security-scan.yml
name: Security Scan
on:
  push:
    branches: [main]
  pull_request:

permissions:
  contents: read
  pull-requests: write
  security-events: write

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: nometria/security-scanner@main
        with:
          target_dir: '.'
          format: 'text'
          fail_on_findings: 'true'
          fail_on: 'high'
          post_comment: 'true'
          sarif_upload: 'true'
```

### Action inputs

| Input | Default | Description |
|-------|---------|-------------|
| `target_dir` | `.` | Directory to scan |
| `format` | `text` | Output format: `text`, `json`, or `markdown` |
| `fail_on_findings` | `true` | Fail the action if findings meet the severity threshold |
| `fail_on` | `high` | Minimum severity to fail: `critical`, `high`, `medium`, `low`, `any` |
| `post_comment` | `true` | Post results as a PR comment (pull_request events only) |
| `sarif_upload` | `true` | Upload SARIF results to GitHub Code Scanning |
| `python_version` | `3.11` | Python version to use |

### Action outputs

| Output | Description |
|--------|-------------|
| `passed` | `true` if no findings at or above the fail threshold |
| `findings_count` | Total number of findings |
| `critical_count` | Number of critical findings |
| `report` | Full scan report in the requested format |

See [`examples/security-scan-action.yml`](examples/security-scan-action.yml) for a complete workflow example.

#### Manual pip-based workflow

If you prefer not to use the composite action, you can install and run directly:

```yaml
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: { python-version: '3.11' }
      - run: pip install ai-security-scan
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
        if 'fetch("http://' in line:
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
1. ~~Publish to PyPI: `pip install ai-security-scan`~~ Done
2. Publish to npm as `npx security-scan` wrapper
3. ~~Submit to GitHub Marketplace as an Action~~ Done (`action.yml`)
4. Add SEC-005 (missing auth middleware) — requires AST parsing
5. ~~Add `--watch` mode for IDE integration~~ Done (`--watch` flag with incremental re-scan)

---

## Commercial viability
- **Open source** it — "security scanner for AI-generated code" is high SEO value
- Drive inbound: every AI app builder user is a potential Nometria customer
- Upsell: "scan found issues → let us help you fix and self-host securely"
- GitHub App: auto-scan every PR, post findings as PR review comments — $9–19/mo/repo

---

---

## Built by Nometria

<a href="https://nometria.com">
  <img src="https://img.shields.io/badge/nometria.com-Take%20AI%20apps%20to%20production-111827?style=for-the-badge&logo=data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iMjQiIGhlaWdodD0iMjQiIHZpZXdCb3g9IjAgMCAyNCAyNCIgZmlsbD0ibm9uZSIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIj48cGF0aCBkPSJNMTIgMkw0IDdWMTdMMTIgMjJMMjAgMTdWN0wxMiAyWiIgc3Ryb2tlPSJ3aGl0ZSIgc3Ryb2tlLXdpZHRoPSIyIi8+PC9zdmc+" alt="Nometria" />
</a>

**security-scan** is open source and free to use. It's one of the developer tools we built while helping teams ship AI-generated apps to production.

AI-generated code often ships with hardcoded secrets and missing auth. We built this scanner specifically for the patterns we see in Lovable, Bolt, and Base44 output.

**What Nometria does:**
- :rocket: **Deploy AI apps to AWS** -- one click, production-ready
- :lock: **Security & compliance** -- SOC 2, HIPAA-ready infrastructure
- :chart_with_upwards_trend: **Scale reliably** -- handles real user traffic from day one
- :wrench: **Full source code ownership** -- you own everything, no lock-in

If you're building with AI tools (Base44, Lovable, Bolt, Replit, Cursor) and need to go to production -- **[nometria.com](https://nometria.com)**

---

## Example output

Running `security-scan examples/ --no-color` against the included `examples/vulnerable.js`:

```
Scanning /tmp/ownmy-releases/security-scanner/examples ...

══════════════════════════════════════════════════════════════════════
  SECURITY SCAN — 1 files scanned, 5 findings
══════════════════════════════════════════════════════════════════════

  🔴 [CRITICAL] SEC-001
     File   : vulnerable.js:4
     Issue  : Hardcoded API key detected
     Code   : const API_KEY = "sk-live-abc123def456ghi789jkl012mno345pqr678";
     Fix    : Move to environment variables. Never commit secrets to source control.

  🔴 [CRITICAL] SEC-001
     File   : vulnerable.js:5
     Issue  : Hardcoded password detected
     Code   : const DB_PASSWORD = "SuperSecret123!";
     Fix    : Move to environment variables. Never commit secrets to source control.

  🟠 [HIGH] SEC-003
     File   : vulnerable.js:10
     Issue  : Dangerous eval/exec usage — potential code injection
     Code   : return eval(input);
     Fix    : Avoid eval/exec with user input. Use JSON.parse() or safe alternatives.

  🟠 [HIGH] SEC-004
     File   : vulnerable.js:15
     Issue  : Potential SQL injection — string interpolation in query
     Code   : const query = `SELECT * FROM users WHERE id = ${userId}`;
     Fix    : Use parameterised queries: db.query('SELECT * FROM t WHERE id = $1', [id])

  🟠 [HIGH] SEC-004
     File   : vulnerable.js:20
     Issue  : Potential SQL injection — string interpolation in query
     Code   : const sql = "SELECT * FROM products WHERE name = '" + term + "'";
     Fix    : Use parameterised queries: db.query('SELECT * FROM t WHERE id = $1', [id])

──────────────────────────────────────────────────────────────────────
  Critical: 2  |  High: 3  |  Medium: 0  |  Low: 0
  Overall: ❌ FAIL
──────────────────────────────────────────────────────────────────────
```
