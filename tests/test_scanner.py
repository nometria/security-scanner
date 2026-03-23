"""Tests for security scanner rules."""
import sys
import textwrap
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from scanner import (
    scan_project, check_secrets, check_eval_exec, check_sql_injection,
    check_cors_wildcard, check_localstorage_auth, check_console_env,
    check_supabase_service_key_clientside,
    CRITICAL, HIGH, MEDIUM, LOW,
)


def make_project(files: dict) -> Path:
    tmp = Path(tempfile.mkdtemp())
    (tmp / ".gitignore").write_text(".env\nnode_modules/\n")
    for rel, content in files.items():
        p = tmp / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(textwrap.dedent(content))
    return tmp


# ── SEC-001: secrets ──────────────────────────────────────────────────────────

def test_openai_key_detected():
    # sk- followed by exactly 48 alphanumeric chars (matches OpenAI key pattern)
    project = make_project({"src/config.ts": "const key = 'sk-aaaabbbbccccddddeeeeffffgggghhhhiiiijjjjkkkkllll';"})
    result = scan_project(project)
    assert any(f.rule_id == "SEC-001" and f.severity == CRITICAL for f in result.findings)


def test_placeholder_not_flagged():
    project = make_project({"src/config.ts": "const key = 'your_api_key_here';"})
    result = scan_project(project)
    secrets = [f for f in result.findings if f.rule_id == "SEC-001"]
    assert len(secrets) == 0


def test_example_env_not_flagged():
    project = make_project({".env.example": "OPENAI_API_KEY=sk-your-key-here"})
    result = scan_project(project)
    secrets = [f for f in result.findings if f.rule_id == "SEC-001"]
    assert len(secrets) == 0


# ── SEC-003: eval ─────────────────────────────────────────────────────────────

def test_eval_detected():
    project = make_project({"src/utils.js": "const result = eval(userInput);"})
    result = scan_project(project)
    assert any(f.rule_id == "SEC-003" for f in result.findings)


def test_eval_in_comment_not_flagged():
    project = make_project({"src/utils.js": "// Don't use eval()"})
    result = scan_project(project)
    evals = [f for f in result.findings if f.rule_id == "SEC-003"]
    assert len(evals) == 0


# ── SEC-004: SQL injection ────────────────────────────────────────────────────

def test_sql_injection_detected():
    project = make_project({
        "src/db.ts": 'db.query(`SELECT * FROM users WHERE id = ${userId}`);'
    })
    result = scan_project(project)
    assert any(f.rule_id == "SEC-004" for f in result.findings)


# ── SEC-006: CORS wildcard ────────────────────────────────────────────────────

def test_cors_wildcard_detected():
    project = make_project({
        "src/server.js": "res.setHeader('Access-Control-Allow-Origin', '*');"
    })
    result = scan_project(project)
    assert any(f.rule_id == "SEC-006" for f in result.findings)


# ── SEC-009: localStorage tokens ─────────────────────────────────────────────

def test_localstorage_token_detected():
    project = make_project({
        "src/auth.ts": "localStorage.setItem('auth_token', response.token);"
    })
    result = scan_project(project)
    assert any(f.rule_id == "SEC-009" for f in result.findings)


# ── SEC-010: console.log env ──────────────────────────────────────────────────

def test_console_log_env_detected():
    project = make_project({
        "src/debug.js": "console.log('key:', process.env.STRIPE_SECRET_KEY);"
    })
    result = scan_project(project)
    assert any(f.rule_id == "SEC-010" for f in result.findings)


# ── Clean project ─────────────────────────────────────────────────────────────

def test_clean_project_passes():
    project = make_project({
        "src/app.ts": textwrap.dedent("""
            const apiKey = process.env.OPENAI_API_KEY;
            if (!apiKey) throw new Error('Missing OPENAI_API_KEY');
            export { apiKey };
        """).lstrip()
    })
    result = scan_project(project)
    assert result.passed
    assert len([f for f in result.findings if f.severity in (CRITICAL, HIGH)]) == 0


# ── Report formats ────────────────────────────────────────────────────────────

def test_json_report_structure():
    from reporter import format_json
    import json
    project = make_project({"src/bad.js": "const key = 'sk-abcdefghijklmnopqrstuvwxyz0123456789012345678';"})
    result = scan_project(project)
    parsed = json.loads(format_json(result))
    assert "findings" in parsed
    assert "summary" in parsed
    assert "passed" in parsed


def test_sarif_report_valid():
    from reporter import format_sarif
    import json
    project = make_project({})
    result = scan_project(project)
    parsed = json.loads(format_sarif(result))
    assert parsed["version"] == "2.1.0"
    assert "runs" in parsed
