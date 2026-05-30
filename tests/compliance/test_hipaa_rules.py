"""
test_hipaa_rules.py - Tests for every HIPAA compliance rule.

Each test class covers one rule with:
- True positives (code that MUST trigger the rule)
- True negatives (compliant code that must NOT trigger the rule)
- Edge cases (comments, whitelisted values, mixed content)

No filesystem or network I/O - all content is passed as strings.
"""

import pytest
from pathlib import Path

from security_scanner.compliance.config import Severity, Framework
from security_scanner.compliance.rules.hipaa_rules import (
    HipaaHardcodedCredentials,
    HipaaPhiInLogs,
    HipaaUnencryptedHttp,
    HipaaMissingAuthGuard,
    HipaaSensitiveDataInErrors,
    HipaaDisabledTlsVerification,
    HipaaDebugMode,
    HIPAA_RULES,
)


PY = Path("app.py")
JS = Path("app.js")
ENV = Path(".env")


def findings(rule, content, path=PY):
    return list(rule.check(path, content))


# ---------------------------------------------------------------------------
# HIPAA-001: Hardcoded credentials
# ---------------------------------------------------------------------------
class TestHipaaHardcodedCredentials:
    rule = HipaaHardcodedCredentials()

    def test_password_assignment_triggers(self):
        code = 'password = "SuperSecret123!"'
        assert len(findings(self.rule, code)) >= 1

    def test_api_key_triggers(self):
        code = 'api_key = "sk-prod-abc123def456ghi789jkl0"'
        assert len(findings(self.rule, code)) >= 1

    def test_aws_access_key_triggers(self):
        code = "aws_access_key = AKIAIOSFODNN7EXAMPLE"
        assert len(findings(self.rule, code)) >= 1

    def test_openai_key_triggers(self):
        code = 'OPENAI_API_KEY = "sk-abcdefghijklmnopqrstuvwxyz12345678901234"'
        assert len(findings(self.rule, code)) >= 1

    def test_supabase_jwt_triggers(self):
        # Fake JWT-shaped token (3 base64 segments)
        token = "eyJhbGciOiJIUzI1NiJ9." + "a" * 60 + "." + "b" * 30
        code = f'SUPABASE_KEY = "{token}"'
        assert len(findings(self.rule, code)) >= 1

    def test_comment_line_ignored(self):
        code = '# password = "ExamplePassword123"'
        assert len(findings(self.rule, code)) == 0

    def test_whitelisted_placeholder_ignored(self):
        code = 'password = "changeme"'
        assert len(findings(self.rule, code)) == 0

    def test_env_var_reference_not_flagged(self):
        code = 'password = os.getenv("DB_PASSWORD")'
        assert len(findings(self.rule, code)) == 0

    def test_finding_severity_is_critical(self):
        code = 'secret_key = "real-secret-key-value-1234567890"'
        found = findings(self.rule, code)
        assert any(f.severity == Severity.CRITICAL for f in found)

    def test_finding_framework_is_hipaa(self):
        code = 'api_key = "sk-prod-realkey12345678901234567"'
        found = findings(self.rule, code)
        assert any(f.framework == Framework.HIPAA for f in found)


# ---------------------------------------------------------------------------
# HIPAA-002: PHI in logs
# ---------------------------------------------------------------------------
class TestHipaaPhiInLogs:
    rule = HipaaPhiInLogs()

    def test_python_print_with_ssn_triggers(self):
        code = 'print(f"Processing SSN: {patient.ssn}")'
        assert len(findings(self.rule, code)) >= 1

    def test_logging_with_patient_id_triggers(self):
        code = 'logging.info(f"Loaded record for patient_id={pid}")'
        assert len(findings(self.rule, code)) >= 1

    def test_console_log_with_dob_triggers(self):
        code = 'console.log("Patient DOB:", patient.dob)', JS
        assert len(findings(self.rule, 'console.log("Patient DOB:", patient.dob)', JS)) >= 1

    def test_log_without_phi_not_flagged(self):
        code = 'logging.info("Processing request for user %s", user_id)'
        assert len(findings(self.rule, code)) == 0

    def test_phi_in_variable_not_in_log_not_flagged(self):
        code = 'diagnosis = patient.diagnosis'
        assert len(findings(self.rule, code)) == 0


# ---------------------------------------------------------------------------
# HIPAA-003: Unencrypted HTTP
# ---------------------------------------------------------------------------
class TestHipaaUnencryptedHttp:
    rule = HipaaUnencryptedHttp()

    def test_production_http_url_triggers(self):
        code = 'API_URL = "http://api.company.com/patients"'
        assert len(findings(self.rule, code)) >= 1

    def test_localhost_http_not_flagged(self):
        code = 'BASE_URL = "http://localhost:8000"'
        assert len(findings(self.rule, code)) == 0

    def test_127_0_0_1_not_flagged(self):
        code = 'url = "http://127.0.0.1:5173"'
        assert len(findings(self.rule, code)) == 0

    def test_https_url_not_flagged(self):
        code = 'url = "https://api.company.com/records"'
        assert len(findings(self.rule, code)) == 0

    def test_comment_with_http_not_flagged(self):
        code = '# Old endpoint: http://legacy.api.com'
        assert len(findings(self.rule, code)) == 0


# ---------------------------------------------------------------------------
# HIPAA-004: Missing auth guard
# ---------------------------------------------------------------------------
class TestHipaaMissingAuthGuard:
    rule = HipaaMissingAuthGuard()

    def test_unprotected_post_route_triggers(self):
        code = '''
@app.post("/patients/records")
def get_patient_records(payload: dict = Body(...)):
    return db.query_all()
'''
        assert len(findings(self.rule, code)) >= 1

    def test_route_with_depends_not_flagged(self):
        code = '''
@app.post("/patients/records")
def get_patient_records(
    payload: dict = Body(...),
    current_user = Depends(get_current_user)
):
    return db.query_all()
'''
        assert len(findings(self.rule, code)) == 0

    def test_health_check_route_not_flagged(self):
        code = '''
@app.get("/healthcheck")
def health():
    return {"status": "ok"}
'''
        assert len(findings(self.rule, code)) == 0


# ---------------------------------------------------------------------------
# HIPAA-005: Sensitive data in errors
# ---------------------------------------------------------------------------
class TestHipaaSensitiveDataInErrors:
    rule = HipaaSensitiveDataInErrors()

    def test_exception_detail_in_http_error_triggers(self):
        code = 'raise HTTPException(status_code=500, detail=f"Internal error: {e}")'
        assert len(findings(self.rule, code)) >= 1

    def test_generic_error_message_not_flagged(self):
        code = 'raise HTTPException(status_code=500, detail="Internal server error")'
        assert len(findings(self.rule, code)) == 0


# ---------------------------------------------------------------------------
# HIPAA-006: Disabled TLS verification
# ---------------------------------------------------------------------------
class TestHipaaDisabledTlsVerification:
    rule = HipaaDisabledTlsVerification()

    def test_requests_verify_false_triggers(self):
        code = 'response = requests.get(url, verify=False)'
        assert len(findings(self.rule, code)) >= 1

    def test_reject_unauthorized_false_triggers(self):
        code = 'const https = require("https"); const agent = new https.Agent({ rejectUnauthorized: false });'
        assert len(findings(self.rule, code, path=JS)) >= 1

    def test_verify_true_not_flagged(self):
        code = 'response = requests.get(url, verify=True)'
        assert len(findings(self.rule, code)) == 0

    def test_finding_severity_is_critical(self):
        code = 'resp = requests.post(url, json=body, verify=False)'
        found = findings(self.rule, code)
        assert any(f.severity == Severity.CRITICAL for f in found)


# ---------------------------------------------------------------------------
# HIPAA-007: Debug mode
# ---------------------------------------------------------------------------
class TestHipaaDebugMode:
    rule = HipaaDebugMode()

    def test_debug_true_in_python_triggers(self):
        code = 'DEBUG = True'
        assert len(findings(self.rule, code)) >= 1

    def test_debug_true_in_env_triggers(self):
        code = 'DEBUG=true'
        assert len(findings(self.rule, code, path=ENV)) >= 1

    def test_debug_false_not_flagged(self):
        code = 'DEBUG = False'
        assert len(findings(self.rule, code)) == 0

    def test_debug_env_false_not_flagged(self):
        code = 'DEBUG=false'
        assert len(findings(self.rule, code, path=ENV)) == 0


# ---------------------------------------------------------------------------
# HIPAA_RULES list integrity
# ---------------------------------------------------------------------------
class TestHipaaRulesList:
    def test_all_rules_have_required_attributes(self):
        for rule in HIPAA_RULES:
            assert rule.rule_id.startswith("HIPAA-"), f"{rule.__class__.__name__} bad rule_id"
            assert rule.title, f"{rule.__class__.__name__} missing title"
            assert rule.severity in Severity, f"{rule.__class__.__name__} bad severity"
            assert rule.framework == Framework.HIPAA
            assert rule.remediation, f"{rule.__class__.__name__} missing remediation"

    def test_rule_ids_are_unique(self):
        ids = [r.rule_id for r in HIPAA_RULES]
        assert len(ids) == len(set(ids)), "Duplicate HIPAA rule IDs detected"

    def test_all_rules_have_check_method(self):
        for rule in HIPAA_RULES:
            assert callable(getattr(rule, "check", None))
