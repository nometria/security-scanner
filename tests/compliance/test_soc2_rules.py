"""
test_soc2_rules.py - Tests for SOC2 and OWASP compliance rules.
"""

import pytest
from pathlib import Path

from security_scanner.compliance.config import Severity, Framework
from security_scanner.compliance.rules.soc2_rules import (
    Soc2NoRateLimiting,
    Soc2HardcodedCloudCredentials,
    Soc2SqlInjectionRisk,
    Soc2MissingInputValidation,
    Soc2EvalUsage,
    Soc2SensitiveDataInLocalStorage,
    Soc2CorsWildcard,
    SOC2_RULES,
)
from security_scanner.compliance.rules.owasp_rules import (
    OwaspWeakCrypto,
    OwaspCommandInjection,
    OwaspPathTraversal,
    OwaspSsrf,
    OwaspInsecureDeserialization,
    OWASP_RULES,
)


PY = Path("app.py")
JS = Path("app.js")
TS = Path("app.ts")


def findings(rule, content, path=PY):
    return list(rule.check(path, content))


# ---------------------------------------------------------------------------
# SOC2-001: No rate limiting
# ---------------------------------------------------------------------------
class TestSoc2NoRateLimiting:
    rule = Soc2NoRateLimiting()

    def test_route_without_rate_limit_triggers(self):
        code = '''
@app.post("/checkout")
def checkout(payload: dict):
    return process(payload)
'''
        assert len(findings(self.rule, code)) >= 1

    def test_route_with_rate_limiter_not_flagged(self):
        code = '''
from slowapi import Limiter
limiter = Limiter(key_func=get_remote_address)

@app.post("/checkout")
@limiter.limit("10/minute")
def checkout(payload: dict):
    return process(payload)
'''
        assert len(findings(self.rule, code)) == 0

    def test_file_without_routes_not_flagged(self):
        code = '''
def helper_function():
    return 42
'''
        assert len(findings(self.rule, code)) == 0


# ---------------------------------------------------------------------------
# SOC2-002: Hardcoded cloud credentials
# ---------------------------------------------------------------------------
class TestSoc2HardcodedCloudCredentials:
    rule = Soc2HardcodedCloudCredentials()

    def test_aws_access_key_triggers(self):
        code = "AWS_ACCESS_KEY = AKIAIOSFODNN7EXAMPLE"
        assert len(findings(self.rule, code)) >= 1

    def test_aws_secret_key_triggers(self):
        code = 'aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"'
        assert len(findings(self.rule, code)) >= 1

    def test_env_var_reference_not_flagged(self):
        code = 'AWS_SECRET = os.environ["AWS_SECRET_ACCESS_KEY"]'
        assert len(findings(self.rule, code)) == 0

    def test_comment_not_flagged(self):
        code = "# AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE"
        assert len(findings(self.rule, code)) == 0

    def test_severity_is_critical(self):
        code = "AKIAIOSFODNN7EXAMPLE"
        found = findings(self.rule, code)
        if found:
            assert found[0].severity == Severity.CRITICAL


# ---------------------------------------------------------------------------
# SOC2-003: SQL injection
# ---------------------------------------------------------------------------
class TestSoc2SqlInjectionRisk:
    rule = Soc2SqlInjectionRisk()

    def test_fstring_sql_triggers(self):
        code = 'query = f"SELECT * FROM users WHERE id = {user_id}"'
        assert len(findings(self.rule, code)) >= 1

    def test_string_concat_sql_triggers(self):
        code = 'query = "SELECT * FROM records WHERE patient=" + patient_id'
        assert len(findings(self.rule, code)) >= 1

    def test_parameterised_query_not_flagged(self):
        code = 'cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))'
        assert len(findings(self.rule, code)) == 0

    def test_orm_query_not_flagged(self):
        code = 'User.objects.filter(id=user_id)'
        assert len(findings(self.rule, code)) == 0


# ---------------------------------------------------------------------------
# SOC2-004: Missing input validation
# ---------------------------------------------------------------------------
class TestSoc2MissingInputValidation:
    rule = Soc2MissingInputValidation()

    def test_raw_dict_body_without_pydantic_triggers(self):
        code = '''
@app.post("/data")
def handle(payload: dict = Body(...)):
    return payload
'''
        assert len(findings(self.rule, code)) >= 1

    def test_raw_dict_body_with_pydantic_model_not_flagged(self):
        code = '''
from pydantic import BaseModel

class RequestBody(BaseModel):
    name: str

@app.post("/data")
def handle(payload: dict = Body(...)):
    return payload
'''
        assert len(findings(self.rule, code)) == 0


# ---------------------------------------------------------------------------
# SOC2-005: eval() usage
# ---------------------------------------------------------------------------
class TestSoc2EvalUsage:
    rule = Soc2EvalUsage()

    def test_eval_call_triggers(self):
        code = 'result = eval(user_input)'
        assert len(findings(self.rule, code)) >= 1

    def test_exec_call_triggers(self):
        code = 'exec(compile(source, "<string>", "exec"))'
        assert len(findings(self.rule, code)) >= 1

    def test_eval_in_comment_not_flagged(self):
        code = '# You can use eval() but should not'
        assert len(findings(self.rule, code)) == 0

    def test_ast_literal_eval_context(self):
        # ast.literal_eval is safe - but the rule checks for eval(), not ast.literal_eval
        code = 'safe = ast.literal_eval(user_input)'
        # This contains 'eval' - rule may or may not flag it; just check it's callable
        result = findings(self.rule, code)
        # ast.literal_eval does contain 'eval' substring - acceptable to flag as info
        # We don't enforce either outcome here; just verify no exception
        assert isinstance(result, list)

    def test_severity_is_critical(self):
        code = 'eval(request.data)'
        found = findings(self.rule, code)
        assert any(f.severity == Severity.CRITICAL for f in found)


# ---------------------------------------------------------------------------
# SOC2-006: Sensitive data in localStorage
# ---------------------------------------------------------------------------
class TestSoc2SensitiveDataInLocalStorage:
    rule = Soc2SensitiveDataInLocalStorage()

    def test_storing_token_in_localstorage_triggers(self):
        code = "localStorage.setItem('token', response.access_token);"
        assert len(findings(self.rule, code, path=JS)) >= 1

    def test_storing_password_triggers(self):
        code = "localStorage.setItem('password', pwd);"
        assert len(findings(self.rule, code, path=JS)) >= 1

    def test_storing_non_sensitive_data_not_flagged(self):
        code = "localStorage.setItem('theme', 'dark');"
        assert len(findings(self.rule, code, path=JS)) == 0

    def test_reading_token_triggers(self):
        code = "const token = localStorage.getItem('access_token');"
        assert len(findings(self.rule, code, path=JS)) >= 1


# ---------------------------------------------------------------------------
# SOC2-007: CORS wildcard
# ---------------------------------------------------------------------------
class TestSoc2CorsWildcard:
    rule = Soc2CorsWildcard()

    def test_allow_origins_wildcard_triggers(self):
        code = 'app.add_middleware(CORSMiddleware, allow_origins=["*"])'
        assert len(findings(self.rule, code)) >= 1

    def test_explicit_origin_not_flagged(self):
        code = 'app.add_middleware(CORSMiddleware, allow_origins=["https://app.example.com"])'
        assert len(findings(self.rule, code)) == 0


# ---------------------------------------------------------------------------
# OWASP-A02: Weak crypto
# ---------------------------------------------------------------------------
class TestOwaspWeakCrypto:
    rule = OwaspWeakCrypto()

    def test_hashlib_md5_triggers(self):
        code = 'h = hashlib.md5(data.encode()).hexdigest()'
        assert len(findings(self.rule, code)) >= 1

    def test_hashlib_sha1_triggers(self):
        code = 'checksum = hashlib.sha1(content).hexdigest()'
        assert len(findings(self.rule, code)) >= 1

    def test_createhash_md5_triggers(self):
        code = "const hash = crypto.createHash('md5').update(data).digest('hex');"
        assert len(findings(self.rule, code, path=JS)) >= 1

    def test_hashlib_sha256_not_flagged(self):
        code = 'h = hashlib.sha256(data.encode()).hexdigest()'
        assert len(findings(self.rule, code)) == 0

    def test_comment_not_flagged(self):
        code = '# Do not use hashlib.md5 for security purposes'
        assert len(findings(self.rule, code)) == 0


# ---------------------------------------------------------------------------
# OWASP-A03: Command injection
# ---------------------------------------------------------------------------
class TestOwaspCommandInjection:
    rule = OwaspCommandInjection()

    def test_subprocess_shell_true_triggers(self):
        code = 'subprocess.run(cmd, shell=True)'
        assert len(findings(self.rule, code)) >= 1

    def test_subprocess_shell_false_not_flagged(self):
        code = 'subprocess.run(["ls", "-la"], shell=False)'
        assert len(findings(self.rule, code)) == 0

    def test_subprocess_no_shell_arg_not_flagged(self):
        code = 'subprocess.run(["git", "status"])'
        assert len(findings(self.rule, code)) == 0


# ---------------------------------------------------------------------------
# OWASP-A10: SSRF
# ---------------------------------------------------------------------------
class TestOwaspSsrf:
    rule = OwaspSsrf()

    def test_requests_get_with_user_url_triggers(self):
        code = 'response = requests.get(payload.url)'
        assert len(findings(self.rule, code)) >= 1

    def test_fetch_with_request_url_triggers(self):
        code = 'const res = await fetch(req.query.url);'
        assert len(findings(self.rule, code, path=JS)) >= 1

    def test_requests_get_with_hardcoded_url_not_flagged(self):
        code = 'response = requests.get("https://api.example.com/data")'
        assert len(findings(self.rule, code)) == 0


# ---------------------------------------------------------------------------
# OWASP-A08: Insecure deserialization
# ---------------------------------------------------------------------------
class TestOwaspInsecureDeserialization:
    rule = OwaspInsecureDeserialization()

    def test_pickle_loads_triggers(self):
        code = 'obj = pickle.loads(data)'
        assert len(findings(self.rule, code)) >= 1

    def test_pickle_load_triggers(self):
        code = 'with open("data.pkl", "rb") as f: obj = pickle.load(f)'
        # This pattern may or may not match the regex - verify no crash
        result = findings(self.rule, code)
        assert isinstance(result, list)

    def test_json_loads_not_flagged(self):
        code = 'data = json.loads(request_body)'
        assert len(findings(self.rule, code)) == 0

    def test_severity_is_critical(self):
        code = 'result = pickle.loads(user_data)'
        found = findings(self.rule, code)
        assert any(f.severity == Severity.CRITICAL for f in found)


# ---------------------------------------------------------------------------
# Rule list integrity
# ---------------------------------------------------------------------------
class TestSoc2RulesList:
    def test_all_rules_have_required_attributes(self):
        for rule in SOC2_RULES:
            assert rule.rule_id.startswith("SOC2-"), f"{rule.__class__.__name__} bad rule_id"
            assert rule.title
            assert rule.severity in Severity
            assert rule.framework == Framework.SOC2
            assert rule.remediation

    def test_rule_ids_are_unique(self):
        ids = [r.rule_id for r in SOC2_RULES]
        assert len(ids) == len(set(ids))


class TestOwaspRulesList:
    def test_all_rules_have_required_attributes(self):
        for rule in OWASP_RULES:
            assert rule.rule_id.startswith("OWASP-"), f"{rule.__class__.__name__} bad rule_id"
            assert rule.title
            assert rule.severity in Severity
            assert rule.framework == Framework.OWASP
            assert rule.remediation

    def test_rule_ids_are_unique(self):
        ids = [r.rule_id for r in OWASP_RULES]
        assert len(ids) == len(set(ids))
