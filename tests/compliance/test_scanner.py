"""
test_scanner.py - Integration tests for the Scanner and ScanReport.

Tests the full pipeline: config → scanner → report, using temp filesystem
content. No network I/O. Uses only rules that ship with the package.
"""

import json
import pytest
from pathlib import Path

from security_scanner.compliance.config import Framework, Severity, ScanConfig
from security_scanner.compliance.scanner import Scanner, ScanReport
from security_scanner.compliance.rules.hipaa_rules import HipaaHardcodedCredentials, HipaaUnencryptedHttp
from security_scanner.compliance.rules.soc2_rules import Soc2EvalUsage
from security_scanner.compliance.rules.owasp_rules import OwaspWeakCrypto


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def minimal_config(tmp_path):
    return ScanConfig(
        paths=[tmp_path],
        frameworks=[Framework.HIPAA, Framework.SOC2, Framework.OWASP],
        min_severity=Severity.LOW,
        fail_on=Severity.HIGH,
    )


@pytest.fixture()
def scanner_with_rules(minimal_config):
    """Scanner that only runs a small set of well-understood rules."""
    return Scanner(
        minimal_config,
        rules=[
            HipaaHardcodedCredentials(),
            HipaaUnencryptedHttp(),
            Soc2EvalUsage(),
            OwaspWeakCrypto(),
        ],
    )


def write_file(path: Path, name: str, content: str) -> Path:
    f = path / name
    f.write_text(content, encoding="utf-8")
    return f


# ---------------------------------------------------------------------------
# Scanner.scan_content() - unit-level API
# ---------------------------------------------------------------------------

class TestScanContent:
    def test_clean_code_returns_no_findings(self, scanner_with_rules):
        code = '''
import hashlib
password = os.getenv("DB_PASS")
url = "https://api.example.com"
'''
        result = scanner_with_rules.scan_content(code, Path("clean.py"))
        assert result == []

    def test_hardcoded_password_detected(self, scanner_with_rules):
        code = 'db_password = "s3cr3tP@ssw0rd"'
        result = scanner_with_rules.scan_content(code, Path("bad.py"))
        assert any(f.rule_id == "HIPAA-001" for f in result)

    def test_http_url_detected(self, scanner_with_rules):
        code = 'API = "http://prod.api.company.com/data"'
        result = scanner_with_rules.scan_content(code, Path("urls.py"))
        assert any(f.rule_id == "HIPAA-003" for f in result)

    def test_md5_usage_detected(self, scanner_with_rules):
        code = 'digest = hashlib.md5(data).hexdigest()'
        result = scanner_with_rules.scan_content(code, Path("crypto.py"))
        assert any(f.rule_id == "OWASP-A02" for f in result)

    def test_finding_has_correct_file_path(self, scanner_with_rules):
        target = Path("myfile.py")
        code = 'secret = "realpassword123456"'
        result = scanner_with_rules.scan_content(code, target)
        if result:
            assert result[0].file_path == target


# ---------------------------------------------------------------------------
# Scanner.scan() - filesystem-level
# ---------------------------------------------------------------------------

class TestScannerFilesystem:
    def test_clean_directory_passes(self, scanner_with_rules, tmp_path):
        write_file(tmp_path, "clean.py", 'x = os.getenv("SECRET")\nurl = "https://ok.com"\n')
        report = scanner_with_rules.scan()
        assert report.passed

    def test_dirty_file_generates_findings(self, scanner_with_rules, tmp_path):
        write_file(tmp_path, "bad.py", 'password = "HardcodedPassword123!"')
        report = scanner_with_rules.scan()
        assert len(report.findings) >= 1

    def test_node_modules_excluded(self, scanner_with_rules, minimal_config, tmp_path):
        nm = tmp_path / "node_modules" / "lib"
        nm.mkdir(parents=True)
        write_file(nm, "vuln.py", 'password = "ShouldBeIgnored123"')

        report = scanner_with_rules.scan()
        assert all("node_modules" not in str(f.file_path) for f in report.findings)

    def test_multiple_files_scanned(self, scanner_with_rules, tmp_path):
        write_file(tmp_path, "file1.py", 'x = 1\n')
        write_file(tmp_path, "file2.py", 'y = 2\n')
        write_file(tmp_path, "file3.js", 'const z = 3;\n')
        report = scanner_with_rules.scan()
        assert report.scanned_files >= 3

    def test_unreadable_file_does_not_crash_scanner(self, scanner_with_rules, tmp_path):
        f = write_file(tmp_path, "noread.py", 'x = 1')
        f.chmod(0o000)
        try:
            report = scanner_with_rules.scan()
            # Should not raise
            assert report is not None
        finally:
            f.chmod(0o644)  # Restore for cleanup


# ---------------------------------------------------------------------------
# ScanReport properties
# ---------------------------------------------------------------------------

class TestScanReport:
    def _make_report(self, findings, config=None):
        config = config or ScanConfig(paths=[Path(".")], fail_on=Severity.HIGH)
        return ScanReport(
            findings=findings,
            scanned_files=10,
            skipped_files=0,
            rules_applied=5,
            config=config,
        )

    def test_passed_when_no_findings(self):
        report = self._make_report([])
        assert report.passed is True

    def test_failed_when_critical_finding(self):
        from security_scanner.compliance.rules.base import Finding
        finding = Finding(
            rule_id="HIPAA-001",
            title="Test",
            description="desc",
            severity=Severity.CRITICAL,
            framework=Framework.HIPAA,
            reference="ref",
            file_path=Path("test.py"),
        )
        report = self._make_report([finding])
        assert report.passed is False

    def test_passed_when_only_low_findings(self):
        from security_scanner.compliance.rules.base import Finding
        config = ScanConfig(paths=[Path(".")], fail_on=Severity.HIGH)
        finding = Finding(
            rule_id="HIPAA-007",
            title="Test",
            description="desc",
            severity=Severity.LOW,
            framework=Framework.HIPAA,
            reference="ref",
            file_path=Path("test.py"),
        )
        report = self._make_report([finding], config=config)
        assert report.passed is True

    def test_by_framework_groups_correctly(self):
        from security_scanner.compliance.rules.base import Finding
        findings = [
            Finding("HIPAA-001", "t", "d", Severity.HIGH, Framework.HIPAA, "r", Path("a.py")),
            Finding("SOC2-001", "t", "d", Severity.MEDIUM, Framework.SOC2, "r", Path("b.py")),
        ]
        report = self._make_report(findings)
        assert len(report.by_framework[Framework.HIPAA]) == 1
        assert len(report.by_framework[Framework.SOC2]) == 1

    def test_summary_string_contains_counts(self):
        report = self._make_report([])
        summary = report.summary()
        assert "CRITICAL" in summary
        assert "HIGH" in summary


# ---------------------------------------------------------------------------
# JSON Reporter
# ---------------------------------------------------------------------------

class TestJsonReporter:
    def test_json_output_is_valid(self, scanner_with_rules, tmp_path):
        write_file(tmp_path, "code.py", 'pw = "hardcoded_secret_value_123"')
        report = scanner_with_rules.scan()

        from security_scanner.compliance.reporters import JsonReporter
        output = JsonReporter().report(report)
        data = json.loads(output)

        assert "findings" in data
        assert "summary" in data
        assert "passed" in data
        assert isinstance(data["findings"], list)

    def test_json_report_to_file(self, scanner_with_rules, tmp_path, tmp_path_factory):
        out_file = tmp_path_factory.mktemp("reports") / "report.json"
        write_file(tmp_path, "code.py", 'x = 1')
        report = scanner_with_rules.scan()

        from security_scanner.compliance.reporters import JsonReporter
        JsonReporter(output_file=out_file).report(report)

        assert out_file.exists()
        data = json.loads(out_file.read_text())
        assert "findings" in data
