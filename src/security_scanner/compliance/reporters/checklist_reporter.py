"""
checklist_reporter.py - Generates the manual compliance action checklist.

Items that cannot be auto-fixed (MFA, BAA contracts, RLS schema design,
FedRAMP PIV/CAC, encryption at rest, audit logging, etc.) are rendered
as an actionable checklist - both to the terminal and as a Markdown file.

Usage:
    from security_scanner.compliance.reporters.checklist_reporter import ChecklistReporter
    reporter = ChecklistReporter()
    reporter.report(findings, output_file=Path("COMPLIANCE_CHECKLIST.md"))
"""

from __future__ import annotations

import datetime
from pathlib import Path
from typing import List, Optional, TYPE_CHECKING

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box


if TYPE_CHECKING:
    from security_scanner.compliance.scanner import ScanReport

console = Console()

# ---------------------------------------------------------------------------
# Static manual checklist items (always emitted regardless of findings)
# These are architectural/process items that code scanners can't detect
# ---------------------------------------------------------------------------

MANUAL_ITEMS = [
    # ── MFA ──────────────────────────────────────────────────────────────
    {
        "id": "MAN-001",
        "framework": "HIPAA/FedRAMP",
        "severity": "CRITICAL",
        "title": "Implement Multi-Factor Authentication (MFA)",
        "description": (
            "Neither HIPAA (164.312(d)) nor FedRAMP (IA-2) allow password-only "
            "access to systems handling protected data. FedRAMP treats this as a "
            "hard requirement - not addressable."
        ),
        "steps": [
            "Enable Supabase Auth MFA in the Supabase dashboard: Auth → Settings → Multi-factor auth",
            "Add TOTP enrollment flow: `supabase.auth.mfa.enroll({ factorType: 'totp' })`",
            "Add challenge/verify flow before granting access to sensitive operations",
            "Make MFA mandatory for admin/operator roles; strongly encourage for all users",
            "Store MFA enforcement status in user metadata and enforce server-side",
            "Supabase docs: https://supabase.com/docs/guides/auth/auth-mfa",
        ],
        "evidence": "Screenshot of MFA enrollment screen + Supabase Auth settings showing MFA required",
        "category": "Authentication",
    },

    # ── BAA: OpenAI ───────────────────────────────────────────────────────
    {
        "id": "MAN-002",
        "framework": "HIPAA",
        "severity": "CRITICAL",
        "title": "Sign Business Associate Agreement (BAA) with OpenAI",
        "description": (
            "The codebase sends document content to the OpenAI API. If that content "
            "contains PHI (Protected Health Information), this is a HIPAA disclosure "
            "to a third party without a BAA - a reportable breach under §164.314(a)."
        ),
        "steps": [
            "Evaluate whether any document content sent to OpenAI could contain PHI",
            "Option A: Sign a BAA with OpenAI - available on the Enterprise tier (contact sales@openai.com)",
            "Option B: Strip all PHI BEFORE constructing the OpenAI prompt (de-identification per §164.514)",
            "Option C: Replace OpenAI with a self-hosted model (e.g. Llama 3 on your own infrastructure)",
            "Document the chosen approach in your Risk Assessment",
            "If using Option A, store a copy of the signed BAA in your compliance documentation",
        ],
        "evidence": "Signed BAA document or de-identification code review + test cases",
        "category": "Third-party / Contracts",
    },

    # ── BAA: Sentry ───────────────────────────────────────────────────────
    {
        "id": "MAN-003",
        "framework": "HIPAA",
        "severity": "HIGH",
        "title": "Configure Sentry PHI filtering + evaluate BAA requirement",
        "description": (
            "Sentry captures error context, stack traces, and breadcrumbs. "
            "If PHI appears in exceptions or variables, it could flow to Sentry's servers. "
            "Sentry offers a HIPAA BAA only on specific enterprise plans."
        ),
        "steps": [
            "Implement `beforeSend` hook to redact PHI from all Sentry events:",
            "  Sentry.init({ beforeSend(event) { /* strip PHI fields */ return event; } })",
            "Fields to redact: email, name, ssn, dob, address, file_url, patient_id",
            "Contact Sentry sales to sign a HIPAA BAA if PHI could reach their servers",
            "Alternatively, self-host Sentry (open-source) or switch to a HIPAA-compliant APM",
            "Configure Sentry data scrubbing in the Sentry dashboard as a secondary defense",
        ],
        "evidence": "Sentry `beforeSend` code review + BAA document",
        "category": "Third-party / Contracts",
    },

    # ── BAA: Mixpanel ─────────────────────────────────────────────────────
    {
        "id": "MAN-004",
        "framework": "HIPAA",
        "severity": "MEDIUM",
        "title": "Evaluate Mixpanel for PHI exposure + BAA",
        "description": (
            "Mixpanel is called with `currentUser.email` and `plan` metadata. "
            "Email is considered PII and potentially PHI depending on context. "
            "Mixpanel has a HIPAA compliance program; evaluate whether a BAA is needed."
        ),
        "steps": [
            "Audit all Mixpanel `identify()` and `people.set()` calls for PHI",
            "Replace email with an opaque user UUID in Mixpanel identify calls",
            "Contact Mixpanel to sign a BAA if any PHI is tracked",
            "Consider replacing Mixpanel with PostHog (self-hostable, open-source)",
            "Reference: https://mixpanel.com/legal/hipaa",
        ],
        "evidence": "Updated Mixpanel calls using UUID only + optional BAA",
        "category": "Third-party / Contracts",
    },

    # ── Row Level Security ─────────────────────────────────────────────────
    {
        "id": "MAN-005",
        "framework": "HIPAA/FedRAMP/SOC2",
        "severity": "CRITICAL",
        "title": "Enable Row Level Security (RLS) on all Supabase tables",
        "description": (
            "Without RLS, any user holding the `authenticated` Supabase role can "
            "read or write any row in any table - bypassing all tenant/user isolation. "
            "AC-3 (Access Enforcement) and AC-6 (Least Privilege) both require this."
        ),
        "steps": [
            "List all tables: SELECT tablename FROM pg_tables WHERE schemaname = 'public';",
            "For each table, enable RLS: ALTER TABLE <table> ENABLE ROW LEVEL SECURITY;",
            "Create user-isolation policy:\n"
            "  CREATE POLICY user_isolation ON <table>\n"
            "    FOR ALL\n"
            "    USING (user_id = auth.uid())\n"
            "    WITH CHECK (user_id = auth.uid());",
            "For multi-tenant tables, scope by org_id:\n"
            "  USING (org_id = (SELECT org_id FROM users WHERE id = auth.uid()))",
            "Test: log in as User A, verify you cannot access User B's rows via PostgREST",
            "Alternatively, move ALL DB operations to the backend and disable direct PostgREST access",
        ],
        "evidence": "SQL migration files with RLS + integration test showing isolation",
        "category": "Database",
    },

    # ── Encryption at rest ─────────────────────────────────────────────────
    {
        "id": "MAN-006",
        "framework": "HIPAA/FedRAMP",
        "severity": "HIGH",
        "title": "Implement encryption at rest for PHI data and uploaded files",
        "description": (
            "HIPAA §164.312(a)(2)(iv) and FedRAMP SC-28 require PHI to be encrypted "
            "at rest using FIPS 140-2 validated cryptography. Currently, uploaded files "
            "and database fields are stored in plaintext."
        ),
        "steps": [
            "Enable S3 bucket encryption: SSE-KMS with an AWS KMS Customer Managed Key",
            "  aws s3api put-bucket-encryption --bucket own-my-app ...",
            "Enable Supabase Vault for sensitive column encryption:",
            "  SELECT vault.create_secret('my_secret', 'my_key_name');",
            "Enable transparent data encryption (TDE) in PostgreSQL via pgcrypto or pgsodium",
            "For temp files in the OCR pipeline: encrypt with an ephemeral key on write,",
            "  wipe the key immediately after processing, use secure deletion",
            "Document the key management procedure (rotation schedule, access controls)",
        ],
        "evidence": "S3 encryption config + Supabase Vault migration + key rotation runbook",
        "category": "Encryption",
    },

    # ── Audit logging ──────────────────────────────────────────────────────
    {
        "id": "MAN-007",
        "framework": "HIPAA/FedRAMP/SOC2",
        "severity": "HIGH",
        "title": "Implement structured audit logging for all data access",
        "description": (
            "HIPAA §164.312(b) requires audit controls. FedRAMP AU-2 requires logging "
            "of logon/logoff, privilege use, account management, file access, and "
            "process creation. Logs must be retained for 90 days online, 1 year archived "
            "(FedRAMP) or 6 years (HIPAA)."
        ),
        "steps": [
            "Create an `audit_log` table in Supabase:",
            "  CREATE TABLE audit_log (",
            "    id UUID DEFAULT gen_random_uuid() PRIMARY KEY,",
            "    user_id UUID REFERENCES auth.users(id),",
            "    action TEXT NOT NULL,",
            "    resource_type TEXT,",
            "    resource_id TEXT,",
            "    ip_address INET,",
            "    user_agent TEXT,",
            "    result TEXT,",
            "    created_at TIMESTAMPTZ DEFAULT NOW()",
            "  );",
            "Add FastAPI middleware that writes to audit_log on every request",
            "Configure log retention: CloudWatch 90-day retention + S3 Glacier 6-year archive",
            "Enable Supabase's built-in Auth audit logs: Auth → Audit Logs",
            "Ship application logs to SIEM (Datadog, Splunk, or AWS Security Hub)",
        ],
        "evidence": "audit_log table migration + middleware code + log retention policy",
        "category": "Logging & Monitoring",
    },

    # ── Password policy ────────────────────────────────────────────────────
    {
        "id": "MAN-008",
        "framework": "HIPAA/FedRAMP",
        "severity": "HIGH",
        "title": "Enforce password complexity and history policy",
        "description": (
            "FedRAMP IA-5 requires: ≥15 characters, uppercase, lowercase, number, special char, "
            "60-day max age, no reuse of last 5 passwords. HIPAA 2025 NPRM requires similar. "
            "Currently, the auth form only checks for non-empty email/password."
        ),
        "steps": [
            "Configure Supabase Auth password strength: Auth → Settings → Password strength",
            "Add client-side validation in Auth.jsx:",
            "  - Minimum 12 characters (15 for FedRAMP)",
            "  - At least 1 uppercase, 1 lowercase, 1 number, 1 special character",
            "  - Check against haveibeenpwned.com API for known breached passwords",
            "Add server-side validation in a Supabase Auth hook (Edge Function)",
            "Implement password history: store bcrypt hashes of last 5 passwords",
            "Configure password expiry notification at 45 days, enforcement at 60 days",
        ],
        "evidence": "Auth.jsx validation code + Supabase password strength config",
        "category": "Authentication",
    },

    # ── Account lockout ────────────────────────────────────────────────────
    {
        "id": "MAN-009",
        "framework": "HIPAA/FedRAMP",
        "severity": "HIGH",
        "title": "Implement account lockout after failed login attempts",
        "description": (
            "FedRAMP AC-7 requires automatic account lockout after a defined number "
            "of consecutive failed login attempts. Supabase has rate limiting but it "
            "needs to be explicitly configured."
        ),
        "steps": [
            "Configure Supabase Auth rate limiting: Auth → Settings → Rate limits",
            "Set: max 5 failed attempts, 5-minute lockout, escalating to 30 minutes",
            "Add client-side exponential backoff in Auth.jsx on AuthApiError",
            "Implement admin notification for repeated failed attempts (potential brute-force)",
            "Log all failed attempts to audit_log with IP address",
        ],
        "evidence": "Supabase Auth rate limit config screenshot + client-side backoff code",
        "category": "Authentication",
    },

    # ── Breach notification ────────────────────────────────────────────────
    {
        "id": "MAN-010",
        "framework": "HIPAA",
        "severity": "MEDIUM",
        "title": "Implement breach detection and notification capability",
        "description": (
            "HIPAA §164.400-414 (Breach Notification Rule) requires notifying affected "
            "individuals within 60 days of discovering a breach of unsecured PHI. "
            "HHS must be notified within 60 days. No detection capability exists."
        ),
        "steps": [
            "Implement anomaly detection: alert on bulk data export (>100 records in 1 minute)",
            "Alert on access from unusual geolocations or off-hours access",
            "Define your breach response runbook (who to notify, timeline, template)",
            "Integrate with AWS GuardDuty or similar IDS/IPS",
            "Test the breach notification process annually",
            "Register with HHS HITECH breach portal: https://ocrportal.hhs.gov/ocr/breach/wizard_reporting.jsf",
        ],
        "evidence": "Anomaly alert config + breach response runbook",
        "category": "Incident Response",
    },

    # ── Secrets rotation ──────────────────────────────────────────────────
    {
        "id": "MAN-011",
        "framework": "SOC2/FedRAMP",
        "severity": "HIGH",
        "title": "Establish secrets rotation and management process",
        "description": (
            "The .env file contains multiple long-lived credentials. "
            "SOC2 CC6.1 and FedRAMP IA-5 require credential rotation. "
            "FedRAMP requires API key rotation at least annually, "
            "privileged credentials at 60-90 days."
        ),
        "steps": [
            "Migrate all secrets from .env to AWS Secrets Manager or HashiCorp Vault",
            "Enable automatic rotation for database passwords (RDS supports this natively)",
            "Set rotation schedule: DB passwords every 90 days, API keys every 180 days",
            "Add secret scanning to CI/CD: `detect-secrets scan` or GitHub secret scanning",
            "Revoke and rotate all credentials that have been in the .env file in git history",
            "Run: git filter-repo or BFG Repo Cleaner to purge secrets from git history",
        ],
        "evidence": "AWS Secrets Manager config + rotation schedule documentation",
        "category": "Secrets Management",
    },

    # ── Dependency scanning ───────────────────────────────────────────────
    {
        "id": "MAN-012",
        "framework": "SOC2/FedRAMP",
        "severity": "MEDIUM",
        "title": "Add automated dependency vulnerability scanning to CI/CD",
        "description": (
            "FedRAMP SI-2 and SOC2 CC7.1 require identifying and remediating "
            "software vulnerabilities. No dependency scanning is configured."
        ),
        "steps": [
            "Add pip-audit to CI: `pip-audit --output json --output-file audit.json`",
            "Add npm audit to CI: `npm audit --audit-level=high`",
            "Enable Dependabot in the GitHub repository settings",
            "Add trivy for container scanning: `trivy image your-image:tag`",
            "Set CI to fail on HIGH or CRITICAL CVEs",
            "Review and update pinned versions in requirements.txt (especially opencv-python, easyocr)",
        ],
        "evidence": "CI pipeline config showing audit steps + Dependabot config",
        "category": "Dependency Management",
    },

    # ── FedRAMP PIV/CAC ───────────────────────────────────────────────────
    {
        "id": "MAN-013",
        "framework": "FedRAMP",
        "severity": "MEDIUM",
        "title": "[FedRAMP only] PIV/CAC or FICAM-approved credential support",
        "description": (
            "FedRAMP IA-8 requires that non-organizational users be identified and "
            "authenticated using FICAM-approved credentials. For federal agency use, "
            "PIV/CAC card support or a FICAM-approved Identity Provider is required."
        ),
        "steps": [
            "Evaluate whether your users are federal employees (PIV/CAC required) or public",
            "If federal: integrate with Login.gov or MAX.gov as the Identity Provider",
            "Login.gov OIDC integration: https://developers.login.gov/oidc/",
            "Configure Supabase Auth to accept the Login.gov OIDC token",
            "Document the authentication chain in your System Security Plan (SSP)",
        ],
        "evidence": "Login.gov integration code + SSP documentation",
        "category": "Authentication",
    },

    # ── System Security Plan ──────────────────────────────────────────────
    {
        "id": "MAN-014",
        "framework": "FedRAMP",
        "severity": "MEDIUM",
        "title": "[FedRAMP only] Prepare System Security Plan (SSP)",
        "description": (
            "FedRAMP requires a System Security Plan that documents how each "
            "NIST SP 800-53 control is implemented. This is a prerequisite for "
            "the 3PAO (Third-Party Assessment Organization) assessment."
        ),
        "steps": [
            "Use the FedRAMP SSP template: https://www.fedramp.gov/documents-templates/",
            "Document all 325 Moderate baseline controls (implement, inherit, or plan)",
            "Identify which controls are inherited from your CSP (AWS, if using AWS infrastructure)",
            "Submit to a FedRAMP-accredited 3PAO for assessment",
            "Plan for 12-18 months for full FedRAMP authorization",
        ],
        "evidence": "Completed SSP document + 3PAO engagement letter",
        "category": "Compliance Program",
    },
]


# ---------------------------------------------------------------------------
# Reporter class
# ---------------------------------------------------------------------------

class ChecklistReporter:
    """
    Generates the manual compliance action checklist.

    Combines:
    1. Static manual items (MAN-001 through MAN-014)
    2. Non-fixable findings from the scan (findings where auto_fixable=False)

    Outputs to terminal (Rich) and optionally to a Markdown file.
    """

    def __init__(self):
        self.console = console

    def report(
        self,
        scan_report: "ScanReport",
        output_file: Optional[Path] = None,
    ) -> None:
        """Render the checklist to terminal and optionally write Markdown."""
        self._print_terminal(scan_report)
        if output_file:
            self._write_markdown(scan_report, output_file)
            self.console.print(f"\n[green]📋 Checklist written to: {output_file}[/green]")

    def _print_terminal(self, scan_report: "ScanReport") -> None:
        self.console.print()
        self.console.print(Panel(
            "📋 [bold]Manual Action Checklist[/bold]\n\n"
            "[dim]These items cannot be auto-fixed and require engineering, "
            "legal, or operational action.[/dim]",
            border_style="cyan",
        ))

        # Categorise items
        by_category: dict[str, list] = {}
        for item in MANUAL_ITEMS:
            by_category.setdefault(item["category"], []).append(item)

        for category, items in sorted(by_category.items()):
            self.console.print(f"\n[bold cyan]── {category} ──[/bold cyan]")
            for item in items:
                sev_icon = {
                    "CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵"
                }.get(item["severity"], "⚪")
                sev_color = {
                    "CRITICAL": "bold red", "HIGH": "red",
                    "MEDIUM": "yellow", "LOW": "cyan"
                }.get(item["severity"], "white")

                self.console.print(
                    f"\n  {sev_icon} [{sev_color}][{item['id']}][/{sev_color}]  "
                    f"[bold]{item['title']}[/bold]  "
                    f"[dim]({item['framework']})[/dim]"
                )
                self.console.print(f"  [dim]{item['description'][:120]}...[/dim]")

        # Summary table
        self.console.print()
        table = Table(
            box=box.SIMPLE,
            title="[bold]Checklist Summary[/bold]",
            show_header=True,
        )
        table.add_column("ID", style="bold", width=10)
        table.add_column("Severity", width=10)
        table.add_column("Title", width=50)
        table.add_column("Framework", width=16)
        table.add_column("Category", width=22)

        sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        sorted_items = sorted(MANUAL_ITEMS, key=lambda i: sev_order.get(i["severity"], 9))

        for item in sorted_items:
            sev_color = {
                "CRITICAL": "bold red", "HIGH": "red",
                "MEDIUM": "yellow", "LOW": "cyan"
            }.get(item["severity"], "white")
            table.add_row(
                item["id"],
                f"[{sev_color}]{item['severity']}[/{sev_color}]",
                item["title"][:48],
                item["framework"],
                item["category"],
            )
        self.console.print(table)

    def _write_markdown(
        self, scan_report: "ScanReport", output_file: Path
    ) -> None:
        """Write full actionable checklist as a Markdown file."""
        lines: List[str] = []
        now = datetime.datetime.utcnow().strftime("%Y-%m-%d")

        lines += [
            "# Compliance Manual Action Checklist",
            f"> Generated: {now}  ",
            "> These items require engineering, legal, or operational action - they cannot be auto-fixed by the scanner.",
            "",
            "---",
            "",
        ]

        sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        sorted_items = sorted(MANUAL_ITEMS, key=lambda i: sev_order.get(i["severity"], 9))

        for item in sorted_items:
            sev_badge = {
                "CRITICAL": "🔴 CRITICAL",
                "HIGH": "🟠 HIGH",
                "MEDIUM": "🟡 MEDIUM",
                "LOW": "🔵 LOW",
            }.get(item["severity"], item["severity"])

            lines += [
                f"## [{item['id']}] {item['title']}",
                "",
                "| Field | Value |",
                "|---|---|",
                f"| **Severity** | {sev_badge} |",
                f"| **Framework** | {item['framework']} |",
                f"| **Category** | {item['category']} |",
                f"| **Evidence Required** | {item['evidence']} |",
                "",
                f"**Description:** {item['description']}",
                "",
                "**Action Steps:**",
                "",
            ]
            for step in item["steps"]:
                lines.append(f"- [ ] {step}")

            lines += ["", "---", ""]

        # Add non-auto-fixable findings from the scan
        non_fixable_findings = [
            f for f in scan_report.findings
            if not _is_auto_fixable_rule(f.rule_id)
        ]
        if non_fixable_findings:
            lines += [
                "## Scan Findings Requiring Manual Action",
                "",
                "These were detected by the scanner but require manual remediation:",
                "",
            ]
            for f in non_fixable_findings:
                lines += [
                    f"### [{f.rule_id}] {f.title}",
                    "",
                    f"- **Severity:** {f.severity.value}",
                    f"- **Framework:** {f.framework.value}",
                    f"- **File:** `{f.file_path}` line {f.line_number}",
                    f"- **Reference:** {f.reference}",
                    "",
                    f"**Description:** {f.description}",
                    "",
                    f"**Remediation:** {f.remediation}",
                    "",
                    "---",
                    "",
                ]

        output_file.write_text("\n".join(lines), encoding="utf-8")


def _is_auto_fixable_rule(rule_id: str) -> bool:
    """Return True if this rule_id has an auto-fix available."""
    from security_scanner.compliance.fixer import RULE_TO_FIX
    return rule_id in RULE_TO_FIX
