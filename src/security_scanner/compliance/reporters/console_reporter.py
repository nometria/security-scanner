"""
console_reporter.py - Rich terminal output for scan results.

Renders:
1. Findings table (all findings, sorted by severity)
2. Per-finding remediation details
3. Per-endpoint vulnerability map (if endpoint data is provided)
4. Scan summary panel
"""

from __future__ import annotations

from typing import TYPE_CHECKING, List, Optional

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box
from rich.text import Text
from rich.rule import Rule as RichRule

from security_scanner.compliance.config import Severity

if TYPE_CHECKING:
    from security_scanner.compliance.scanner import ScanReport
    from security_scanner.compliance.endpoint_scanner import EndpointInfo

SEVERITY_COLORS = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}

RISK_COLORS = {
    "CRITICAL": "bold red",
    "HIGH": "red",
    "MEDIUM": "yellow",
    "LOW": "cyan",
    "CLEAN": "green",
}


class ConsoleReporter:
    """Renders a ScanReport to the terminal using Rich."""

    def __init__(self, show_remediation: bool = True):
        self.console = Console()
        self.show_remediation = show_remediation

    def report(
        self,
        scan_report: "ScanReport",
        endpoints: Optional[List["EndpointInfo"]] = None,
    ) -> None:
        self.console.print()
        self._print_header(scan_report)
        self._print_findings(scan_report)
        if endpoints:
            self._print_endpoint_report(endpoints)
        self._print_auto_fix_hint(scan_report)
        self._print_summary(scan_report)

    # ── Header ─────────────────────────────────────────────────────────────

    def _print_header(self, scan_report: "ScanReport") -> None:
        frameworks = " / ".join(f.value for f in scan_report.config.frameworks)
        self.console.print(Panel(
            f"🔒  [bold]{frameworks} Security Scan[/bold]\n"
            f"[dim]Scanning {scan_report.scanned_files} files with "
            f"{scan_report.rules_applied} rules[/dim]",
            style="bold blue",
            border_style="blue",
        ))

    # ── Findings table ──────────────────────────────────────────────────────

    def _print_findings(self, scan_report: "ScanReport") -> None:
        if not scan_report.findings:
            self.console.print("\n[bold green]✅ No findings - clean scan![/bold green]\n")
            return

        table = Table(
            box=box.ROUNDED,
            show_lines=True,
            title=f"[bold]Findings ({len(scan_report.findings)} total)[/bold]",
            highlight=True,
        )
        table.add_column("Rule", style="bold", width=13)
        table.add_column("Sev", width=9)
        table.add_column("FW", width=9)
        table.add_column("File", width=28)
        table.add_column("Line", width=6, justify="right")
        table.add_column("Auto-Fix", width=9, justify="center")
        table.add_column("Title")

        from security_scanner.compliance.fixer import is_auto_fixable

        for f in scan_report.findings:
            color = SEVERITY_COLORS.get(f.severity, "white")
            fixable = "✅" if is_auto_fixable(f) else "❌"
            table.add_row(
                f.rule_id,
                Text(f.severity.value, style=color),
                f.framework.value,
                f.file_path.name[:26],
                str(f.line_number) if f.line_number else "-",
                fixable,
                f.title,
            )

        self.console.print(table)

        if self.show_remediation:
            from security_scanner.compliance.fixer import RULE_TO_FIX
            self.console.print()
            self.console.print(RichRule("[bold]Remediation Details[/bold]", style="dim"))
            for f in scan_report.findings:
                if not f.remediation:
                    continue
                color = SEVERITY_COLORS.get(f.severity, "white")
                auto_fix_note = (
                    f"  [green]⚡ Auto-fixable - run with [bold]--fix[/bold][/green]\n"
                    if f.rule_id in RULE_TO_FIX else ""
                )
                self.console.print(
                    f"\n[{color}]▸ [{f.rule_id}] {f.severity.value}[/{color}]  "
                    f"[bold]{f.title}[/bold]\n"
                    f"  [dim]{f.file_path}:{f.line_number}[/dim]"
                )
                if f.line_content:
                    self.console.print(f"  [dim]Code:[/dim]  [italic]{f.line_content[:120]}[/italic]")
                self.console.print(f"  [dim]Ref:[/dim]   {f.reference}")
                self.console.print(f"{auto_fix_note}  [dim]Fix:[/dim]   {f.remediation[:300]}")

    # ── Per-endpoint vulnerability map ─────────────────────────────────────

    def _print_endpoint_report(self, endpoints: List["EndpointInfo"]) -> None:
        if not endpoints:
            return

        self.console.print()
        self.console.print(RichRule(
            "[bold]API Endpoint Vulnerability Map[/bold]",
            style="bold cyan",
        ))

        table = Table(
            box=box.ROUNDED,
            show_lines=True,
            title=f"[bold]Endpoints ({len(endpoints)} found)[/bold]",
            highlight=True,
        )
        table.add_column("Method", width=8, justify="center")
        table.add_column("Path", width=30)
        table.add_column("File", width=20)
        table.add_column("Auth", width=6, justify="center")
        table.add_column("Schema", width=8, justify="center")
        table.add_column("Rate Limit", width=11, justify="center")
        table.add_column("Risk", width=10)
        table.add_column("Findings", width=8, justify="right")

        METHOD_COLORS = {
            "GET": "green", "POST": "blue", "PUT": "yellow",
            "DELETE": "red", "PATCH": "magenta",
        }

        for ep in endpoints:
            method_color = METHOD_COLORS.get(ep.method, "white")
            risk_color = RISK_COLORS.get(ep.risk_level, "white")

            auth_icon = "✅" if ep.has_auth else "[bold red]❌[/bold red]"
            schema_icon = "✅" if not ep.raw_dict_body else "[bold red]❌[/bold red]"
            rate_icon = "✅" if ep.has_rate_limit else "[yellow]⚠️[/yellow]"

            table.add_row(
                Text(ep.method, style=f"bold {method_color}"),
                ep.path,
                ep.file_path.name[:18],
                auth_icon,
                schema_icon,
                rate_icon,
                Text(ep.risk_level, style=risk_color),
                str(len(ep.findings)),
            )

        self.console.print(table)

        # Detail panel for each endpoint with vulnerabilities
        for ep in endpoints:
            if ep.risk_level == "CLEAN" and not ep.vulnerability_summary:
                continue

            risk_color = RISK_COLORS.get(ep.risk_level, "white")
            issues = "\n".join(f"  {v}" for v in ep.vulnerability_summary)

            self.console.print(
                f"\n[{risk_color}]▸ {ep.method} {ep.path}[/{risk_color}]  "
                f"[dim]{ep.file_path.name}:{ep.line_number}[/dim]  "
                f"handler: [italic]{ep.handler}()[/italic]"
            )
            self.console.print(issues)

    # ── Auto-fix hint ───────────────────────────────────────────────────────

    def _print_auto_fix_hint(self, scan_report: "ScanReport") -> None:
        from security_scanner.compliance.fixer import is_auto_fixable
        fixable_count = sum(1 for f in scan_report.findings if is_auto_fixable(f))
        if fixable_count > 0:
            self.console.print()
            self.console.print(Panel(
                f"⚡ [bold green]{fixable_count} findings can be auto-fixed.[/bold green]  "
                f"Re-run with [bold]--fix[/bold] to apply them interactively.\n"
                f"[dim]Run with [bold]--checklist[/bold] to generate the manual action checklist.[/dim]",
                border_style="green",
            ))

    # ── Summary ─────────────────────────────────────────────────────────────

    def _print_summary(self, scan_report: "ScanReport") -> None:
        from security_scanner.compliance.fixer import is_auto_fixable
        fixable = sum(1 for f in scan_report.findings if is_auto_fixable(f))
        manual = len(scan_report.findings) - fixable

        status_color = "green" if scan_report.passed else "red"
        status_icon = "✅" if scan_report.passed else "❌"

        self.console.print()
        self.console.print(Panel(
            f"[bold]Scan Summary[/bold]\n\n"
            f"  Files scanned  : {scan_report.scanned_files}\n"
            f"  Rules applied  : {scan_report.rules_applied}\n\n"
            f"  [bold red]CRITICAL   : {len(scan_report.critical)}[/bold red]\n"
            f"  [red]HIGH       : {len(scan_report.high)}[/red]\n"
            f"  [yellow]MEDIUM     : {len(scan_report.medium)}[/yellow]\n"
            f"  [cyan]LOW        : {len(scan_report.low)}[/cyan]\n\n"
            f"  [green]Auto-fixable: {fixable}[/green]  "
            f"[yellow](run --fix to apply)[/yellow]\n"
            f"  [dim]Manual action: {manual}  (run --checklist to see full list)[/dim]\n\n"
            f"  [{status_color}]{status_icon} Status: "
            f"{'PASSED' if scan_report.passed else 'FAILED'}[/{status_color}]",
            border_style=status_color,
        ))
