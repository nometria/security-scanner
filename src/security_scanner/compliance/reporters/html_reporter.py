"""
html_reporter.py - Self-contained HTML report for human review.
"""

from __future__ import annotations
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    from security_scanner.compliance.scanner import ScanReport

_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Security Scan Report</title>
<style>
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
         background: #0f172a; color: #e2e8f0; margin: 0; padding: 2rem; }
  h1   { color: #60a5fa; border-bottom: 1px solid #1e3a5f; padding-bottom: 1rem; }
  .badge { display: inline-block; padding: 2px 10px; border-radius: 9999px;
           font-size: 0.75rem; font-weight: 700; text-transform: uppercase; }
  .CRITICAL { background: #7f1d1d; color: #fca5a5; }
  .HIGH     { background: #7c2d12; color: #fdba74; }
  .MEDIUM   { background: #78350f; color: #fde68a; }
  .LOW      { background: #1e3a5f; color: #93c5fd; }
  table { width: 100%; border-collapse: collapse; margin-top: 1.5rem; }
  th    { background: #1e293b; text-align: left; padding: 0.75rem; }
  td    { padding: 0.6rem 0.75rem; border-bottom: 1px solid #1e293b;
          vertical-align: top; max-width: 400px; overflow-wrap: break-word; }
  tr:hover td { background: #1e293b; }
  .pass { color: #4ade80; } .fail { color: #f87171; }
  .summary-grid { display: grid; grid-template-columns: repeat(5, 1fr);
                  gap: 1rem; margin: 1.5rem 0; }
  .card { background: #1e293b; border-radius: 8px; padding: 1rem; text-align: center; }
  .card .num { font-size: 2rem; font-weight: 700; }
  pre  { font-size: 0.75rem; background: #0f172a; padding: 0.5rem;
         border-radius: 4px; white-space: pre-wrap; }
</style>
</head>
<body>
<h1>🔒 HIPAA / SOC2 / OWASP Security Scan Report</h1>
<p>Generated: <strong>{{ timestamp }}</strong> &nbsp;|&nbsp;
   Status: <strong class="{{ 'pass' if passed else 'fail' }}">
   {{ '✅ PASSED' if passed else '❌ FAILED' }}</strong></p>

<div class="summary-grid">
  <div class="card"><div class="num">{{ total }}</div><div>Total</div></div>
  <div class="card"><div class="num CRITICAL" style="color:#fca5a5">{{ critical }}</div><div>Critical</div></div>
  <div class="card"><div class="num HIGH" style="color:#fdba74">{{ high }}</div><div>High</div></div>
  <div class="card"><div class="num MEDIUM" style="color:#fde68a">{{ medium }}</div><div>Medium</div></div>
  <div class="card"><div class="num LOW" style="color:#93c5fd">{{ low }}</div><div>Low</div></div>
</div>

<table>
  <thead>
    <tr>
      <th>Rule</th><th>Severity</th><th>Framework</th>
      <th>File : Line</th><th>Title</th><th>Code / Remediation</th>
    </tr>
  </thead>
  <tbody>
    {% for f in findings %}
    <tr>
      <td><code>{{ f.rule_id }}</code></td>
      <td><span class="badge {{ f.severity }}">{{ f.severity }}</span></td>
      <td>{{ f.framework }}</td>
      <td><code>{{ f.file_name }}:{{ f.line_number }}</code></td>
      <td>{{ f.title }}</td>
      <td>
        {% if f.line_content %}<pre>{{ f.line_content }}</pre>{% endif %}
        <small>{{ f.remediation }}</small>
      </td>
    </tr>
    {% endfor %}
    {% if not findings %}
    <tr><td colspan="6" style="text-align:center;color:#4ade80">
      ✅ No findings - all checks passed!
    </td></tr>
    {% endif %}
  </tbody>
</table>
</body>
</html>"""


class HtmlReporter:
    """Generates a self-contained HTML report."""

    def __init__(self, output_file: Optional[Path] = None):
        self.output_file = output_file

    def report(self, scan_report: "ScanReport") -> str:
        try:
            from jinja2 import Environment
            env = Environment(autoescape=True)
            template = env.from_string(_TEMPLATE)
        except ImportError:
            # Jinja2 not installed - fall back to simple string substitution
            return self._simple_render(scan_report)

        rows = []
        for f in scan_report.findings:
            rows.append({
                "rule_id": f.rule_id,
                "severity": f.severity.value,
                "framework": f.framework.value,
                "file_name": f.file_path.name,
                "line_number": f.line_number,
                "title": f.title,
                "line_content": f.line_content,
                "remediation": f.remediation,
            })

        html = template.render(
            timestamp=datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
            passed=scan_report.passed,
            total=len(scan_report.findings),
            critical=len(scan_report.critical),
            high=len(scan_report.high),
            medium=len(scan_report.medium),
            low=len(scan_report.low),
            findings=rows,
        )

        if self.output_file:
            Path(self.output_file).write_text(html, encoding="utf-8")
        else:
            print(html)

        return html

    def _simple_render(self, scan_report: "ScanReport") -> str:
        """Fallback when Jinja2 is unavailable."""
        lines = [f"<h1>Security Scan: {len(scan_report.findings)} findings</h1><ul>"]
        for f in scan_report.findings:
            lines.append(
                f"<li>[{f.severity.value}] {f.rule_id} - {f.title} "
                f"({f.file_path.name}:{f.line_number})</li>"
            )
        lines.append("</ul>")
        return "\n".join(lines)
