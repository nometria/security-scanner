"""
Review agent — triages scan findings to reduce false positives.

Basic mode (default): heuristic suppression (test files, known FP patterns).
Advanced mode (optional): LLM-powered structured verdicts.
"""

from pathlib import Path
from typing import Optional

from security_scanner.scanner import Finding, ScanResult

from .verdict import FindingVerdict, ReviewVerdict

# Patterns that suggest a finding is in test code
_TEST_PATH_PATTERNS = [
    "test_", "_test.", ".test.", "tests/", "test/", "__tests__/",
    "spec/", ".spec.", "fixtures/", "mocks/", "mock_",
    "examples/", "example_",
]

# Rule IDs that are commonly false positives in certain contexts
_KNOWN_FP_CONTEXTS = {
    "SEC-001": ["test", "example", "fixture", "mock", "snapshot"],
    "SEC-007": ["test", "localhost", "development"],
    "LINT-": ["generated", "vendor", "third_party", "node_modules"],
    "FMT-": ["generated", "vendor", "min.js", "min.css"],
}


class ReviewAgent:
    """Triage findings to identify likely true/false positives."""

    def review(self, result: ScanResult) -> ReviewVerdict:
        """Review all findings using heuristics.

        Does NOT require any AI API calls.
        """
        verdicts = []
        for finding in result.findings:
            verdict = self._evaluate_finding(finding)
            verdicts.append(verdict)

        # Compute overall risk level
        true_positives = [v for v in verdicts if v.is_true_positive]
        if any(v.finding.severity == "CRITICAL" for v in true_positives):
            risk = "critical"
        elif any(v.finding.severity == "HIGH" for v in true_positives):
            risk = "high"
        elif any(v.finding.severity == "MEDIUM" for v in true_positives):
            risk = "medium"
        elif true_positives:
            risk = "low"
        else:
            risk = "none"

        # Generate summary
        fp_count = len(verdicts) - len(true_positives)
        summary = (
            f"{len(true_positives)} likely true positive(s), "
            f"{fp_count} likely false positive(s) "
            f"out of {len(verdicts)} total finding(s)."
        )

        # Generate recommended actions
        actions = []
        if any(v.finding.severity == "CRITICAL" and v.is_true_positive for v in verdicts):
            actions.append("Fix CRITICAL findings immediately before merging")
        if any(v.finding.severity == "HIGH" and v.is_true_positive for v in verdicts):
            actions.append("Review and fix HIGH-severity findings")
        if fp_count > 0:
            actions.append(f"Consider suppressing {fp_count} likely false positive(s)")

        return ReviewVerdict(
            finding_verdicts=verdicts,
            risk_level=risk,
            summary=summary,
            recommended_actions=actions,
        )

    def review_with_ai(
        self,
        result: ScanResult,
        ai_client=None,
        project_root: Optional[Path] = None,
    ) -> ReviewVerdict:
        """Enhanced review using an LLM for structured verdicts.

        Falls back to heuristic review if AI client is not available.
        """
        # Start with heuristic review
        verdict = self.review(result)

        if ai_client is None or not result.findings:
            return verdict

        # Send findings to LLM for evaluation
        findings_text = []
        for i, f in enumerate(result.findings[:30]):  # Cap to control cost
            snippet = ""
            if project_root and f.file:
                fpath = project_root / f.file
                if fpath.is_file():
                    try:
                        lines = fpath.read_text(errors="replace").splitlines()
                        start = max(0, f.line - 3)
                        end = min(len(lines), f.line + 3)
                        snippet = "\n".join(lines[start:end])
                    except Exception:
                        pass

            findings_text.append(
                f"[{i+1}] {f.severity} {f.rule_id}: {f.message}\n"
                f"    File: {f.file}:{f.line}\n"
                + (f"    Context:\n{snippet}\n" if snippet else "")
            )

        prompt = (
            "Review these security/quality findings and classify each as "
            "true positive or false positive.\n\n"
            + "\n".join(findings_text)
            + "\n\nFor each finding number, respond with JSON:\n"
            '[{"id": 1, "tp": true, "confidence": 0.9, "reason": "..."}]'
        )

        try:
            response = ai_client.complete(prompt, max_tokens=2000)
            import json
            ai_verdicts = json.loads(response)

            # Merge AI verdicts with heuristic verdicts
            for av in ai_verdicts:
                idx = av.get("id", 0) - 1
                if 0 <= idx < len(verdict.finding_verdicts):
                    fv = verdict.finding_verdicts[idx]
                    fv.is_true_positive = av.get("tp", fv.is_true_positive)
                    fv.confidence = av.get("confidence", fv.confidence)
                    fv.explanation = av.get("reason", fv.explanation)
        except Exception:
            pass  # AI failure is non-fatal

        return verdict

    def _evaluate_finding(self, finding: Finding) -> FindingVerdict:
        """Heuristic evaluation of a single finding."""
        is_tp = True
        confidence = 0.8
        explanation = ""

        # Check if in test code
        if self._is_test_file(finding.file):
            is_tp = False
            confidence = 0.7
            explanation = "Finding is in test/example code"

        # Check known FP contexts
        for rule_prefix, contexts in _KNOWN_FP_CONTEXTS.items():
            if finding.rule_id.startswith(rule_prefix):
                fpath_lower = finding.file.lower()
                for ctx in contexts:
                    if ctx in fpath_lower:
                        is_tp = False
                        confidence = 0.6
                        explanation = f"Likely false positive: {ctx} context"
                        break

        # High-confidence true positives
        if finding.severity == "CRITICAL" and is_tp:
            confidence = 0.95
            explanation = "Critical severity finding — high confidence true positive"

        return FindingVerdict(
            finding=finding,
            is_true_positive=is_tp,
            confidence=confidence,
            explanation=explanation,
            suggested_fix=finding.fix,
        )

    @staticmethod
    def _is_test_file(fpath: str) -> bool:
        lower = fpath.lower()
        return any(p in lower for p in _TEST_PATH_PATTERNS)
