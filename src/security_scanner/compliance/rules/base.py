"""
base.py - Abstract base class for all compliance rules.

Every rule is a self-contained object that:
1. Knows which files it can scan (file_extensions)
2. Has a check() method that returns zero or more Finding objects
3. Carries metadata (id, title, severity, framework, reference)

Design: rules are stateless and can be applied in parallel.
"""

from __future__ import annotations
from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator, Optional

from security_scanner.compliance.config import Framework, Severity


@dataclass(frozen=True)
class Finding:
    """
    A single compliance issue found in a file.

    Attributes:
        rule_id:     Unique rule identifier (e.g. HIPAA-001)
        title:       Short human-readable summary
        description: Detailed explanation of the issue
        severity:    How critical this finding is
        framework:   Which compliance framework raised this
        reference:   Regulatory reference (e.g. "164.312(e)(2)(ii)")
        file_path:   Absolute path to the offending file
        line_number: Line where the issue was found (1-indexed, 0 if N/A)
        line_content: The actual offending line (redacted if secret)
        remediation: How to fix this issue
    """
    rule_id: str
    title: str
    description: str
    severity: Severity
    framework: Framework
    reference: str
    file_path: Path
    line_number: int = 0
    line_content: str = ""
    remediation: str = ""
    auto_fixable: bool = False

    def as_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value,
            "framework": self.framework.value,
            "reference": self.reference,
            "file_path": str(self.file_path),
            "line_number": self.line_number,
            "line_content": self.line_content,
            "remediation": self.remediation,
            "auto_fixable": self.auto_fixable,
        }


class Rule(ABC):
    """
    Abstract base class for all scanner rules.

    Subclasses MUST implement:
    - rule_id    (class attribute)
    - title      (class attribute)
    - description (class attribute)
    - severity   (class attribute)
    - framework  (class attribute)
    - reference  (class attribute)
    - file_extensions (class attribute) - which file types this rule applies to
    - check(file_path, content) -> Iterator[Finding]
    """

    # ---- Metadata (override in subclasses) --------------------------------
    rule_id: str = ""
    title: str = ""
    description: str = ""
    severity: Severity = Severity.MEDIUM
    framework: Framework = Framework.HIPAA
    reference: str = ""
    remediation: str = ""

    # Which file extensions this rule applies to.
    # Empty set means the rule applies to ALL file types.
    file_extensions: frozenset = frozenset()

    def applies_to(self, file_path: Path) -> bool:
        """Return True if this rule should be applied to the given file."""
        if not self.file_extensions:
            return True
        return file_path.suffix.lower() in self.file_extensions

    @abstractmethod
    def check(self, file_path: Path, content: str) -> Iterator[Finding]:
        """
        Scan `content` (the full text of `file_path`) for compliance issues.
        Yield zero or more Finding objects.
        """
        ...

    def _finding(
        self,
        file_path: Path,
        line_number: int = 0,
        line_content: str = "",
        description_override: Optional[str] = None,
    ) -> Finding:
        """Convenience factory to build a Finding from this rule's metadata."""
        return Finding(
            rule_id=self.rule_id,
            title=self.title,
            description=description_override or self.description,
            severity=self.severity,
            framework=self.framework,
            reference=self.reference,
            file_path=file_path,
            line_number=line_number,
            line_content=line_content[:200],  # cap at 200 chars
            remediation=self.remediation,
            auto_fixable=getattr(self, "auto_fixable", False),
        )
