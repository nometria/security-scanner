"""
config.py - Scanner configuration and severity definitions.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import List, Optional, Set


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class Framework(str, Enum):
    HIPAA = "HIPAA"
    SOC2 = "SOC2"
    OWASP = "OWASP"
    FEDRAMP = "FEDRAMP"


SEVERITY_ORDER = {
    Severity.CRITICAL: 4,
    Severity.HIGH: 3,
    Severity.MEDIUM: 2,
    Severity.LOW: 1,
    Severity.INFO: 0,
}

# Maps frameworks to their relevant SOC2 Trust Services Criteria
SOC2_CRITERIA = {
    "CC6.1": "Logical and Physical Access Controls",
    "CC6.2": "Authentication and Access Management",
    "CC6.3": "Role-based Access Control",
    "CC7.1": "Vulnerability Management",
    "CC7.2": "Threat Detection",
    "CC8.1": "Change Management",
    "PI1.1": "Processing Integrity",
    "C1.1": "Confidentiality",
    "P1.1": "Privacy",
}

# Maps HIPAA safeguard categories
HIPAA_SAFEGUARDS = {
    "164.312(a)(1)": "Access Control",
    "164.312(a)(2)(i)": "Unique User Identification",
    "164.312(a)(2)(iii)": "Automatic Logoff",
    "164.312(a)(2)(iv)": "Encryption and Decryption",
    "164.312(b)": "Audit Controls",
    "164.312(c)(1)": "Integrity",
    "164.312(d)": "Person or Entity Authentication",
    "164.312(e)(1)": "Transmission Security",
    "164.312(e)(2)(ii)": "Encryption in Transit",
}


@dataclass
class ScanConfig:
    """Configuration for a single scanner run."""

    # Directories / files to scan
    paths: List[Path] = field(default_factory=list)

    # File extensions to include (empty = all)
    include_extensions: Set[str] = field(default_factory=lambda: {
        ".py", ".js", ".jsx", ".ts", ".tsx",
        ".env", ".yaml", ".yml", ".json", ".toml",
        ".sh", ".dockerfile",
    })

    # Patterns to exclude (glob)
    exclude_patterns: List[str] = field(default_factory=lambda: [
        "**/node_modules/**",
        "**/.git/**",
        "**/dist/**",
        "**/build/**",
        "**/__pycache__/**",
        "**/*.pyc",
        "**/coverage/**",
        "**/coverage_html/**",
    ])

    # Minimum severity to report
    min_severity: Severity = Severity.LOW

    # Which compliance frameworks to check
    frameworks: List[Framework] = field(default_factory=lambda: [
        Framework.HIPAA,
        Framework.SOC2,
        Framework.OWASP,
        Framework.FEDRAMP,
    ])

    # Exit with non-zero code if findings at this severity or above
    fail_on: Severity = Severity.HIGH

    # Output format
    output_format: str = "console"  # console | json | html

    # Output file (None = stdout)
    output_file: Optional[Path] = None

    # Max findings per rule (0 = unlimited)
    max_findings_per_rule: int = 0
