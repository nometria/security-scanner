"""security-scanner - static security analysis for AI-generated web app code."""
from .scanner import scan_project, scan_files, scan_project_v2, ScanResult, Finding, CRITICAL, HIGH, MEDIUM, LOW, INFO

__all__ = [
    "scan_project", "scan_files", "scan_project_v2",
    "ScanResult", "Finding",
    "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO",
]
__version__ = "0.3.0"
