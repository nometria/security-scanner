"""security-scanner — static security analysis for AI-generated web app code."""
from .scanner import scan_project, scan_files, ScanResult, Finding, CRITICAL, HIGH, MEDIUM, LOW

__all__ = ["scan_project", "scan_files", "ScanResult", "Finding", "CRITICAL", "HIGH", "MEDIUM", "LOW"]
__version__ = "0.2.0"
