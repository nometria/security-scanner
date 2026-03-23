"""security-scanner — static security analysis for AI-generated web app code."""
from .scanner import scan_project, ScanResult, Finding, CRITICAL, HIGH, MEDIUM, LOW

__all__ = ["scan_project", "ScanResult", "Finding", "CRITICAL", "HIGH", "MEDIUM", "LOW"]
__version__ = "0.1.0"
