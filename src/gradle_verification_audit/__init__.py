"""Offline checks for Gradle dependency verification metadata."""

from .engine import audit_file
from .model import AuditResult, Diagnostic, Severity

__all__ = ["AuditResult", "Diagnostic", "Severity", "audit_file"]
__version__ = "0.1.0"
