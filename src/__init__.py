"""
AWS Security Analysis Tool
A comprehensive security scanning tool for AWS accounts
"""

__version__ = "1.7.0"
__author__ = "AWS Security Tool Team"

from .models import Finding, ScanResult, Severity, Category
from .scanners import BaseScanner, IAMScanner
from .analyzers import FindingAnalyzer
from .generators import RemediationGenerator, ReportGenerator, DashboardGenerator

__all__ = [
    "Finding",
    "ScanResult", 
    "Severity",
    "Category",
    "BaseScanner",
    "IAMScanner",
    "FindingAnalyzer",
    "RemediationGenerator",
    "ReportGenerator",
    "DashboardGenerator",
]