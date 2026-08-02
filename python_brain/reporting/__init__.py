"""
Reporting module for AEGIS security scanner.

This module provides comprehensive reporting capabilities including CVE matching
against NVD databases, and generation of security reports in multiple formats
(JSON, PDF, HTML, Markdown) with mathematical proofs and kernel execution traces.
"""

from .cve_matcher import (
    CVEMatcher,
    NVDDatabase,
    CVEDetails,
    CVESeverity,
    VulnerabilityPattern,
    CVEMatch,
)

from .report_generator import (
    ReportGenerator,
    ReportBuilder,
    ReportFormat,
    VulnerabilitySeverity,
    VulnerabilityFinding,
    ScanSummary,
    ReportMetadata,
)

__all__ = [
    # CVE Matcher
    'CVEMatcher',
    'NVDDatabase',
    'CVEDetails',
    'CVESeverity',
    'VulnerabilityPattern',
    'CVEMatch',
    
    # Report Generator
    'ReportGenerator',
    'ReportBuilder',
    'ReportFormat',
    'VulnerabilitySeverity',
    'VulnerabilityFinding',
    'ScanSummary',
    'ReportMetadata',
]

__version__ = '0.1.0'
