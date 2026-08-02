"""
Report Generator for AEGIS security scanner.

This module compiles verified vulnerabilities into structured JSON and PDF formats.
Includes the mathematical proof (Z3 model) and the kernel execution trace (eBPF log).
"""

import json
import logging
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
import asyncio
import base64

logger = logging.getLogger(__name__)


class ReportFormat(Enum):
    """Supported report formats."""
    JSON = "json"
    PDF = "pdf"
    HTML = "html"
    MARKDOWN = "markdown"


class VulnerabilitySeverity(Enum):
    """Severity levels for vulnerabilities."""
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class VulnerabilityFinding:
    """A verified vulnerability finding."""
    finding_id: str
    title: str
    description: str
    severity: VulnerabilitySeverity
    cvss_score: float
    affected_component: str
    endpoint: Optional[str] = None
    payload: Optional[str] = None
    proof_model: Optional[Dict[str, Any]] = None  # Z3 mathematical proof
    ebpf_trace: Optional[str] = None  # Kernel execution trace
    reproduction_steps: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    cve_matches: List[Dict[str, Any]] = field(default_factory=list)
    discovered_at: datetime = field(default_factory=datetime.now)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ScanSummary:
    """Summary information about a scan."""
    scan_id: str
    target: str
    start_time: datetime
    end_time: datetime
    duration_seconds: float
    total_endpoints_tested: int
    total_payloads_generated: int
    vulnerabilities_found: int
    vulnerabilities_by_severity: Dict[str, int] = field(default_factory=dict)
    scan_config: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ReportMetadata:
    """Metadata about the generated report."""
    report_id: str
    generated_at: datetime
    scanner_version: str
    format: ReportFormat
    author: str = "AEGIS Security Scanner"
    classification: str = "Confidential"


class ReportGenerator:
    """
    Generate comprehensive security reports in multiple formats.
    
    Compiles verified vulnerabilities into structured reports including
    mathematical proofs (Z3 models) and kernel execution traces (eBPF logs).
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize the report generator.
        
        Args:
            config: Optional configuration dictionary
        """
        self.config = config or {}
        self.scanner_version = self.config.get('scanner_version', '1.0.0')
        self.output_dir = Path(self.config.get('output_dir', './reports'))
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        logger.info("ReportGenerator initialized")
    
    def generate_report_id(self) -> str:
        """
        Generate a unique report identifier.
        
        Returns:
            Unique report ID
        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        return f"report_{timestamp}"
    
    def create_scan_summary(
        self,
        scan_id: str,
        target: str,
        start_time: datetime,
        end_time: datetime,
        scan_results: Dict[str, Any]
    ) -> ScanSummary:
        """
        Create a scan summary from scan results.
        
        Args:
            scan_id: Scan identifier
            target: Target that was scanned
            start_time: Scan start time
            end_time: Scan end time
            scan_results: Raw scan results
            
        Returns:
            ScanSummary object
        """
        duration = (end_time - start_time).total_seconds()
        
        # Count vulnerabilities by severity
        vulns_by_severity = {}
        for vuln in scan_results.get('vulnerabilities', []):
            severity = vuln.get('severity', 'unknown')
            vulns_by_severity[severity] = vulns_by_severity.get(severity, 0) + 1
        
        summary = ScanSummary(
            scan_id=scan_id,
            target=target,
            start_time=start_time,
            end_time=end_time,
            duration_seconds=duration,
            total_endpoints_tested=scan_results.get('endpoints_tested', 0),
            total_payloads_generated=scan_results.get('payloads_generated', 0),
            vulnerabilities_found=len(scan_results.get('vulnerabilities', [])),
            vulnerabilities_by_severity=vulns_by_severity,
            scan_config=scan_results.get('config', {})
        )
        
        return summary
    
    def create_vulnerability_finding(
        self,
        vuln_data: Dict[str, Any]
    ) -> VulnerabilityFinding:
        """
        Create a vulnerability finding from raw vulnerability data.
        
        Args:
            vuln_data: Raw vulnerability data
            
        Returns:
            VulnerabilityFinding object
        """
        # Parse severity
        severity_str = vuln_data.get('severity', 'info').upper()
        try:
            severity = VulnerabilitySeverity(severity_str)
        except ValueError:
            severity = VulnerabilitySeverity.INFO
        
        finding = VulnerabilityFinding(
            finding_id=vuln_data.get('id', f"vuln_{hash(str(vuln_data))}"),
            title=vuln_data.get('title', 'Untitled Vulnerability'),
            description=vuln_data.get('description', ''),
            severity=severity,
            cvss_score=vuln_data.get('cvss_score', 0.0),
            affected_component=vuln_data.get('component', 'unknown'),
            endpoint=vuln_data.get('endpoint'),
            payload=vuln_data.get('payload'),
            proof_model=vuln_data.get('proof_model'),  # Z3 model
            ebpf_trace=vuln_data.get('ebpf_trace'),  # eBPF log
            reproduction_steps=vuln_data.get('reproduction_steps', []),
            references=vuln_data.get('references', []),
            cve_matches=vuln_data.get('cve_matches', []),
            discovered_at=vuln_data.get('discovered_at', datetime.now()),
            metadata=vuln_data.get('metadata', {})
        )
        
        return finding
    
    def generate_json_report(
        self,
        scan_summary: ScanSummary,
        findings: List[VulnerabilityFinding],
        additional_data: Optional[Dict[str, Any]] = None
    ) -> str:
        """
        Generate a JSON format report.
        
        Args:
            scan_summary: Scan summary information
            findings: List of vulnerability findings
            additional_data: Optional additional data to include
            
        Returns:
            JSON string
        """
        report_id = self.generate_report_id()
        
        report = {
            'metadata': {
                'report_id': report_id,
                'generated_at': datetime.now().isoformat(),
                'scanner_version': self.scanner_version,
                'format': ReportFormat.JSON.value,
                'author': 'AEGIS Security Scanner',
                'classification': 'Confidential'
            },
            'summary': {
                'scan_id': scan_summary.scan_id,
                'target': scan_summary.target,
                'start_time': scan_summary.start_time.isoformat(),
                'end_time': scan_summary.end_time.isoformat(),
                'duration_seconds': scan_summary.duration_seconds,
                'total_endpoints_tested': scan_summary.total_endpoints_tested,
                'total_payloads_generated': scan_summary.total_payloads_generated,
                'vulnerabilities_found': scan_summary.vulnerabilities_found,
                'vulnerabilities_by_severity': scan_summary.vulnerabilities_by_severity,
                'scan_config': scan_summary.scan_config
            },
            'findings': []
        }
        
        # Add findings
        for finding in findings:
            finding_data = {
                'finding_id': finding.finding_id,
                'title': finding.title,
                'description': finding.description,
                'severity': finding.severity.value,
                'cvss_score': finding.cvss_score,
                'affected_component': finding.affected_component,
                'endpoint': finding.endpoint,
                'payload': finding.payload,
                'proof_model': finding.proof_model,  # Z3 mathematical proof
                'ebpf_trace': finding.ebpf_trace,  # Kernel execution trace
                'reproduction_steps': finding.reproduction_steps,
                'references': finding.references,
                'cve_matches': finding.cve_matches,
                'discovered_at': finding.discovered_at.isoformat(),
                'metadata': finding.metadata
            }
            report['findings'].append(finding_data)
        
        # Add additional data if provided
        if additional_data:
            report['additional_data'] = additional_data
        
        return json.dumps(report, indent=2, default=str)
    
    def generate_markdown_report(
        self,
        scan_summary: ScanSummary,
        findings: List[VulnerabilityFinding],
        additional_data: Optional[Dict[str, Any]] = None
    ) -> str:
        """
        Generate a Markdown format report.
        
        Args:
            scan_summary: Scan summary information
            findings: List of vulnerability findings
            additional_data: Optional additional data to include
            
        Returns:
            Markdown string
        """
        report_id = self.generate_report_id()
        
        lines = []
        
        # Header
        lines.append(f"# AEGIS Security Scanner Report")
        lines.append(f"**Report ID:** {report_id}")
        lines.append(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append(f"**Scanner Version:** {self.scanner_version}")
        lines.append("")
        
        # Executive Summary
        lines.append("## Executive Summary")
        lines.append(f"**Target:** {scan_summary.target}")
        lines.append(f"**Scan Duration:** {scan_summary.duration_seconds:.2f} seconds")
        lines.append(f"**Endpoints Tested:** {scan_summary.total_endpoints_tested}")
        lines.append(f"**Payloads Generated:** {scan_summary.total_payloads_generated}")
        lines.append(f"**Vulnerabilities Found:** {scan_summary.vulnerabilities_found}")
        lines.append("")
        
        # Severity breakdown
        lines.append("### Vulnerabilities by Severity")
        for severity, count in scan_summary.vulnerabilities_by_severity.items():
            lines.append(f"- **{severity.upper()}:** {count}")
        lines.append("")
        
        # Detailed Findings
        lines.append("## Detailed Findings")
        lines.append("")
        
        for i, finding in enumerate(findings, 1):
            lines.append(f"### {i}. {finding.title}")
            lines.append(f"**Finding ID:** {finding.finding_id}")
            lines.append(f"**Severity:** {finding.severity.value.upper()}")
            lines.append(f"**CVSS Score:** {finding.cvss_score}")
            lines.append(f"**Affected Component:** {finding.affected_component}")
            if finding.endpoint:
                lines.append(f"**Endpoint:** {finding.endpoint}")
            lines.append("")
            
            lines.append("#### Description")
            lines.append(finding.description)
            lines.append("")
            
            if finding.payload:
                lines.append("#### Exploit Payload")
                lines.append("```")
                lines.append(finding.payload)
                lines.append("```")
                lines.append("")
            
            if finding.proof_model:
                lines.append("#### Mathematical Proof (Z3 Model)")
                lines.append("```json")
                lines.append(json.dumps(finding.proof_model, indent=2))
                lines.append("```")
                lines.append("")
            
            if finding.ebpf_trace:
                lines.append("#### Kernel Execution Trace (eBPF)")
                lines.append("```")
                lines.append(finding.ebpf_trace)
                lines.append("```")
                lines.append("")
            
            if finding.reproduction_steps:
                lines.append("#### Reproduction Steps")
                for step_num, step in enumerate(finding.reproduction_steps, 1):
                    lines.append(f"{step_num}. {step}")
                lines.append("")
            
            if finding.cve_matches:
                lines.append("#### Related CVEs")
                for cve in finding.cve_matches:
                    lines.append(f"- **{cve.get('cve_id', 'Unknown')}** - {cve.get('match_reason', '')}")
                lines.append("")
            
            if finding.references:
                lines.append("#### References")
                for ref in finding.references:
                    lines.append(f"- {ref}")
                lines.append("")
            
            lines.append("---")
            lines.append("")
        
        # Additional data
        if additional_data:
            lines.append("## Additional Data")
            lines.append("```json")
            lines.append(json.dumps(additional_data, indent=2))
            lines.append("```")
        
        return "\n".join(lines)
    
    def generate_html_report(
        self,
        scan_summary: ScanSummary,
        findings: List[VulnerabilityFinding],
        additional_data: Optional[Dict[str, Any]] = None
    ) -> str:
        """
        Generate an HTML format report.
        
        Args:
            scan_summary: Scan summary information
            findings: List of vulnerability findings
            additional_data: Optional additional data to include
            
        Returns:
            HTML string
        """
        report_id = self.generate_report_id()
        
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AEGIS Security Scanner Report - {report_id}</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            line-height: 1.6;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background-color: white;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        h1 {{
            color: #333;
            border-bottom: 3px solid #007bff;
            padding-bottom: 10px;
        }}
        h2 {{
            color: #555;
            margin-top: 30px;
        }}
        .summary {{
            background-color: #f8f9fa;
            padding: 20px;
            border-radius: 5px;
            margin: 20px 0;
        }}
        .severity-critical {{ color: #dc3545; font-weight: bold; }}
        .severity-high {{ color: #fd7e14; font-weight: bold; }}
        .severity-medium {{ color: #ffc107; font-weight: bold; }}
        .severity-low {{ color: #28a745; font-weight: bold; }}
        .severity-info {{ color: #17a2b8; font-weight: bold; }}
        .finding {{
            border: 1px solid #ddd;
            border-radius: 5px;
            padding: 20px;
            margin: 20px 0;
            background-color: #fff;
        }}
        .finding-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 15px;
        }}
        pre {{
            background-color: #f8f9fa;
            padding: 15px;
            border-radius: 5px;
            overflow-x: auto;
        }}
        code {{
            background-color: #f8f9fa;
            padding: 2px 5px;
            border-radius: 3px;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }}
        th, td {{
            border: 1px solid #ddd;
            padding: 12px;
            text-align: left;
        }}
        th {{
            background-color: #007bff;
            color: white;
        }}
        .badge {{
            display: inline-block;
            padding: 5px 10px;
            border-radius: 3px;
            color: white;
            font-size: 12px;
        }}
        .badge-critical {{ background-color: #dc3545; }}
        .badge-high {{ background-color: #fd7e14; }}
        .badge-medium {{ background-color: #ffc107; color: #333; }}
        .badge-low {{ background-color: #28a745; }}
        .badge-info {{ background-color: #17a2b8; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>AEGIS Security Scanner Report</h1>
        <p><strong>Report ID:</strong> {report_id}</p>
        <p><strong>Generated:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        <p><strong>Scanner Version:</strong> {self.scanner_version}</p>
        
        <h2>Executive Summary</h2>
        <div class="summary">
            <table>
                <tr><th>Metric</th><th>Value</th></tr>
                <tr><td>Target</td><td>{scan_summary.target}</td></tr>
                <tr><td>Scan Duration</td><td>{scan_summary.duration_seconds:.2f} seconds</td></tr>
                <tr><td>Endpoints Tested</td><td>{scan_summary.total_endpoints_tested}</td></tr>
                <tr><td>Payloads Generated</td><td>{scan_summary.total_payloads_generated}</td></tr>
                <tr><td>Vulnerabilities Found</td><td>{scan_summary.vulnerabilities_found}</td></tr>
            </table>
        </div>
        
        <h2>Vulnerabilities by Severity</h2>
        <table>
            <tr><th>Severity</th><th>Count</th></tr>
"""
        
        for severity, count in scan_summary.vulnerabilities_by_severity.items():
            html += f"            <tr><td><span class='badge badge-{severity.lower()}'>{severity.upper()}</span></td><td>{count}</td></tr>\n"
        
        html += """        </table>
        
        <h2>Detailed Findings</h2>
"""
        
        for i, finding in enumerate(findings, 1):
            html += f"""
        <div class="finding">
            <div class="finding-header">
                <h3>{i}. {finding.title}</h3>
                <span class="badge badge-{finding.severity.value}">{finding.severity.value.upper()}</span>
            </div>
            <p><strong>Finding ID:</strong> {finding.finding_id}</p>
            <p><strong>CVSS Score:</strong> {finding.cvss_score}</p>
            <p><strong>Affected Component:</strong> {finding.affected_component}</p>
"""
            if finding.endpoint:
                html += f"            <p><strong>Endpoint:</strong> {finding.endpoint}</p>\n"
            
            html += f"""
            <h4>Description</h4>
            <p>{finding.description}</p>
"""
            
            if finding.payload:
                html += f"""
            <h4>Exploit Payload</h4>
            <pre><code>{finding.payload}</code></pre>
"""
            
            if finding.proof_model:
                html += f"""
            <h4>Mathematical Proof (Z3 Model)</h4>
            <pre><code>{json.dumps(finding.proof_model, indent=2)}</code></pre>
"""
            
            if finding.ebpf_trace:
                html += f"""
            <h4>Kernel Execution Trace (eBPF)</h4>
            <pre><code>{finding.ebpf_trace}</code></pre>
"""
            
            if finding.reproduction_steps:
                html += "            <h4>Reproduction Steps</h4>\n            <ol>\n"
                for step in finding.reproduction_steps:
                    html += f"                <li>{step}</li>\n"
                html += "            </ol>\n"
            
            if finding.cve_matches:
                html += "            <h4>Related CVEs</h4>\n            <ul>\n"
                for cve in finding.cve_matches:
                    html += f"                <li><strong>{cve.get('cve_id', 'Unknown')}</strong> - {cve.get('match_reason', '')}</li>\n"
                html += "            </ul>\n"
            
            if finding.references:
                html += "            <h4>References</h4>\n            <ul>\n"
                for ref in finding.references:
                    html += f"                <li><a href='{ref}'>{ref}</a></li>\n"
                html += "            </ul>\n"
            
            html += "        </div>\n"
        
        html += """
    </div>
</body>
</html>
"""
        
        return html
    
    def generate_pdf_report(
        self,
        scan_summary: ScanSummary,
        findings: List[VulnerabilityFinding],
        additional_data: Optional[Dict[str, Any]] = None
    ) -> bytes:
        """
        Generate a PDF format report.
        
        Note: This is a placeholder implementation. For production use,
        integrate with a PDF generation library like reportlab or weasyprint.
        
        Args:
            scan_summary: Scan summary information
            findings: List of vulnerability findings
            additional_data: Optional additional data to include
            
        Returns:
            PDF bytes
        """
        # For now, we'll generate HTML and convert it
        # In production, use reportlab or weasyprint directly
        html_content = self.generate_html_report(
            scan_summary,
            findings,
            additional_data
        )
        
        # Placeholder: In production, convert HTML to PDF here
        # For now, return the HTML as bytes with a note
        pdf_note = f"""PDF GENERATION NOT YET IMPLEMENTED
        
To enable PDF generation, install one of the following:
- reportlab: pip install reportlab
- weasyprint: pip install weasyprint

HTML content (can be manually converted to PDF):
{html_content}
"""
        
        return pdf_note.encode('utf-8')
    
    def save_report(
        self,
        content: str,
        format: ReportFormat,
        filename: Optional[str] = None
    ) -> Path:
        """
        Save a report to disk.
        
        Args:
            content: Report content
            format: Report format
            filename: Optional filename (auto-generated if not provided)
            
        Returns:
            Path to the saved file
        """
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"aegis_report_{timestamp}.{format.value}"
        
        filepath = self.output_dir / filename
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(content)
        
        logger.info(f"Report saved to: {filepath}")
        return filepath
    
    def generate_and_save_report(
        self,
        scan_summary: ScanSummary,
        findings: List[VulnerabilityFinding],
        format: ReportFormat = ReportFormat.JSON,
        additional_data: Optional[Dict[str, Any]] = None,
        filename: Optional[str] = None
    ) -> Path:
        """
        Generate and save a report in the specified format.
        
        Args:
            scan_summary: Scan summary information
            findings: List of vulnerability findings
            format: Report format
            additional_data: Optional additional data to include
            filename: Optional filename
            
        Returns:
            Path to the saved file
        """
        if format == ReportFormat.JSON:
            content = self.generate_json_report(
                scan_summary,
                findings,
                additional_data
            )
        elif format == ReportFormat.MARKDOWN:
            content = self.generate_markdown_report(
                scan_summary,
                findings,
                additional_data
            )
        elif format == ReportFormat.HTML:
            content = self.generate_html_report(
                scan_summary,
                findings,
                additional_data
            )
        elif format == ReportFormat.PDF:
            pdf_bytes = self.generate_pdf_report(
                scan_summary,
                findings,
                additional_data
            )
            # PDF returns bytes, handle separately
            if not filename:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                filename = f"aegis_report_{timestamp}.pdf"
            
            filepath = self.output_dir / filename
            with open(filepath, 'wb') as f:
                f.write(pdf_bytes)
            
            logger.info(f"PDF report saved to: {filepath}")
            return filepath
        else:
            raise ValueError(f"Unsupported format: {format}")
        
        return self.save_report(content, format, filename)
    
    def generate_all_formats(
        self,
        scan_summary: ScanSummary,
        findings: List[VulnerabilityFinding],
        additional_data: Optional[Dict[str, Any]] = None,
        base_filename: Optional[str] = None
    ) -> Dict[ReportFormat, Path]:
        """
        Generate reports in all supported formats.
        
        Args:
            scan_summary: Scan summary information
            findings: List of vulnerability findings
            additional_data: Optional additional data to include
            base_filename: Optional base filename (without extension)
            
        Returns:
            Dictionary mapping formats to file paths
        """
        if not base_filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            base_filename = f"aegis_report_{timestamp}"
        
        results = {}
        
        for format in ReportFormat:
            try:
                filename = f"{base_filename}.{format.value}"
                filepath = self.generate_and_save_report(
                    scan_summary,
                    findings,
                    format,
                    additional_data,
                    filename
                )
                results[format] = filepath
            except Exception as e:
                logger.error(f"Failed to generate {format.value} report: {e}")
        
        return results
    
    def create_executive_summary(
        self,
        scan_summary: ScanSummary,
        findings: List[VulnerabilityFinding]
    ) -> Dict[str, Any]:
        """
        Create an executive summary for quick consumption.
        
        Args:
            scan_summary: Scan summary information
            findings: List of vulnerability findings
            
        Returns:
            Executive summary dictionary
        """
        # Count critical and high severity findings
        critical_count = sum(1 for f in findings if f.severity == VulnerabilitySeverity.CRITICAL)
        high_count = sum(1 for f in findings if f.severity == VulnerabilitySeverity.HIGH)
        
        # Get top 5 most severe findings
        sorted_findings = sorted(
            findings,
            key=lambda f: (f.severity.value, f.cvss_score),
            reverse=True
        )
        top_findings = sorted_findings[:5]
        
        executive_summary = {
            'overall_risk_level': self._calculate_overall_risk(critical_count, high_count),
            'total_vulnerabilities': len(findings),
            'critical_vulnerabilities': critical_count,
            'high_vulnerabilities': high_count,
            'scan_coverage': {
                'endpoints_tested': scan_summary.total_endpoints_tested,
                'payloads_generated': scan_summary.total_payloads_generated
            },
            'top_findings': [
                {
                    'title': f.title,
                    'severity': f.severity.value,
                    'cvss_score': f.cvss_score,
                    'affected_component': f.affected_component
                }
                for f in top_findings
            ],
            'recommendations': self._generate_recommendations(findings)
        }
        
        return executive_summary
    
    def _calculate_overall_risk(self, critical_count: int, high_count: int) -> str:
        """Calculate overall risk level based on vulnerability counts."""
        if critical_count > 0:
            return "CRITICAL"
        elif high_count > 2:
            return "HIGH"
        elif high_count > 0:
            return "MEDIUM"
        else:
            return "LOW"
    
    def _generate_recommendations(self, findings: List[VulnerabilityFinding]) -> List[str]:
        """Generate remediation recommendations based on findings."""
        recommendations = []
        
        # Check for specific vulnerability types
        vuln_types = set(f.metadata.get('type', 'unknown') for f in findings)
        
        if 'sql_injection' in vuln_types:
            recommendations.append(
                "Implement parameterized queries and input validation to prevent SQL injection"
            )
        
        if 'xss' in vuln_types:
            recommendations.append(
                "Implement Content Security Policy (CSP) and sanitize user input to prevent XSS"
            )
        
        if 'auth_bypass' in vuln_types:
            recommendations.append(
                "Review and strengthen authentication mechanisms, implement multi-factor authentication"
            )
        
        if any(f.severity in [VulnerabilitySeverity.CRITICAL, VulnerabilitySeverity.HIGH] for f in findings):
            recommendations.append(
                "Prioritize patching of critical and high severity vulnerabilities immediately"
            )
        
        if not recommendations:
            recommendations.append(
                "Continue regular security scanning and vulnerability management"
            )
        
        return recommendations


class ReportBuilder:
    """
    Builder class for constructing reports incrementally.
    
    Provides a fluent interface for building complex reports
    with multiple findings and data sources.
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize the report builder.
        
        Args:
            config: Optional configuration dictionary
        """
        self.generator = ReportGenerator(config)
        self.findings: List[VulnerabilityFinding] = []
        self.additional_data: Dict[str, Any] = {}
        self.scan_summary: Optional[ScanSummary] = None
        
        logger.info("ReportBuilder initialized")
    
    def set_scan_summary(self, summary: ScanSummary) -> 'ReportBuilder':
        """Set the scan summary."""
        self.scan_summary = summary
        return self
    
    def add_finding(self, finding: VulnerabilityFinding) -> 'ReportBuilder':
        """Add a vulnerability finding."""
        self.findings.append(finding)
        return self
    
    def add_findings(self, findings: List[VulnerabilityFinding]) -> 'ReportBuilder':
        """Add multiple vulnerability findings."""
        self.findings.extend(findings)
        return self
    
    def add_additional_data(self, key: str, value: Any) -> 'ReportBuilder':
        """Add additional data to the report."""
        self.additional_data[key] = value
        return self
    
    def build(self, format: ReportFormat = ReportFormat.JSON) -> str:
        """
        Build the report in the specified format.
        
        Args:
            format: Report format
            
        Returns:
            Report content as string
        """
        if not self.scan_summary:
            raise ValueError("Scan summary must be set before building report")
        
        if format == ReportFormat.JSON:
            return self.generator.generate_json_report(
                self.scan_summary,
                self.findings,
                self.additional_data
            )
        elif format == ReportFormat.MARKDOWN:
            return self.generator.generate_markdown_report(
                self.scan_summary,
                self.findings,
                self.additional_data
            )
        elif format == ReportFormat.HTML:
            return self.generator.generate_html_report(
                self.scan_summary,
                self.findings,
                self.additional_data
            )
        elif format == ReportFormat.PDF:
            pdf_bytes = self.generator.generate_pdf_report(
                self.scan_summary,
                self.findings,
                self.additional_data
            )
            return pdf_bytes.decode('utf-8')
        else:
            raise ValueError(f"Unsupported format: {format}")
    
    def save(self, format: ReportFormat = ReportFormat.JSON, filename: Optional[str] = None) -> Path:
        """
        Build and save the report.
        
        Args:
            format: Report format
            filename: Optional filename
            
        Returns:
            Path to the saved file
        """
        if not self.scan_summary:
            raise ValueError("Scan summary must be set before building report")
        
        return self.generator.generate_and_save_report(
            self.scan_summary,
            self.findings,
            format,
            self.additional_data,
            filename
        )
