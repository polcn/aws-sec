from typing import List, Dict, Any, Optional
from datetime import datetime
from jinja2 import Template
import json
import markdown
from ..models import Finding, ScanResult, Severity
from ..analyzers import FindingAnalyzer


class ReportGenerator:
    """Generate security reports in various formats"""
    
    def __init__(self, scan_result: ScanResult):
        self.scan_result = scan_result
        self.analyzer = FindingAnalyzer(scan_result)
        self.findings = scan_result.findings
    
    def generate_html_report(self) -> str:
        """Generate an HTML report"""
        template = Template(self._get_html_template())
        
        context = {
            'scan_result': self.scan_result,
            'scan_date': self.scan_result.start_time.strftime('%Y-%m-%d %H:%M:%S UTC'),
            'account_id': self.scan_result.account_id,
            'regions_scanned': ', '.join(self.scan_result.regions),
            'services_scanned': ', '.join(self.scan_result.services_scanned),
            'statistics': self.scan_result.get_statistics(),
            'findings_by_severity': self._group_findings_by_severity(),
            'findings_by_service': self.analyzer.get_findings_by_service(),
            'priority_matrix': self.analyzer.get_remediation_priority_matrix(),
            'quick_wins': self.analyzer.get_quick_wins()[:10],
            'compliance_summary': self.analyzer.get_compliance_summary(),
            'attack_surface': self.analyzer.get_attack_surface_analysis(),
            'severity_colors': {
                'CRITICAL': '#dc3545',
                'HIGH': '#fd7e14',
                'MEDIUM': '#ffc107',
                'LOW': '#28a745',
                'INFO': '#17a2b8'
            }
        }
        
        return template.render(**context)
    
    def generate_markdown_report(self) -> str:
        """Generate a Markdown report"""
        lines = []
        
        # Header
        lines.append(f"# AWS Security Analysis Report")
        lines.append(f"")
        lines.append(f"**Generated:** {self.scan_result.start_time.strftime('%Y-%m-%d %H:%M:%S UTC')}")
        lines.append(f"**Account ID:** {self.scan_result.account_id}")
        lines.append(f"**Regions:** {', '.join(self.scan_result.regions)}")
        lines.append(f"**Services:** {', '.join(self.scan_result.services_scanned)}")
        lines.append(f"")
        
        # Executive Summary
        lines.append("## Executive Summary")
        lines.append("")
        stats = self.scan_result.get_statistics()
        lines.append(f"- **Total Findings:** {stats['total_findings']}")
        lines.append(f"- **Critical:** {stats['severity_distribution']['CRITICAL']}")
        lines.append(f"- **High:** {stats['severity_distribution']['HIGH']}")
        lines.append(f"- **Medium:** {stats['severity_distribution']['MEDIUM']}")
        lines.append(f"- **Low:** {stats['severity_distribution']['LOW']}")
        lines.append(f"- **Informational:** {stats['severity_distribution']['INFO']}")
        lines.append(f"- **Resources Scanned:** {stats['resources_scanned']}")
        if stats['scan_duration']:
            lines.append(f"- **Scan Duration:** {int(stats['scan_duration'])} seconds")
        lines.append("")
        
        # Attack Surface Analysis
        attack_surface = self.analyzer.get_attack_surface_analysis()
        lines.append("## Attack Surface Analysis")
        lines.append("")
        lines.append(f"- **Total Attack Vectors:** {attack_surface['total_attack_vectors']}")
        lines.append(f"- **Critical Exposures:** {attack_surface['critical_exposures']}")
        lines.append(f"- **Categories Affected:** {attack_surface['categories_affected']}")
        lines.append(f"- **Services Affected:** {attack_surface['services_affected']}")
        lines.append("")
        
        if attack_surface['top_risks']:
            lines.append("### Top Security Risks")
            lines.append("")
            for i, risk in enumerate(attack_surface['top_risks'], 1):
                lines.append(f"{i}. **{risk['title']}** (Risk Score: {risk['risk_score']})")
                lines.append(f"   - Resource: `{risk['resource']}`")
                lines.append(f"   - Impact: {risk['impact']}")
                lines.append("")
        
        # Quick Wins
        quick_wins = self.analyzer.get_quick_wins()[:5]
        if quick_wins:
            lines.append("## Quick Wins")
            lines.append("")
            lines.append("These findings have automated remediation available and should be addressed first:")
            lines.append("")
            for finding in quick_wins:
                lines.append(f"- **{finding.title}** ({finding.severity.value})")
                lines.append(f"  - Resource: `{finding.resource_id}`")
                lines.append(f"  - Risk Score: {finding.risk_score}")
            lines.append("")
        
        # Detailed Findings by Severity
        lines.append("## Detailed Findings")
        lines.append("")
        
        for severity in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]:
            severity_findings = [f for f in self.findings if f.severity == severity]
            if severity_findings:
                lines.append(f"### {severity.value} Severity ({len(severity_findings)} findings)")
                lines.append("")
                
                for finding in severity_findings[:10]:  # Limit to first 10 per severity
                    lines.append(f"#### {finding.title}")
                    lines.append(f"")
                    lines.append(f"- **Resource Type:** {finding.resource_type}")
                    lines.append(f"- **Resource ID:** `{finding.resource_id}`")
                    lines.append(f"- **Region:** {finding.region}")
                    lines.append(f"- **Risk Score:** {finding.risk_score}")
                    lines.append(f"")
                    lines.append(f"**Description:** {finding.description}")
                    lines.append(f"")
                    lines.append(f"**Impact:** {finding.impact}")
                    lines.append(f"")
                    lines.append(f"**Recommendation:** {finding.recommendation}")
                    lines.append(f"")
                    
                    if finding.compliance_frameworks:
                        frameworks = ', '.join([f.value for f in finding.compliance_frameworks])
                        lines.append(f"**Compliance Frameworks:** {frameworks}")
                        lines.append(f"")
                    
                    if finding.automated_remediation_available:
                        lines.append(f"✅ **Automated remediation available**")
                        lines.append(f"")
                    
                    lines.append("---")
                    lines.append("")
                
                if len(severity_findings) > 10:
                    lines.append(f"*... and {len(severity_findings) - 10} more {severity.value} findings*")
                    lines.append("")
        
        # Compliance Summary
        compliance_summary = self.analyzer.get_compliance_summary()
        if compliance_summary:
            lines.append("## Compliance Framework Summary")
            lines.append("")
            
            for framework, data in compliance_summary.items():
                lines.append(f"### {framework}")
                lines.append(f"- Total Findings: {data['total']}")
                for severity, count in data['by_severity'].items():
                    if count > 0:
                        lines.append(f"- {severity}: {count}")
                lines.append("")
        
        # Remediation Priority Matrix
        lines.append("## Remediation Priority Matrix")
        lines.append("")
        
        matrix = self.analyzer.get_remediation_priority_matrix()
        for priority in matrix:
            lines.append(f"### {priority['priority']}")
            lines.append(f"- **Risk Score Range:** {priority['risk_score_range']}")
            lines.append(f"- **Total Findings:** {priority['finding_count']}")
            lines.append(f"- **Automated Remediation:** {priority['automated_remediation_count']}")
            lines.append(f"- **Manual Remediation:** {priority['manual_remediation_count']}")
            lines.append(f"- **Estimated Effort:** {priority['estimated_effort']}")
            lines.append("")
        
        return '\n'.join(lines)
    
    def generate_json_report(self) -> str:
        """Generate a JSON report"""
        report_data = {
            'metadata': {
                'report_version': '1.0',
                'generated_at': datetime.utcnow().isoformat(),
                'tool_name': 'AWS Security Analysis Tool'
            },
            'scan_info': {
                'scan_id': self.scan_result.scan_id,
                'account_id': self.scan_result.account_id,
                'regions': self.scan_result.regions,
                'services_scanned': self.scan_result.services_scanned,
                'start_time': self.scan_result.start_time.isoformat(),
                'end_time': self.scan_result.end_time.isoformat() if self.scan_result.end_time else None,
                'total_resources_scanned': self.scan_result.total_resources_scanned
            },
            'statistics': self.scan_result.get_statistics(),
            'findings': [
                {
                    'finding_id': f.finding_id,
                    'severity': f.severity.value,
                    'category': f.category.value,
                    'resource_type': f.resource_type,
                    'resource_id': f.resource_id,
                    'region': f.region,
                    'title': f.title,
                    'description': f.description,
                    'impact': f.impact,
                    'recommendation': f.recommendation,
                    'risk_score': f.risk_score,
                    'compliance_frameworks': [cf.value for cf in f.compliance_frameworks],
                    'automated_remediation_available': f.automated_remediation_available,
                    'detected_at': f.detected_at.isoformat(),
                    'evidence': f.evidence
                }
                for f in self.findings
            ],
            'analysis': {
                'attack_surface': self.analyzer.get_attack_surface_analysis(),
                'remediation_priority_matrix': self.analyzer.get_remediation_priority_matrix(),
                'compliance_summary': self.analyzer.get_compliance_summary(),
                'risk_baseline': self.analyzer.get_risk_trend_baseline()
            }
        }
        
        return json.dumps(report_data, indent=2, default=str)
    
    def generate_text_report(self) -> str:
        """Generate a simple text report"""
        lines = []
        width = 80
        
        # Header
        lines.append("=" * width)
        lines.append("AWS SECURITY ANALYSIS REPORT".center(width))
        lines.append("=" * width)
        lines.append("")
        
        lines.append(f"Generated: {self.scan_result.start_time.strftime('%Y-%m-%d %H:%M:%S UTC')}")
        lines.append(f"Account: {self.scan_result.account_id}")
        lines.append(f"Regions: {', '.join(self.scan_result.regions)}")
        lines.append("")
        
        # Summary
        lines.append("-" * width)
        lines.append("SUMMARY")
        lines.append("-" * width)
        
        stats = self.scan_result.get_statistics()
        lines.append(f"Total Findings: {stats['total_findings']}")
        lines.append(f"  Critical: {stats['severity_distribution']['CRITICAL']}")
        lines.append(f"  High:     {stats['severity_distribution']['HIGH']}")
        lines.append(f"  Medium:   {stats['severity_distribution']['MEDIUM']}")
        lines.append(f"  Low:      {stats['severity_distribution']['LOW']}")
        lines.append(f"  Info:     {stats['severity_distribution']['INFO']}")
        lines.append("")
        
        # Critical and High findings
        critical_high = [f for f in self.findings if f.severity in [Severity.CRITICAL, Severity.HIGH]]
        if critical_high:
            lines.append("-" * width)
            lines.append("CRITICAL AND HIGH SEVERITY FINDINGS")
            lines.append("-" * width)
            
            for finding in critical_high:
                lines.append(f"\n[{finding.severity.value}] {finding.title}")
                lines.append(f"Resource: {finding.resource_type} - {finding.resource_id}")
                lines.append(f"Region: {finding.region}")
                lines.append(f"Risk Score: {finding.risk_score}")
                lines.append(f"Impact: {finding.impact}")
                lines.append(f"Action: {finding.recommendation}")
                
                if finding.automated_remediation_available:
                    lines.append("Note: Automated remediation available")
        
        lines.append("")
        lines.append("=" * width)
        lines.append("END OF REPORT")
        lines.append("=" * width)
        
        return '\n'.join(lines)
    
    def _group_findings_by_severity(self) -> Dict[str, List[Finding]]:
        """Group findings by severity level"""
        grouped = {}
        for severity in Severity:
            grouped[severity.value] = [f for f in self.findings if f.severity == severity]
        return grouped
    
    def _get_html_template(self) -> str:
        """Get the HTML template"""
        return '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AWS Security Analysis Report</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background-color: #f5f5f5;
        }
        .container {
            background-color: white;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        h1, h2, h3 {
            color: #232f3e;
        }
        h1 {
            border-bottom: 3px solid #ff9900;
            padding-bottom: 10px;
        }
        .summary-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin: 20px 0;
        }
        .summary-card {
            background-color: #f8f9fa;
            padding: 20px;
            border-radius: 8px;
            text-align: center;
            border: 1px solid #dee2e6;
        }
        .summary-card h3 {
            margin: 0 0 10px 0;
            font-size: 18px;
        }
        .summary-card .number {
            font-size: 36px;
            font-weight: bold;
        }
        .severity-badge {
            display: inline-block;
            padding: 4px 12px;
            border-radius: 4px;
            color: white;
            font-weight: bold;
            font-size: 14px;
        }
        .finding {
            background-color: #f8f9fa;
            padding: 20px;
            margin: 15px 0;
            border-radius: 8px;
            border-left: 4px solid #dee2e6;
        }
        .finding.critical { border-left-color: #dc3545; }
        .finding.high { border-left-color: #fd7e14; }
        .finding.medium { border-left-color: #ffc107; }
        .finding.low { border-left-color: #28a745; }
        .finding.info { border-left-color: #17a2b8; }
        .finding h4 {
            margin-top: 0;
        }
        .metadata {
            display: flex;
            gap: 20px;
            color: #666;
            font-size: 14px;
            margin: 10px 0;
        }
        .metadata span {
            display: flex;
            align-items: center;
            gap: 5px;
        }
        .recommendation {
            background-color: #e9ecef;
            padding: 15px;
            border-radius: 4px;
            margin: 10px 0;
        }
        .quick-wins {
            background-color: #d4edda;
            border: 1px solid #c3e6cb;
            padding: 20px;
            border-radius: 8px;
            margin: 20px 0;
        }
        .chart-container {
            margin: 20px 0;
            padding: 20px;
            background-color: #f8f9fa;
            border-radius: 8px;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }
        th, td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #dee2e6;
        }
        th {
            background-color: #f8f9fa;
            font-weight: bold;
        }
        .progress-bar {
            width: 100%;
            height: 20px;
            background-color: #e9ecef;
            border-radius: 10px;
            overflow: hidden;
            margin: 10px 0;
        }
        .progress-fill {
            height: 100%;
            background-color: #28a745;
            transition: width 0.3s ease;
        }
        code {
            background-color: #f8f9fa;
            padding: 2px 6px;
            border-radius: 3px;
            font-family: 'Courier New', monospace;
        }
        .resource-id {
            font-family: monospace;
            background-color: #f0f0f0;
            padding: 2px 6px;
            border-radius: 3px;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>AWS Security Analysis Report</h1>
        
        <div class="metadata">
            <span>📅 Generated: {{ scan_date }}</span>
            <span>🏢 Account: {{ account_id }}</span>
            <span>🌍 Regions: {{ regions_scanned }}</span>
        </div>
        
        <h2>Executive Summary</h2>
        
        <div class="summary-grid">
            <div class="summary-card">
                <h3>Total Findings</h3>
                <div class="number">{{ statistics.total_findings }}</div>
            </div>
            <div class="summary-card" style="border-color: {{ severity_colors.CRITICAL }};">
                <h3>Critical</h3>
                <div class="number" style="color: {{ severity_colors.CRITICAL }};">
                    {{ statistics.severity_distribution.CRITICAL }}
                </div>
            </div>
            <div class="summary-card" style="border-color: {{ severity_colors.HIGH }};">
                <h3>High</h3>
                <div class="number" style="color: {{ severity_colors.HIGH }};">
                    {{ statistics.severity_distribution.HIGH }}
                </div>
            </div>
            <div class="summary-card" style="border-color: {{ severity_colors.MEDIUM }};">
                <h3>Medium</h3>
                <div class="number" style="color: {{ severity_colors.MEDIUM }};">
                    {{ statistics.severity_distribution.MEDIUM }}
                </div>
            </div>
        </div>
        
        {% if quick_wins %}
        <div class="quick-wins">
            <h2>🎯 Quick Wins</h2>
            <p>These findings have automated remediation available and should be addressed first:</p>
            <ul>
                {% for finding in quick_wins %}
                <li>
                    <strong>{{ finding.title }}</strong> 
                    <span class="severity-badge" style="background-color: {{ severity_colors[finding.severity.value] }};">
                        {{ finding.severity.value }}
                    </span>
                    - <span class="resource-id">{{ finding.resource_id }}</span>
                    (Risk Score: {{ finding.risk_score }})
                </li>
                {% endfor %}
            </ul>
        </div>
        {% endif %}
        
        <h2>Attack Surface Analysis</h2>
        <div class="chart-container">
            <p><strong>Total Attack Vectors:</strong> {{ attack_surface.total_attack_vectors }}</p>
            <p><strong>Critical Exposures:</strong> {{ attack_surface.critical_exposures }}</p>
            <p><strong>Categories Affected:</strong> {{ attack_surface.categories_affected }}</p>
            <p><strong>Services Affected:</strong> {{ attack_surface.services_affected }}</p>
            
            {% if attack_surface.top_risks %}
            <h3>Top Security Risks</h3>
            <ol>
                {% for risk in attack_surface.top_risks %}
                <li>
                    <strong>{{ risk.title }}</strong> (Risk Score: {{ risk.risk_score }})
                    <br>Resource: <code>{{ risk.resource }}</code>
                    <br>Impact: {{ risk.impact }}
                </li>
                {% endfor %}
            </ol>
            {% endif %}
        </div>
        
        <h2>Remediation Priority Matrix</h2>
        <table>
            <thead>
                <tr>
                    <th>Priority</th>
                    <th>Risk Score Range</th>
                    <th>Finding Count</th>
                    <th>Automated</th>
                    <th>Manual</th>
                    <th>Estimated Effort</th>
                </tr>
            </thead>
            <tbody>
                {% for priority in priority_matrix %}
                <tr>
                    <td><strong>{{ priority.priority }}</strong></td>
                    <td>{{ priority.risk_score_range }}</td>
                    <td>{{ priority.finding_count }}</td>
                    <td>{{ priority.automated_remediation_count }}</td>
                    <td>{{ priority.manual_remediation_count }}</td>
                    <td>{{ priority.estimated_effort }}</td>
                </tr>
                {% endfor %}
            </tbody>
        </table>
        
        <h2>Detailed Findings</h2>
        
        {% for severity, findings in findings_by_severity.items() %}
            {% if findings %}
            <h3>
                <span class="severity-badge" style="background-color: {{ severity_colors[severity] }};">
                    {{ severity }}
                </span>
                Severity ({{ findings|length }} findings)
            </h3>
            
            {% for finding in findings[:10] %}
            <div class="finding {{ severity|lower }}">
                <h4>{{ finding.title }}</h4>
                
                <div class="metadata">
                    <span>📦 {{ finding.resource_type }}</span>
                    <span>🔑 {{ finding.resource_id }}</span>
                    <span>📍 {{ finding.region }}</span>
                    <span>⚡ Risk Score: {{ finding.risk_score }}</span>
                </div>
                
                <p><strong>Description:</strong> {{ finding.description }}</p>
                <p><strong>Impact:</strong> {{ finding.impact }}</p>
                
                <div class="recommendation">
                    <strong>Recommendation:</strong> {{ finding.recommendation }}
                </div>
                
                {% if finding.compliance_frameworks %}
                <p><strong>Compliance Frameworks:</strong> 
                    {% for framework in finding.compliance_frameworks %}
                        <span class="severity-badge" style="background-color: #6c757d;">{{ framework.value }}</span>
                    {% endfor %}
                </p>
                {% endif %}
                
                {% if finding.automated_remediation_available %}
                <p>✅ <strong>Automated remediation available</strong></p>
                {% endif %}
            </div>
            {% endfor %}
            
            {% if findings|length > 10 %}
            <p><em>... and {{ findings|length - 10 }} more {{ severity }} findings</em></p>
            {% endif %}
            {% endif %}
        {% endfor %}
        
        <h2>Compliance Summary</h2>
        <div class="chart-container">
            {% for framework, data in compliance_summary.items() %}
            <h3>{{ framework }}</h3>
            <p>Total Findings: {{ data.total }}</p>
            <div class="progress-bar">
                <div class="progress-fill" style="width: {{ (data.total / statistics.total_findings * 100)|round }}%;"></div>
            </div>
            {% endfor %}
        </div>
        
        <div style="text-align: center; margin-top: 40px; color: #666;">
            <p>Generated by AWS Security Analysis Tool</p>
            <p>{{ scan_date }}</p>
        </div>
    </div>
</body>
</html>'''