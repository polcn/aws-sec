"""Executive Summary Dashboard Generator for AWS Security Analysis Tool"""

from typing import Dict, Any, List
from datetime import datetime
import json
from jinja2 import Environment
from ..models import ScanResult, Severity, Category
from ..analyzers import FindingAnalyzer


class DashboardGenerator:
    """Generate an executive summary dashboard for security findings"""
    
    def __init__(self, scan_result: ScanResult):
        self.scan_result = scan_result
        self.analyzer = FindingAnalyzer(scan_result)
        self.findings = scan_result.findings
    
    def generate_dashboard(self) -> str:
        """Generate the executive summary dashboard HTML"""
        env = Environment()
        # Use built-in tojson filter instead of custom tojson
        template = env.from_string(self._get_dashboard_template())
        
        # Get statistics and convert severity distribution to use string keys
        stats = self.scan_result.get_statistics()
        severity_dist = stats['severity_distribution']
        stats['severity_distribution'] = {
            'CRITICAL': severity_dist.get(Severity.CRITICAL, 0),
            'HIGH': severity_dist.get(Severity.HIGH, 0),
            'MEDIUM': severity_dist.get(Severity.MEDIUM, 0),
            'LOW': severity_dist.get(Severity.LOW, 0),
            'INFO': severity_dist.get(Severity.INFO, 0)
        }
        
        context = {
            'scan_date': self.scan_result.start_time.strftime('%Y-%m-%d %H:%M:%S UTC'),
            'account_id': self.scan_result.account_id,
            'regions_count': len(self.scan_result.regions),
            'services_count': len(self.scan_result.services_scanned),
            'scan_duration': self._format_duration(stats.get('scan_duration', 0)),
            'statistics': stats,
            'severity_data': self._get_severity_chart_data(),
            'category_data': self._get_category_chart_data(),
            'service_data': self._get_service_chart_data(),
            'compliance_data': self._get_compliance_chart_data(),
            'risk_distribution': self._get_risk_distribution(),
            'attack_surface': self.analyzer.get_attack_surface_analysis(),
            'top_risks': self.analyzer.get_attack_surface_analysis()['top_risks'][:5],
            'quick_wins_count': len(self.analyzer.get_quick_wins()),
            'remediation_matrix': [
                {k: v for k, v in item.items() if k != 'findings'}
                for item in self.analyzer.get_remediation_priority_matrix()
            ],
            'security_score': self._calculate_security_score(),
            'trend_indicator': self._get_trend_indicator()
        }
        
        
        return template.render(**context)
    
    def _format_duration(self, seconds: float) -> str:
        """Format duration in human-readable format"""
        if seconds < 60:
            return f"{int(seconds)}s"
        elif seconds < 3600:
            return f"{int(seconds / 60)}m {int(seconds % 60)}s"
        else:
            hours = int(seconds / 3600)
            minutes = int((seconds % 3600) / 60)
            return f"{hours}h {minutes}m"
    
    def _get_severity_chart_data(self) -> Dict[str, Any]:
        """Get severity distribution data for charts"""
        stats = self.scan_result.get_statistics()
        distribution = stats['severity_distribution']
        
        return {
            'labels': ['Critical', 'High', 'Medium', 'Low', 'Info'],
            'values': [
                distribution.get(Severity.CRITICAL, 0),
                distribution.get(Severity.HIGH, 0),
                distribution.get(Severity.MEDIUM, 0),
                distribution.get(Severity.LOW, 0),
                distribution.get(Severity.INFO, 0)
            ],
            'colors': ['#dc3545', '#fd7e14', '#ffc107', '#28a745', '#17a2b8']
        }
    
    def _get_category_chart_data(self) -> Dict[str, Any]:
        """Get category distribution data for charts"""
        category_counts = {}
        for finding in self.findings:
            category = finding.category.value
            category_counts[category] = category_counts.get(category, 0) + 1
        
        # Sort by count descending
        sorted_categories = sorted(category_counts.items(), key=lambda x: x[1], reverse=True)
        
        return {
            'labels': [cat[0] for cat in sorted_categories],
            'values': [cat[1] for cat in sorted_categories],
            'colors': ['#3498db', '#e74c3c', '#f39c12', '#2ecc71', '#9b59b6', '#1abc9c']
        }
    
    def _get_service_chart_data(self) -> Dict[str, Any]:
        """Get service distribution data for charts"""
        findings_by_service = self.analyzer.get_findings_by_service()
        
        # Sort by count descending
        sorted_services = sorted(
            [(service, len(findings)) for service, findings in findings_by_service.items()],
            key=lambda x: x[1],
            reverse=True
        )
        
        return {
            'labels': [svc[0] for svc in sorted_services],
            'values': [svc[1] for svc in sorted_services],
            'colors': ['#FF9900', '#232F3E', '#146EB4', '#FF9900', '#232F3E']  # AWS colors
        }
    
    def _get_compliance_chart_data(self) -> Dict[str, Any]:
        """Get compliance percentage data for charts"""
        compliance_scores = self.analyzer.get_compliance_percentage_scores()
        
        return {
            'labels': list(compliance_scores.keys()),
            'values': [score['compliance_percentage'] for score in compliance_scores.values()],
            'risk_levels': [score['risk_level'] for score in compliance_scores.values()],
            'colors': {
                'Low': '#28a745',
                'Medium': '#ffc107',
                'High': '#fd7e14',
                'Critical': '#dc3545'
            }
        }
    
    def _get_risk_distribution(self) -> Dict[str, int]:
        """Get risk score distribution"""
        distribution = {
            'critical': 0,  # 90-100
            'high': 0,      # 70-89
            'medium': 0,    # 50-69
            'low': 0        # 0-49
        }
        
        for finding in self.findings:
            if finding.risk_score >= 90:
                distribution['critical'] += 1
            elif finding.risk_score >= 70:
                distribution['high'] += 1
            elif finding.risk_score >= 50:
                distribution['medium'] += 1
            else:
                distribution['low'] += 1
        
        return distribution
    
    def _calculate_security_score(self) -> Dict[str, Any]:
        """Calculate overall security score (inverse of risk)"""
        if not self.findings:
            return {'score': 100, 'grade': 'A', 'color': '#28a745'}
        
        # Calculate weighted risk score
        total_weight = 0
        weighted_risk = 0
        
        severity_weights = {
            Severity.CRITICAL: 1.0,
            Severity.HIGH: 0.8,
            Severity.MEDIUM: 0.5,
            Severity.LOW: 0.2,
            Severity.INFO: 0.1
        }
        
        for finding in self.findings:
            weight = severity_weights.get(finding.severity, 0.1)
            weighted_risk += finding.risk_score * weight
            total_weight += weight
        
        avg_weighted_risk = weighted_risk / total_weight if total_weight > 0 else 0
        security_score = max(0, 100 - avg_weighted_risk)
        
        # Determine grade
        if security_score >= 90:
            grade, color = 'A', '#28a745'
        elif security_score >= 80:
            grade, color = 'B', '#28a745'
        elif security_score >= 70:
            grade, color = 'C', '#ffc107'
        elif security_score >= 60:
            grade, color = 'D', '#fd7e14'
        else:
            grade, color = 'F', '#dc3545'
        
        return {
            'score': round(security_score, 1),
            'grade': grade,
            'color': color
        }
    
    def _get_trend_indicator(self) -> Dict[str, Any]:
        """Get trend indicator (placeholder for future trend analysis)"""
        # This will be replaced with actual trend analysis when implemented
        return {
            'direction': 'neutral',
            'symbol': '→',
            'color': '#6c757d',
            'text': 'No previous scan data'
        }
    
    def _get_dashboard_template(self) -> str:
        """Get the dashboard HTML template"""
        return '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AWS Security Dashboard - Executive Summary</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background-color: #f0f2f5;
            color: #1a1a1a;
        }
        
        .dashboard {
            max-width: 1400px;
            margin: 0 auto;
            padding: 20px;
        }
        
        .header {
            background: linear-gradient(135deg, #232F3E 0%, #FF9900 100%);
            color: white;
            padding: 30px;
            border-radius: 10px;
            margin-bottom: 30px;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
        }
        
        .header h1 {
            font-size: 2.5em;
            margin-bottom: 10px;
        }
        
        .header-meta {
            display: flex;
            gap: 30px;
            margin-top: 20px;
            flex-wrap: wrap;
        }
        
        .header-meta-item {
            display: flex;
            align-items: center;
            gap: 8px;
        }
        
        .grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        
        .grid-2 {
            grid-template-columns: repeat(auto-fit, minmax(400px, 1fr));
        }
        
        .card {
            background: white;
            border-radius: 10px;
            padding: 25px;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
            transition: transform 0.2s, box-shadow 0.2s;
        }
        
        .card:hover {
            transform: translateY(-2px);
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.15);
        }
        
        .card h2 {
            font-size: 1.2em;
            color: #232F3E;
            margin-bottom: 20px;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        
        .metric-card {
            text-align: center;
        }
        
        .metric-value {
            font-size: 3em;
            font-weight: bold;
            margin: 10px 0;
        }
        
        .metric-label {
            color: #666;
            font-size: 0.9em;
        }
        
        .security-score {
            position: relative;
            width: 200px;
            height: 200px;
            margin: 0 auto;
        }
        
        .score-circle {
            width: 100%;
            height: 100%;
            border-radius: 50%;
            background: conic-gradient(
                var(--score-color) 0deg,
                var(--score-color) calc(var(--score) * 3.6deg),
                #e9ecef calc(var(--score) * 3.6deg)
            );
            display: flex;
            align-items: center;
            justify-content: center;
            position: relative;
        }
        
        .score-inner {
            width: 85%;
            height: 85%;
            border-radius: 50%;
            background: white;
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
        }
        
        .score-grade {
            font-size: 3em;
            font-weight: bold;
        }
        
        .score-value {
            font-size: 1.2em;
            color: #666;
        }
        
        .severity-badge {
            display: inline-flex;
            align-items: center;
            padding: 6px 12px;
            border-radius: 20px;
            font-size: 0.85em;
            font-weight: 600;
            color: white;
        }
        
        .severity-critical { background-color: #dc3545; }
        .severity-high { background-color: #fd7e14; }
        .severity-medium { background-color: #ffc107; color: #333; }
        .severity-low { background-color: #28a745; }
        .severity-info { background-color: #17a2b8; }
        
        .risk-item {
            padding: 15px;
            margin: 10px 0;
            background: #f8f9fa;
            border-radius: 8px;
            border-left: 4px solid #dc3545;
        }
        
        .risk-item h3 {
            font-size: 1.1em;
            margin-bottom: 5px;
        }
        
        .risk-item p {
            color: #666;
            font-size: 0.9em;
        }
        
        .chart-container {
            position: relative;
            height: 300px;
            margin-top: 20px;
        }
        
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(2, 1fr);
            gap: 15px;
            margin-top: 20px;
        }
        
        .stat-item {
            padding: 15px;
            background: #f8f9fa;
            border-radius: 8px;
            text-align: center;
        }
        
        .stat-value {
            font-size: 2em;
            font-weight: bold;
            color: #232F3E;
        }
        
        .stat-label {
            color: #666;
            font-size: 0.9em;
        }
        
        .progress-bar {
            width: 100%;
            height: 8px;
            background: #e9ecef;
            border-radius: 4px;
            overflow: hidden;
            margin: 10px 0;
        }
        
        .progress-fill {
            height: 100%;
            background: var(--progress-color, #28a745);
            transition: width 0.3s ease;
        }
        
        .footer {
            text-align: center;
            color: #666;
            margin-top: 50px;
            padding: 20px;
        }
        
        .quick-actions {
            display: flex;
            gap: 15px;
            margin-top: 20px;
            flex-wrap: wrap;
        }
        
        .action-button {
            padding: 10px 20px;
            background: #FF9900;
            color: white;
            border: none;
            border-radius: 5px;
            font-weight: 600;
            cursor: pointer;
            text-decoration: none;
            display: inline-block;
            transition: background 0.2s;
        }
        
        .action-button:hover {
            background: #e88a00;
        }
        
        .action-button.secondary {
            background: #6c757d;
        }
        
        .action-button.secondary:hover {
            background: #5a6268;
        }
        
        @media (max-width: 768px) {
            .grid {
                grid-template-columns: 1fr;
            }
            
            .header h1 {
                font-size: 1.8em;
            }
            
            .metric-value {
                font-size: 2em;
            }
        }
    </style>
</head>
<body>
    <div class="dashboard">
        <div class="header">
            <h1>AWS Security Dashboard</h1>
            <p>Executive Summary - {{ scan_date }}</p>
            <div class="header-meta">
                <div class="header-meta-item">
                    <span>🏢</span>
                    <span>Account: {{ account_id }}</span>
                </div>
                <div class="header-meta-item">
                    <span>🌍</span>
                    <span>{{ regions_count }} Regions</span>
                </div>
                <div class="header-meta-item">
                    <span>🔧</span>
                    <span>{{ services_count }} Services</span>
                </div>
                <div class="header-meta-item">
                    <span>⏱️</span>
                    <span>Scan Time: {{ scan_duration }}</span>
                </div>
            </div>
        </div>
        
        <!-- Key Metrics -->
        <div class="grid">
            <div class="card metric-card">
                <h2>Security Score</h2>
                <div class="security-score">
                    <div class="score-circle" style="--score: {{ security_score.score }}; --score-color: {{ security_score.color }};">
                        <div class="score-inner">
                            <div class="score-grade" style="color: {{ security_score.color }};">{{ security_score.grade }}</div>
                            <div class="score-value">{{ security_score.score }}%</div>
                        </div>
                    </div>
                </div>
                <p class="metric-label">{{ trend_indicator.symbol }} {{ trend_indicator.text }}</p>
            </div>
            
            <div class="card metric-card">
                <h2>Total Findings</h2>
                <div class="metric-value" style="color: #232F3E;">{{ statistics.total_findings }}</div>
                <div style="margin-top: 20px;">
                    <span class="severity-badge severity-critical">{{ statistics.severity_distribution.CRITICAL }} Critical</span>
                    <span class="severity-badge severity-high">{{ statistics.severity_distribution.HIGH }} High</span>
                    <span class="severity-badge severity-medium">{{ statistics.severity_distribution.MEDIUM }} Medium</span>
                </div>
            </div>
            
            <div class="card metric-card">
                <h2>Attack Surface</h2>
                <div class="metric-value" style="color: #dc3545;">{{ attack_surface.critical_exposures }}</div>
                <p class="metric-label">Critical Exposures</p>
                <div class="stats-grid" style="margin-top: 20px;">
                    <div class="stat-item">
                        <div class="stat-value">{{ attack_surface.total_attack_vectors }}</div>
                        <div class="stat-label">Attack Vectors</div>
                    </div>
                    <div class="stat-item">
                        <div class="stat-value">{{ attack_surface.services_affected }}</div>
                        <div class="stat-label">Services Affected</div>
                    </div>
                </div>
            </div>
            
            <div class="card metric-card">
                <h2>Quick Wins</h2>
                <div class="metric-value" style="color: #28a745;">{{ quick_wins_count }}</div>
                <p class="metric-label">Automated Remediations Available</p>
                <div class="quick-actions">
                    <a href="#" class="action-button">Generate Scripts</a>
                    <a href="#" class="action-button secondary">View Details</a>
                </div>
            </div>
        </div>
        
        <!-- Charts Row -->
        <div class="grid grid-2">
            <div class="card">
                <h2>📊 Severity Distribution</h2>
                <div class="chart-container">
                    <canvas id="severityChart"></canvas>
                </div>
            </div>
            
            <div class="card">
                <h2>🔐 Compliance Status</h2>
                <div class="chart-container">
                    <canvas id="complianceChart"></canvas>
                </div>
            </div>
        </div>
        
        <!-- Additional Charts -->
        <div class="grid grid-2">
            <div class="card">
                <h2>📁 Findings by Category</h2>
                <div class="chart-container">
                    <canvas id="categoryChart"></canvas>
                </div>
            </div>
            
            <div class="card">
                <h2>🛠️ Findings by Service</h2>
                <div class="chart-container">
                    <canvas id="serviceChart"></canvas>
                </div>
            </div>
        </div>
        
        <!-- Top Risks -->
        <div class="card">
            <h2>⚠️ Top Security Risks</h2>
            {% for risk in top_risks %}
            <div class="risk-item">
                <h3>{{ risk.title }} <span style="float: right; color: #dc3545;">Risk Score: {{ risk.risk_score }}</span></h3>
                <p>{{ risk.impact }}</p>
                <p style="margin-top: 5px;"><strong>Resource:</strong> {{ risk.resource }}</p>
            </div>
            {% endfor %}
        </div>
        
        <!-- Remediation Priority -->
        <div class="card">
            <h2>🎯 Remediation Priority</h2>
            <div class="grid" style="margin-top: 20px;">
                {% for priority in remediation_matrix %}
                <div class="stat-item">
                    <h3>{{ priority.priority }}</h3>
                    <div class="stat-value">{{ priority.finding_count }}</div>
                    <div class="stat-label">{{ priority.risk_score_range }}</div>
                    <div class="progress-bar">
                        <div class="progress-fill" style="width: {{ (priority.automated_remediation_count / priority.finding_count * 100) if priority.finding_count > 0 else 0 }}%; --progress-color: #28a745;"></div>
                    </div>
                    <p style="font-size: 0.8em; color: #666;">{{ priority.automated_remediation_count }} automated</p>
                </div>
                {% endfor %}
            </div>
        </div>
        
        <div class="footer">
            <p>Generated by AWS Security Analysis Tool</p>
            <p>{{ scan_date }}</p>
        </div>
    </div>
    
    <script>
        // Severity Distribution Chart
        const severityCtx = document.getElementById('severityChart').getContext('2d');
        new Chart(severityCtx, {
            type: 'doughnut',
            data: {
                labels: {{ severity_data.labels | tojson }},
                datasets: [{
                    data: {{ severity_data['values'] | tojson }},
                    backgroundColor: {{ severity_data.colors | tojson }},
                    borderWidth: 0
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'bottom',
                        labels: {
                            padding: 15,
                            font: { size: 12 }
                        }
                    }
                }
            }
        });
        
        // Compliance Chart
        const complianceCtx = document.getElementById('complianceChart').getContext('2d');
        const complianceColors = {{ compliance_data['values'] | tojson }}.map((value, index) => {
            const riskLevel = {{ compliance_data.risk_levels | tojson }}[index];
            return {{ compliance_data.colors | tojson }}[riskLevel];
        });
        
        new Chart(complianceCtx, {
            type: 'bar',
            data: {
                labels: {{ compliance_data.labels | tojson }},
                datasets: [{
                    label: 'Compliance %',
                    data: {{ compliance_data['values'] | tojson }},
                    backgroundColor: complianceColors,
                    borderWidth: 0
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    y: {
                        beginAtZero: true,
                        max: 100,
                        ticks: {
                            callback: function(value) {
                                return value + '%';
                            }
                        }
                    }
                },
                plugins: {
                    legend: { display: false }
                }
            }
        });
        
        // Category Chart
        const categoryCtx = document.getElementById('categoryChart').getContext('2d');
        new Chart(categoryCtx, {
            type: 'bar',
            data: {
                labels: {{ category_data.labels | tojson }},
                datasets: [{
                    label: 'Findings',
                    data: {{ category_data['values'] | tojson }},
                    backgroundColor: '#3498db',
                    borderWidth: 0
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    y: { beginAtZero: true }
                },
                plugins: {
                    legend: { display: false }
                }
            }
        });
        
        // Service Chart
        const serviceCtx = document.getElementById('serviceChart').getContext('2d');
        new Chart(serviceCtx, {
            type: 'pie',
            data: {
                labels: {{ service_data.labels | tojson }},
                datasets: [{
                    data: {{ service_data['values'] | tojson }},
                    backgroundColor: {{ service_data.colors | tojson }},
                    borderWidth: 0
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'bottom',
                        labels: {
                            padding: 15,
                            font: { size: 12 }
                        }
                    }
                }
            }
        });
    </script>
</body>
</html>'''