from typing import List, Dict, Any, Tuple
from collections import defaultdict
from ..models import Finding, ScanResult, Severity, Category


class FindingAnalyzer:
    """Analyzes findings and provides risk scoring and prioritization"""
    
    def __init__(self, scan_result: ScanResult):
        self.scan_result = scan_result
        self.findings = scan_result.findings
    
    def get_priority_findings(self, limit: int = 10) -> List[Finding]:
        """Get the top priority findings based on risk score"""
        sorted_findings = sorted(self.findings, key=lambda f: f.risk_score, reverse=True)
        return sorted_findings[:limit]
    
    def get_findings_by_service(self) -> Dict[str, List[Finding]]:
        """Group findings by AWS service"""
        service_findings = defaultdict(list)
        
        for finding in self.findings:
            # Extract service from resource type (e.g., "AWS::IAM::User" -> "IAM")
            parts = finding.resource_type.split("::")
            if len(parts) >= 2:
                service = parts[1]
                service_findings[service].append(finding)
        
        return dict(service_findings)
    
    def get_compliance_summary(self) -> Dict[str, Dict[str, int]]:
        """Get compliance framework summary"""
        compliance_summary = defaultdict(lambda: {
            'total': 0,
            'by_severity': defaultdict(int)
        })
        
        for finding in self.findings:
            for framework in finding.compliance_frameworks:
                compliance_summary[framework.value]['total'] += 1
                compliance_summary[framework.value]['by_severity'][finding.severity.value] += 1
        
        return dict(compliance_summary)
    
    def get_remediation_priority_matrix(self) -> List[Dict[str, Any]]:
        """Create a priority matrix for remediation efforts"""
        matrix = []
        
        # Group by risk score ranges
        risk_ranges = [
            (90, 100, "Critical Priority"),
            (70, 89, "High Priority"),
            (50, 69, "Medium Priority"),
            (30, 49, "Low Priority"),
            (0, 29, "Informational")
        ]
        
        for min_score, max_score, priority_label in risk_ranges:
            findings_in_range = [
                f for f in self.findings 
                if min_score <= f.risk_score <= max_score
            ]
            
            if findings_in_range:
                # Calculate effort estimation
                automated_count = sum(
                    1 for f in findings_in_range 
                    if f.automated_remediation_available
                )
                
                matrix.append({
                    'priority': priority_label,
                    'risk_score_range': f"{min_score}-{max_score}",
                    'finding_count': len(findings_in_range),
                    'automated_remediation_count': automated_count,
                    'manual_remediation_count': len(findings_in_range) - automated_count,
                    'estimated_effort': self._estimate_effort(findings_in_range),
                    'top_categories': self._get_top_categories(findings_in_range),
                    'findings': findings_in_range[:5]  # Top 5 findings in this range
                })
        
        return matrix
    
    def get_attack_surface_analysis(self) -> Dict[str, Any]:
        """Analyze the attack surface based on findings"""
        analysis = {
            'total_attack_vectors': len(self.findings),
            'critical_exposures': len([f for f in self.findings if f.severity == Severity.CRITICAL]),
            'categories_affected': len(set(f.category for f in self.findings)),
            'services_affected': len(self.get_findings_by_service()),
            'top_risks': [],
            'exposure_summary': defaultdict(int)
        }
        
        # Categorize exposures
        for finding in self.findings:
            if finding.category == Category.IAM:
                if 'root' in finding.resource_id.lower():
                    analysis['exposure_summary']['root_account_issues'] += 1
                elif 'mfa' in finding.title.lower():
                    analysis['exposure_summary']['mfa_not_enabled'] += 1
                elif 'key' in finding.title.lower():
                    analysis['exposure_summary']['access_key_issues'] += 1
                else:
                    analysis['exposure_summary']['iam_misconfigurations'] += 1
            elif finding.category == Category.DATA:
                analysis['exposure_summary']['data_exposure_risks'] += 1
            elif finding.category == Category.NETWORK:
                analysis['exposure_summary']['network_vulnerabilities'] += 1
            elif finding.category == Category.ENCRYPTION:
                analysis['exposure_summary']['encryption_weaknesses'] += 1
        
        # Identify top risks
        critical_findings = [f for f in self.findings if f.severity in [Severity.CRITICAL, Severity.HIGH]]
        for finding in critical_findings[:5]:
            analysis['top_risks'].append({
                'title': finding.title,
                'resource': finding.resource_id,
                'risk_score': finding.risk_score,
                'impact': finding.impact
            })
        
        return dict(analysis)
    
    def get_quick_wins(self) -> List[Finding]:
        """Identify quick wins - high impact, low effort remediations"""
        quick_wins = []
        
        for finding in self.findings:
            # Quick wins are automated remediations with high severity
            if (finding.automated_remediation_available and 
                finding.severity in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM]):
                quick_wins.append(finding)
        
        # Sort by risk score
        return sorted(quick_wins, key=lambda f: f.risk_score, reverse=True)
    
    def get_risk_trend_baseline(self) -> Dict[str, Any]:
        """Create a baseline for future risk trend analysis"""
        baseline = {
            'scan_date': self.scan_result.start_time.isoformat(),
            'total_findings': len(self.findings),
            'risk_score_average': self._calculate_average_risk_score(),
            'severity_distribution': {},
            'category_distribution': {},
            'service_distribution': {}
        }
        
        # Severity distribution
        for severity in Severity:
            count = len([f for f in self.findings if f.severity == severity])
            baseline['severity_distribution'][severity.value] = count
        
        # Category distribution
        for category in Category:
            count = len([f for f in self.findings if f.category == category])
            if count > 0:
                baseline['category_distribution'][category.value] = count
        
        # Service distribution
        for service, findings in self.get_findings_by_service().items():
            baseline['service_distribution'][service] = len(findings)
        
        return baseline
    
    def _estimate_effort(self, findings: List[Finding]) -> str:
        """Estimate remediation effort"""
        total_findings = len(findings)
        automated = sum(1 for f in findings if f.automated_remediation_available)
        
        if total_findings <= 5:
            return "Low (< 1 day)"
        elif total_findings <= 20:
            if automated > total_findings * 0.7:
                return "Low-Medium (1-2 days)"
            else:
                return "Medium (2-5 days)"
        elif total_findings <= 50:
            if automated > total_findings * 0.5:
                return "Medium (3-5 days)"
            else:
                return "High (1-2 weeks)"
        else:
            return "Very High (> 2 weeks)"
    
    def _get_top_categories(self, findings: List[Finding]) -> List[Tuple[str, int]]:
        """Get top categories for a set of findings"""
        category_counts = defaultdict(int)
        for finding in findings:
            category_counts[finding.category.value] += 1
        
        # Return top 3 categories
        sorted_categories = sorted(
            category_counts.items(), 
            key=lambda x: x[1], 
            reverse=True
        )
        return sorted_categories[:3]
    
    def _calculate_average_risk_score(self) -> float:
        """Calculate average risk score"""
        if not self.findings:
            return 0.0
        
        total_score = sum(f.risk_score for f in self.findings)
        return round(total_score / len(self.findings), 2)