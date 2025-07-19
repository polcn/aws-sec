"""Tests for the ReportGenerator class"""

import pytest
from datetime import datetime
import csv
import io
import json
from src.models import Finding, ScanResult, Severity, Category, ComplianceFramework
from src.generators import ReportGenerator
from src.analyzers import FindingAnalyzer


@pytest.fixture
def sample_findings():
    """Create sample findings for testing"""
    return [
        Finding(
            finding_id="test-001",
            severity=Severity.CRITICAL,
            category=Category.IAM,
            resource_type="AWS::IAM::User",
            resource_id="admin-user",
            region="global",
            title="Critical IAM Finding",
            description="This is a critical finding",
            impact="High security risk",
            recommendation="Fix immediately",
            risk_score=100,
            compliance_frameworks=[ComplianceFramework.NIST, ComplianceFramework.CIS],
            automated_remediation_available=False,
            detected_at=datetime.utcnow(),
            evidence={"key": "value"}
        ),
        Finding(
            finding_id="test-002",
            severity=Severity.HIGH,
            category=Category.DATA_PROTECTION,
            resource_type="AWS::S3::Bucket",
            resource_id="test-bucket",
            region="us-east-1",
            title="S3 Bucket Not Encrypted",
            description="Bucket lacks encryption",
            impact="Data at rest not protected",
            recommendation="Enable encryption",
            risk_score=80,
            compliance_frameworks=[ComplianceFramework.NIST],
            automated_remediation_available=True,
            detected_at=datetime.utcnow(),
            evidence={"encryption": "none"}
        ),
        Finding(
            finding_id="test-003",
            severity=Severity.MEDIUM,
            category=Category.ACCESS_CONTROL,
            resource_type="AWS::EC2::SecurityGroup",
            resource_id="sg-12345",
            region="us-west-2",
            title="Security Group Too Permissive",
            description="Security group allows 0.0.0.0/0",
            impact="Exposed to internet",
            recommendation="Restrict access",
            risk_score=60,
            compliance_frameworks=[ComplianceFramework.CIS],
            automated_remediation_available=True,
            detected_at=datetime.utcnow(),
            evidence={"rules": [{"cidr": "0.0.0.0/0"}]}
        )
    ]


@pytest.fixture
def scan_result(sample_findings):
    """Create a sample scan result"""
    result = ScanResult(
        scan_id="test-scan-001",
        account_id="123456789012",
        regions=["us-east-1", "us-west-2"],
        services_scanned=["iam", "s3", "ec2"],
        start_time=datetime.utcnow()
    )
    result.findings = sample_findings
    result.end_time = datetime.utcnow()
    result.total_resources_scanned = 50
    return result


class TestReportGenerator:
    """Test cases for ReportGenerator"""
    
    def test_csv_report_generation(self, scan_result):
        """Test CSV report generation"""
        generator = ReportGenerator(scan_result)
        csv_content = generator.generate_csv_report()
        
        # Parse the CSV content
        reader = csv.reader(io.StringIO(csv_content))
        rows = list(reader)
        
        # Check headers
        assert rows[0] == [
            'Finding ID', 'Severity', 'Risk Score', 'Category', 'Service',
            'Resource Type', 'Resource ID', 'Region', 'Title', 'Description',
            'Impact', 'Recommendation', 'Compliance Frameworks',
            'Automated Remediation', 'Detected At'
        ]
        
        # Check findings data (3 findings)
        assert len([r for r in rows[1:] if r and r[0].startswith('test-')]) == 3
        
        # Check first finding
        assert rows[1][0] == 'test-001'  # Finding ID
        assert rows[1][1] == 'CRITICAL'  # Severity
        assert rows[1][2] == '100'  # Risk Score
        assert rows[1][3] == 'IAM'  # Category
        assert rows[1][6] == 'admin-user'  # Resource ID
        assert rows[1][13] == 'No'  # Automated Remediation
        
        # Check summary statistics section
        summary_start = None
        for i, row in enumerate(rows):
            if row and row[0] == 'Summary Statistics':
                summary_start = i
                break
        
        assert summary_start is not None
        
        # Check summary metrics
        metrics = {}
        for row in rows[summary_start + 2:]:  # Skip header rows
            if len(row) >= 2 and row[0] and row[1]:
                metrics[row[0]] = row[1]
        
        assert metrics['Total Findings'] == '3'
        assert metrics['Critical'] == '1'
        assert metrics['High'] == '1'
        assert metrics['Medium'] == '1'
        assert metrics['Low'] == '0'
        assert metrics['Account ID'] == '123456789012'
        assert metrics['Resources Scanned'] == '50'
    
    def test_csv_report_special_characters(self, scan_result):
        """Test CSV report handles special characters properly"""
        # Add a finding with special characters
        scan_result.findings.append(Finding(
            finding_id="test-004",
            severity=Severity.LOW,
            category=Category.LOGGING,
            resource_type="AWS::CloudTrail::Trail",
            resource_id="trail-with,comma",
            region="us-east-1",
            title='Trail with "quotes" and commas',
            description='Description with\nnewline',
            impact="Impact with 'single quotes'",
            recommendation="Use proper \"escaping\"",
            risk_score=30,
            compliance_frameworks=[],
            automated_remediation_available=False,
            detected_at=datetime.utcnow(),
            evidence={}
        ))
        
        generator = ReportGenerator(scan_result)
        csv_content = generator.generate_csv_report()
        
        # Verify CSV can be parsed without errors
        reader = csv.reader(io.StringIO(csv_content))
        rows = list(reader)
        
        # Find the row with special characters
        special_row = None
        for row in rows:
            if row and len(row) > 0 and row[0] == 'test-004':
                special_row = row
                break
        
        assert special_row is not None
        assert 'trail-with,comma' in special_row[6]  # Resource ID preserved
        assert 'quotes' in special_row[8]  # Title preserved
        assert 'newline' in special_row[9]  # Description preserved
    
    def test_csv_report_empty_findings(self):
        """Test CSV report with no findings"""
        result = ScanResult(
            scan_id="empty-scan",
            account_id="123456789012",
            regions=["us-east-1"],
            services_scanned=["iam"],
            start_time=datetime.utcnow()
        )
        result.end_time = datetime.utcnow()
        result.total_resources_scanned = 10
        
        generator = ReportGenerator(result)
        csv_content = generator.generate_csv_report()
        
        reader = csv.reader(io.StringIO(csv_content))
        rows = list(reader)
        
        # Should have headers and summary but no findings
        assert rows[0][0] == 'Finding ID'  # Headers present
        
        # Find summary section
        metrics = {}
        for i, row in enumerate(rows):
            if len(row) >= 2 and row[0] == 'Total Findings':
                metrics[row[0]] = row[1]
        
        assert metrics['Total Findings'] == '0'
    
    def test_markdown_report_generation(self, scan_result):
        """Test markdown report still works"""
        generator = ReportGenerator(scan_result)
        md_content = generator.generate_markdown_report()
        
        assert '# AWS Security Analysis Report' in md_content
        assert 'Total Findings:** 3' in md_content
        assert 'Critical IAM Finding' in md_content
    
    def test_json_report_generation(self, scan_result):
        """Test JSON report still works"""
        generator = ReportGenerator(scan_result)
        json_content = generator.generate_json_report()
        
        import json
        data = json.loads(json_content)
        
        assert data['scan_info']['account_id'] == '123456789012'
        assert len(data['findings']) == 3
        assert data['statistics']['total_findings'] == 3


class TestComplianceScoring:
    """Test cases for compliance percentage scoring"""
    
    def test_compliance_percentage_calculation(self, scan_result):
        """Test compliance percentage calculation"""
        analyzer = FindingAnalyzer(scan_result)
        compliance_scores = analyzer.get_compliance_percentage_scores()
        
        # Check that all frameworks are present
        assert 'NIST' in compliance_scores
        assert 'CIS' in compliance_scores
        assert 'SOX' in compliance_scores
        assert 'OWASP' in compliance_scores
        
        # NIST has 2 findings (1 CRITICAL, 1 HIGH)
        nist_score = compliance_scores['NIST']
        assert nist_score['total_findings'] == 2
        assert nist_score['compliance_percentage'] < 100
        assert nist_score['weighted_violations'] == 1.8  # 1.0 + 0.8
        
        # CIS has 2 findings (1 CRITICAL, 1 MEDIUM)
        cis_score = compliance_scores['CIS']
        assert cis_score['total_findings'] == 2
        assert cis_score['compliance_percentage'] < 100
        assert cis_score['weighted_violations'] == 1.5  # 1.0 + 0.5
        
        # SOX has no findings
        sox_score = compliance_scores['SOX']
        assert sox_score['total_findings'] == 0
        assert sox_score['compliance_percentage'] == 100.0
        assert sox_score['risk_level'] == 'Low'
    
    def test_compliance_risk_levels(self, scan_result):
        """Test compliance risk level determination"""
        analyzer = FindingAnalyzer(scan_result)
        
        # Test risk level boundaries
        assert analyzer._get_compliance_risk_level(100) == 'Low'
        assert analyzer._get_compliance_risk_level(95) == 'Low'
        assert analyzer._get_compliance_risk_level(94.9) == 'Medium'
        assert analyzer._get_compliance_risk_level(80) == 'Medium'
        assert analyzer._get_compliance_risk_level(79.9) == 'High'
        assert analyzer._get_compliance_risk_level(60) == 'High'
        assert analyzer._get_compliance_risk_level(59.9) == 'Critical'
        assert analyzer._get_compliance_risk_level(0) == 'Critical'
    
    def test_compliance_in_reports(self, scan_result):
        """Test compliance scores in various report formats"""
        generator = ReportGenerator(scan_result)
        
        # Test markdown report
        md_report = generator.generate_markdown_report()
        assert 'Compliance Framework Summary' in md_report
        assert 'Compliance %' in md_report
        assert 'Risk Level' in md_report
        
        # Test JSON report
        json_report = generator.generate_json_report()
        data = json.loads(json_report)
        assert 'compliance_scores' in data['analysis']
        assert 'NIST' in data['analysis']['compliance_scores']
        
        # Test CSV report
        csv_report = generator.generate_csv_report()
        assert 'Compliance Scores' in csv_report
        assert 'Compliance %' in csv_report
    
    def test_empty_compliance_scores(self):
        """Test compliance scores with no findings"""
        result = ScanResult(
            scan_id="empty-scan",
            account_id="123456789012",
            regions=["us-east-1"],
            services_scanned=["iam"],
            start_time=datetime.utcnow()
        )
        result.end_time = datetime.utcnow()
        
        analyzer = FindingAnalyzer(result)
        compliance_scores = analyzer.get_compliance_percentage_scores()
        
        # All frameworks should be 100% compliant
        for framework, score in compliance_scores.items():
            assert score['compliance_percentage'] == 100.0
            assert score['total_findings'] == 0
            assert score['risk_level'] == 'Low'