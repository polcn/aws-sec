#!/usr/bin/env python3
"""Test script for enhanced cost scanner features"""

import boto3
import json
from datetime import datetime
from src.scanners.cost_scanner import CostScanner
from src.models import Severity, Category

def test_cost_scanner():
    """Test all enhanced cost scanner features"""
    print("🧪 Testing Enhanced Cost Scanner Features")
    print("=" * 50)
    
    # Initialize session
    session = boto3.Session()
    scanner = CostScanner(session)
    
    # Test categories
    test_categories = [
        ("NAT Gateway Costs", "_check_nat_gateway_costs"),
        ("Data Transfer Costs", "_check_data_transfer_costs"),
        ("Elastic IP Waste", "_check_elastic_ip_waste"),
        ("Lambda Costs", "_check_lambda_costs"),
        ("S3 Request Costs", "_check_s3_request_costs"),
        ("CloudWatch Logs Retention", "_check_cloudwatch_logs_retention"),
        ("Cost Forecast", "_check_cost_forecast"),
        ("ECS/Fargate Costs", "_check_ecs_fargate_costs"),
        ("EKS Costs", "_check_eks_costs"),
        ("Spot Opportunities", "_check_spot_opportunities"),
        ("DynamoDB Costs", "_check_dynamodb_costs"),
        ("ElastiCache Costs", "_check_elasticache_costs"),
        ("Redshift Costs", "_check_redshift_costs"),
        ("SageMaker Costs", "_check_sagemaker_costs")
    ]
    
    results = {
        "total_findings": 0,
        "total_savings": 0.0,
        "by_severity": {
            "CRITICAL": 0,
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0,
            "INFO": 0
        },
        "by_category": {},
        "test_results": []
    }
    
    # Test each feature
    for test_name, method_name in test_categories:
        print(f"\n📋 Testing {test_name}...")
        try:
            method = getattr(scanner, method_name)
            findings = method()
            
            findings_count = len(findings)
            total_savings = 0.0
            
            # Calculate savings from findings
            for finding in findings:
                results["total_findings"] += 1
                results["by_severity"][finding.severity.name] += 1
                
                # Extract savings from evidence
                if finding.evidence and 'cost_impact' in finding.evidence:
                    cost_impact = finding.evidence['cost_impact']
                    if isinstance(cost_impact, str) and '$' in cost_impact:
                        # Extract dollar amount
                        import re
                        amounts = re.findall(r'\$(\d+(?:\.\d+)?)', cost_impact)
                        if amounts:
                            total_savings += float(amounts[0])
            
            results["total_savings"] += total_savings
            
            test_result = {
                "name": test_name,
                "status": "✅ PASS",
                "findings": findings_count,
                "savings": total_savings
            }
            
            if findings_count > 0:
                print(f"  ✅ Found {findings_count} findings with ${total_savings:.2f} potential savings")
                # Show sample finding
                sample = findings[0]
                print(f"  📌 Sample: {sample.title}")
                print(f"     Severity: {sample.severity.name}")
                print(f"     Impact: {sample.impact}")
            else:
                print(f"  ℹ️  No findings (this may be normal)")
                
        except Exception as e:
            test_result = {
                "name": test_name,
                "status": "❌ FAIL",
                "error": str(e)
            }
            print(f"  ❌ Error: {str(e)}")
        
        results["test_results"].append(test_result)
    
    # Run full scan
    print("\n🔍 Running Full Cost Scan...")
    try:
        all_findings = scanner.scan()
        print(f"  ✅ Full scan completed with {len(all_findings)} total findings")
    except Exception as e:
        print(f"  ❌ Full scan failed: {str(e)}")
    
    # Summary
    print("\n📊 Test Summary")
    print("=" * 50)
    print(f"Total Findings: {results['total_findings']}")
    print(f"Total Potential Savings: ${results['total_savings']:.2f}/month")
    print(f"\nFindings by Severity:")
    for severity, count in results['by_severity'].items():
        if count > 0:
            print(f"  {severity}: {count}")
    
    print(f"\nTest Results:")
    passed = sum(1 for r in results["test_results"] if r["status"] == "✅ PASS")
    failed = sum(1 for r in results["test_results"] if r["status"] == "❌ FAIL")
    print(f"  Passed: {passed}/{len(test_categories)}")
    print(f"  Failed: {failed}/{len(test_categories)}")
    
    # Save results
    with open('cost_scanner_test_results.json', 'w') as f:
        json.dump(results, f, indent=2, default=str)
    print(f"\n💾 Detailed results saved to cost_scanner_test_results.json")
    
    # Generate sample dashboard data
    generate_sample_dashboard_data(results, all_findings if 'all_findings' in locals() else [])

def generate_sample_dashboard_data(test_results, findings):
    """Generate sample data for the enhanced dashboard"""
    dashboard_data = {
        "timestamp": datetime.now().isoformat(),
        "summary": {
            "total_findings": test_results["total_findings"],
            "potential_savings": test_results["total_savings"],
            "by_severity": test_results["by_severity"]
        },
        "findings_by_type": {
            "compute": [],
            "storage": [],
            "transfer": [],
            "services": []
        }
    }
    
    # Categorize findings
    for finding in findings[:20]:  # Sample up to 20 findings
        finding_data = {
            "title": finding.title,
            "description": finding.description,
            "severity": finding.severity.name,
            "impact": finding.impact,
            "recommendation": finding.recommendation,
            "resource_id": finding.resource_id,
            "savings": 0.0
        }
        
        # Extract savings
        if finding.evidence and 'cost_impact' in finding.evidence:
            cost_impact = finding.evidence['cost_impact']
            if isinstance(cost_impact, str) and '$' in cost_impact:
                import re
                amounts = re.findall(r'\$(\d+(?:\.\d+)?)', cost_impact)
                if amounts:
                    finding_data["savings"] = float(amounts[0])
        
        # Categorize
        if any(keyword in finding.title.lower() for keyword in ['ec2', 'lambda', 'ecs', 'eks', 'fargate', 'spot']):
            dashboard_data["findings_by_type"]["compute"].append(finding_data)
        elif any(keyword in finding.title.lower() for keyword in ['s3', 'ebs', 'storage', 'logs']):
            dashboard_data["findings_by_type"]["storage"].append(finding_data)
        elif any(keyword in finding.title.lower() for keyword in ['transfer', 'nat', 'elastic ip']):
            dashboard_data["findings_by_type"]["transfer"].append(finding_data)
        else:
            dashboard_data["findings_by_type"]["services"].append(finding_data)
    
    # Save dashboard data
    with open('enhanced_dashboard_data.json', 'w') as f:
        json.dump(dashboard_data, f, indent=2)
    print(f"📊 Dashboard data saved to enhanced_dashboard_data.json")

if __name__ == "__main__":
    test_cost_scanner()