"""AWS Cost and Usage Scanner

This scanner analyzes AWS costs, resource utilization, and provides
optimization recommendations using the AWS Cost Explorer API.
"""

import boto3
from datetime import datetime, timedelta
from decimal import Decimal
from typing import List, Dict, Any, Optional
import logging

from ..models import Finding, Severity, Category
from .base import BaseScanner

logger = logging.getLogger(__name__)


class CostScanner(BaseScanner):
    """Scanner for AWS Cost and Usage analysis"""
    
    def __init__(self, session: boto3.Session):
        super().__init__(session, None)  # Cost Explorer is global
        self.client = session.client('ce', region_name='us-east-1')  # CE must use us-east-1
        self.cloudwatch = session.client('cloudwatch')
        self.ec2 = session.client('ec2')
        self.rds = session.client('rds')
    
    @property
    def service_name(self) -> str:
        """Return the AWS service name"""
        return "Cost Explorer"
        
    def scan(self) -> List[Finding]:
        """Perform cost and usage analysis"""
        findings = []
        
        try:
            # Get cost data
            findings.extend(self._check_cost_trends())
            findings.extend(self._check_untagged_resources())
            findings.extend(self._check_reserved_instance_coverage())
            findings.extend(self._check_savings_plans_coverage())
            
            # Resource utilization checks
            findings.extend(self._check_ec2_utilization())
            findings.extend(self._check_rds_utilization())
            findings.extend(self._check_ebs_utilization())
            
            # Cost anomalies
            findings.extend(self._check_cost_anomalies())
            
        except Exception as e:
            logger.error(f"Error during cost scan: {str(e)}")
            findings.append(Finding(
                severity=Severity.MEDIUM,
                category=Category.CONFIGURATION,
                resource_type="AWS::CostExplorer::Account",
                resource_id=self.account_id,
                region="global",
                title="Cost Scan Error",
                description=f"Unable to complete cost analysis: {str(e)}",
                impact="Unable to determine potential savings and cost optimization opportunities",
                recommendation="Ensure the AWS account has Cost Explorer enabled and the IAM role has necessary permissions."
            ))
            
        return findings
    
    def _check_cost_trends(self) -> List[Finding]:
        """Analyze cost trends and detect anomalies"""
        findings = []
        
        try:
            # Get last 3 months of cost data
            end_date = datetime.now().date()
            start_date = end_date - timedelta(days=90)
            
            response = self.client.get_cost_and_usage(
                TimePeriod={
                    'Start': start_date.strftime('%Y-%m-%d'),
                    'End': end_date.strftime('%Y-%m-%d')
                },
                Granularity='MONTHLY',
                Metrics=['UNBLENDED_COST'],
                GroupBy=[{'Type': 'DIMENSION', 'Key': 'SERVICE'}]
            )
            
            # Analyze month-over-month growth
            monthly_costs = {}
            for result in response['ResultsByTime']:
                month = result['TimePeriod']['Start']
                total_cost = Decimal('0')
                service_costs = {}
                
                for group in result['Groups']:
                    service = group['Keys'][0]
                    cost = Decimal(group['Metrics']['UnblendedCost']['Amount'])
                    service_costs[service] = cost
                    total_cost += cost
                
                monthly_costs[month] = {
                    'total': total_cost,
                    'services': service_costs
                }
            
            # Check for significant cost increases
            months = sorted(monthly_costs.keys())
            if len(months) >= 2:
                latest_month = months[-1]
                previous_month = months[-2]
                
                latest_cost = monthly_costs[latest_month]['total']
                previous_cost = monthly_costs[previous_month]['total']
                
                if previous_cost > 0:
                    growth_rate = ((latest_cost - previous_cost) / previous_cost) * 100
                    
                    if growth_rate > 20:
                        findings.append(Finding(
                            severity=Severity.HIGH,
                            category=Category.COST_OPTIMIZATION,
                            resource_type="AWS::Account::Billing",
                            resource_id=self.account_id,
                            region="global",
                            title="High Month-over-Month Cost Growth",
                            description=f"AWS costs increased by {growth_rate:.1f}% from ${previous_cost:.2f} to ${latest_cost:.2f}",
                            impact=f"${latest_cost - previous_cost:.2f} additional monthly spend without corresponding value",
                            recommendation="Review service usage and implement cost optimization strategies. Set up AWS Budgets with alerts.",
                            evidence={
                                'affected_resources': [f"Total AWS Account Spend"],
                                'previous_cost': f"${previous_cost:.2f}",
                                'latest_cost': f"${latest_cost:.2f}",
                                'cost_impact': f"${latest_cost - previous_cost:.2f} additional monthly spend",
                                'growth_rate': f"{growth_rate:.1f}%"
                            }
                        ))
                    
                # Check for specific service cost spikes
                latest_services = monthly_costs[latest_month]['services']
                previous_services = monthly_costs[previous_month]['services']
                
                for service, latest_cost in latest_services.items():
                    if service in previous_services and previous_services[service] > 0:
                        service_growth = ((latest_cost - previous_services[service]) / previous_services[service]) * 100
                        if service_growth > 50:
                            findings.append(Finding(
                                severity=Severity.MEDIUM,
                                category=Category.COST_OPTIMIZATION,
                                resource_type=f"AWS::{service}::Service",
                                resource_id=service,
                                region="global",
                                title=f"High Cost Growth in {service}",
                                description=f"{service} costs increased by {service_growth:.1f}% month-over-month",
                                impact=f"${latest_cost - previous_services[service]:.2f} additional monthly spend in {service}",
                                recommendation=f"Review {service} usage patterns and optimize resource allocation",
                                evidence={
                                    'affected_resources': [service],
                                    'service': service,
                                    'previous_cost': f"${previous_services[service]:.2f}",
                                    'latest_cost': f"${latest_cost:.2f}",
                                    'cost_impact': f"${latest_cost - previous_services[service]:.2f} additional monthly spend",
                                    'growth_rate': f"{service_growth:.1f}%"
                                }
                            ))
                            
        except Exception as e:
            logger.error(f"Error checking cost trends: {str(e)}")
            
        return findings
    
    def _check_untagged_resources(self) -> List[Finding]:
        """Check for resources without cost allocation tags"""
        findings = []
        
        try:
            # Check EC2 instances
            ec2_response = self.ec2.describe_instances()
            untagged_instances = []
            
            for reservation in ec2_response['Reservations']:
                for instance in reservation['Instances']:
                    if instance['State']['Name'] == 'running':
                        tags = {tag['Key']: tag['Value'] for tag in instance.get('Tags', [])}
                        # Check for common cost allocation tags
                        if not any(key in tags for key in ['Environment', 'Project', 'CostCenter', 'Owner']):
                            untagged_instances.append(instance['InstanceId'])
            
            if untagged_instances:
                findings.append(Finding(
                    severity=Severity.MEDIUM,
                    category=Category.COST_OPTIMIZATION,
                    resource_type="AWS::EC2::Instance",
                    resource_id="multiple",
                    region="multiple",
                    title="EC2 Instances Without Cost Allocation Tags",
                    description=f"Found {len(untagged_instances)} EC2 instances without proper cost allocation tags",
                    impact="Unable to accurately track and allocate costs by project, environment, or cost center",
                    recommendation="Implement a tagging strategy with tags like Environment, Project, CostCenter. Use AWS Organizations tag policies.",
                    evidence={
                        'affected_resources': untagged_instances[:10],
                        'untagged_count': len(untagged_instances),
                        'cost_impact': 'Unable to accurately track and allocate costs',
                        'sample_instances': untagged_instances[:5]
                    }
                ))
                
        except Exception as e:
            logger.error(f"Error checking untagged resources: {str(e)}")
            
        return findings
    
    def _check_reserved_instance_coverage(self) -> List[Finding]:
        """Check Reserved Instance coverage and utilization"""
        findings = []
        
        try:
            # Get RI coverage for the last 30 days
            end_date = datetime.now().date()
            start_date = end_date - timedelta(days=30)
            
            response = self.client.get_reservation_coverage(
                TimePeriod={
                    'Start': start_date.strftime('%Y-%m-%d'),
                    'End': end_date.strftime('%Y-%m-%d')
                },
                Granularity='MONTHLY'
            )
            
            for coverage_data in response['CoveragesByTime']:
                coverage_percentage = float(coverage_data['Total']['CoverageHours']['CoverageHoursPercentage'])
                on_demand_cost = float(coverage_data['Total']['CoverageHours']['OnDemandHours']) * 0.10  # Rough estimate
                
                if coverage_percentage < 70:
                    findings.append(Finding(
                        severity=Severity.MEDIUM,
                        category=Category.COST_OPTIMIZATION,
                        resource_type="AWS::EC2::ReservedInstances",
                        resource_id="coverage-analysis",
                        region="global",
                        title="Low Reserved Instance Coverage",
                        description=f"Only {coverage_percentage:.1f}% of eligible instance hours are covered by Reserved Instances",
                        impact="Paying on-demand prices for steady-state workloads",
                        recommendation="Purchase additional Reserved Instances for steady-state workloads. Use AWS Cost Explorer RI recommendations.",
                        evidence={
                            'coverage_percentage': f"{coverage_percentage:.1f}%",
                            'on_demand_hours_cost': f"${on_demand_cost:.2f}",
                            'cost_impact': f"Potential savings of up to ${on_demand_cost * 0.3:.2f} per month"
                        }
                    ))
            
            # Check RI utilization
            utilization_response = self.client.get_reservation_utilization(
                TimePeriod={
                    'Start': start_date.strftime('%Y-%m-%d'),
                    'End': end_date.strftime('%Y-%m-%d')
                }
            )
            
            total_utilization = float(utilization_response['Total']['UtilizationPercentage'])
            if total_utilization < 80:
                findings.append(Finding(
                    severity=Severity.HIGH,
                    category=Category.COST_OPTIMIZATION,
                    resource_type="AWS::EC2::ReservedInstances",
                    resource_id="utilization-analysis",
                    region="global",
                    title="Low Reserved Instance Utilization",
                    description=f"Reserved Instances are only {total_utilization:.1f}% utilized",
                    impact="Wasting money on unused Reserved Instance capacity",
                    recommendation="Review and modify or sell unused Reserved Instances. Use RI Marketplace for Standard RIs.",
                    evidence={
                        'utilization_percentage': f"{total_utilization:.1f}%",
                        'cost_impact': 'Paying for unused Reserved Instance capacity'
                    }
                ))
                
        except Exception as e:
            logger.error(f"Error checking RI coverage: {str(e)}")
            
        return findings
    
    def _check_savings_plans_coverage(self) -> List[Finding]:
        """Check Savings Plans coverage"""
        findings = []
        
        try:
            end_date = datetime.now().date()
            start_date = end_date - timedelta(days=30)
            
            response = self.client.get_savings_plans_coverage(
                TimePeriod={
                    'Start': start_date.strftime('%Y-%m-%d'),
                    'End': end_date.strftime('%Y-%m-%d')
                },
                Granularity='MONTHLY'
            )
            
            for coverage_data in response['SavingsPlansCoverages']:
                coverage_percentage = float(coverage_data['Coverage']['CoveragePercentage'] or 0)
                on_demand_cost = float(coverage_data['Coverage']['OnDemandCost'] or 0)
                
                if coverage_percentage < 60 and on_demand_cost > 1000:
                    findings.append(Finding(
                        severity=Severity.MEDIUM,
                        category=Category.COST_OPTIMIZATION,
                        resource_type="AWS::SavingsPlans::Coverage",
                        resource_id="coverage-analysis",
                        region="global",
                        title="Low Savings Plans Coverage",
                        description=f"Only {coverage_percentage:.1f}% of eligible compute usage is covered by Savings Plans",
                        impact="Missing out on compute savings across EC2, Lambda, and Fargate",
                        recommendation="Purchase Savings Plans for consistent compute workloads. Consider Compute Savings Plans for flexibility.",
                        evidence={
                            'coverage_percentage': f"{coverage_percentage:.1f}%",
                            'on_demand_cost': f"${on_demand_cost:.2f}",
                            'cost_impact': f"Potential savings of up to ${on_demand_cost * 0.2:.2f} per month"
                        }
                    ))
                    
        except Exception as e:
            logger.error(f"Error checking Savings Plans coverage: {str(e)}")
            
        return findings
    
    def _check_ec2_utilization(self) -> List[Finding]:
        """Check EC2 instance utilization"""
        findings = []
        
        try:
            # Get all running instances
            ec2_response = self.ec2.describe_instances(
                Filters=[{'Name': 'instance-state-name', 'Values': ['running']}]
            )
            region = self.ec2.meta.region_name
            
            end_time = datetime.now()
            start_time = end_time - timedelta(days=7)
            
            for reservation in ec2_response['Reservations']:
                for instance in reservation['Instances']:
                    instance_id = instance['InstanceId']
                    instance_type = instance['InstanceType']
                    
                    # Get CPU utilization metrics
                    cpu_response = self.cloudwatch.get_metric_statistics(
                        Namespace='AWS/EC2',
                        MetricName='CPUUtilization',
                        Dimensions=[{'Name': 'InstanceId', 'Value': instance_id}],
                        StartTime=start_time,
                        EndTime=end_time,
                        Period=3600,
                        Statistics=['Average']
                    )
                    
                    if cpu_response['Datapoints']:
                        avg_cpu = sum(dp['Average'] for dp in cpu_response['Datapoints']) / len(cpu_response['Datapoints'])
                        
                        if avg_cpu < 10:
                            findings.append(Finding(
                                severity=Severity.HIGH,
                                category=Category.COST_OPTIMIZATION,
                                resource_type="AWS::EC2::Instance",
                                resource_id=instance_id,
                                region=region,
                                title=f"Underutilized EC2 Instance",
                                description=f"Instance {instance_id} ({instance_type}) has average CPU utilization of {avg_cpu:.1f}%",
                                impact="Paying for unused compute capacity",
                                recommendation="Consider downsizing or terminating underutilized instances. Use AWS Compute Optimizer for right-sizing.",
                                evidence={
                                    'affected_resources': [instance_id],
                                    'instance_type': instance_type,
                                    'avg_cpu_utilization': f"{avg_cpu:.1f}%",
                                    'cost_impact': f"Potential savings by right-sizing {instance_type}"
                                }
                            ))
                        elif avg_cpu > 90:
                            findings.append(Finding(
                                severity=Severity.MEDIUM,
                                category=Category.OPERATIONAL,
                                resource_type="AWS::EC2::Instance",
                                resource_id=instance_id,
                                region=region,
                                title=f"Overutilized EC2 Instance",
                                description=f"Instance {instance_id} ({instance_type}) has average CPU utilization of {avg_cpu:.1f}%",
                                impact="Performance degradation and potential service disruption",
                                recommendation="Consider upsizing instance for better performance and reliability",
                                evidence={
                                    'affected_resources': [instance_id]
                                }
                            ))
                            
        except Exception as e:
            logger.error(f"Error checking EC2 utilization: {str(e)}")
            
        return findings
    
    def _check_rds_utilization(self) -> List[Finding]:
        """Check RDS instance utilization"""
        findings = []
        
        try:
            rds_response = self.rds.describe_db_instances()
            region = self.rds.meta.region_name
            
            end_time = datetime.now()
            start_time = end_time - timedelta(days=7)
            
            for db_instance in rds_response['DBInstances']:
                if db_instance['DBInstanceStatus'] == 'available':
                    db_id = db_instance['DBInstanceIdentifier']
                    instance_class = db_instance['DBInstanceClass']
                    
                    # Check CPU utilization
                    cpu_response = self.cloudwatch.get_metric_statistics(
                        Namespace='AWS/RDS',
                        MetricName='CPUUtilization',
                        Dimensions=[{'Name': 'DBInstanceIdentifier', 'Value': db_id}],
                        StartTime=start_time,
                        EndTime=end_time,
                        Period=3600,
                        Statistics=['Average']
                    )
                    
                    # Check database connections
                    conn_response = self.cloudwatch.get_metric_statistics(
                        Namespace='AWS/RDS',
                        MetricName='DatabaseConnections',
                        Dimensions=[{'Name': 'DBInstanceIdentifier', 'Value': db_id}],
                        StartTime=start_time,
                        EndTime=end_time,
                        Period=3600,
                        Statistics=['Average']
                    )
                    
                    if cpu_response['Datapoints']:
                        avg_cpu = sum(dp['Average'] for dp in cpu_response['Datapoints']) / len(cpu_response['Datapoints'])
                        
                        if avg_cpu < 20:
                            avg_connections = 0
                            if conn_response['Datapoints']:
                                avg_connections = sum(dp['Average'] for dp in conn_response['Datapoints']) / len(conn_response['Datapoints'])
                            
                            if avg_connections < 5:
                                findings.append(Finding(
                                    severity=Severity.HIGH,
                                    category=Category.COST_OPTIMIZATION,
                                    resource_type="AWS::RDS::DBInstance",
                                    resource_id=db_id,
                                    region=region,
                                    title=f"Underutilized RDS Instance",
                                    description=f"RDS instance {db_id} ({instance_class}) has low CPU ({avg_cpu:.1f}%) and connection count ({avg_connections:.1f})",
                                    impact="Paying for unused database capacity",
                                    recommendation="Consider downsizing or using Aurora Serverless for variable workloads",
                                    evidence={
                                        'affected_resources': [db_id],
                                        'instance_class': instance_class,
                                        'avg_cpu': f"{avg_cpu:.1f}%",
                                        'avg_connections': f"{avg_connections:.1f}",
                                        'cost_impact': f"Potential savings by right-sizing {instance_class}"
                                    }
                                ))
                    
                    # Check for Multi-AZ on non-production
                    if db_instance.get('MultiAZ', False):
                        tags = {tag['Key']: tag['Value'] for tag in db_instance.get('TagList', [])}
                        if tags.get('Environment', '').lower() in ['dev', 'development', 'test', 'staging']:
                            findings.append(Finding(
                                severity=Severity.MEDIUM,
                                category=Category.COST_OPTIMIZATION,
                                resource_type="AWS::RDS::DBInstance",
                                resource_id=db_id,
                                region=region,
                                title="Multi-AZ Enabled on Non-Production RDS",
                                description=f"RDS instance {db_id} has Multi-AZ enabled in {tags.get('Environment', 'unknown')} environment",
                                impact="Paying double for high availability in non-production environment",
                                recommendation="Disable Multi-AZ for non-production databases to save ~50% on instance costs",
                                evidence={
                                    'affected_resources': [db_id],
                                    'environment': tags.get('Environment', 'unknown'),
                                    'multi_az': True,
                                    'cost_impact': '~50% reduction in RDS instance costs'
                                }
                            ))
                            
        except Exception as e:
            logger.error(f"Error checking RDS utilization: {str(e)}")
            
        return findings
    
    def _check_ebs_utilization(self) -> List[Finding]:
        """Check EBS volume utilization"""
        findings = []
        
        try:
            # Get all EBS volumes
            volumes_response = self.ec2.describe_volumes()
            region = self.ec2.meta.region_name
            
            unattached_volumes = []
            low_iops_volumes = []
            
            end_time = datetime.now()
            start_time = end_time - timedelta(days=7)
            
            for volume in volumes_response['Volumes']:
                volume_id = volume['VolumeId']
                volume_type = volume['VolumeType']
                volume_size = volume['Size']
                
                # Check for unattached volumes
                if volume['State'] == 'available':
                    unattached_volumes.append({
                        'id': volume_id,
                        'size': volume_size,
                        'type': volume_type
                    })
                elif volume['State'] == 'in-use' and volume_type in ['io1', 'io2']:
                    # Check IOPS utilization for provisioned IOPS volumes
                    iops_response = self.cloudwatch.get_metric_statistics(
                        Namespace='AWS/EBS',
                        MetricName='VolumeReadOps',
                        Dimensions=[{'Name': 'VolumeId', 'Value': volume_id}],
                        StartTime=start_time,
                        EndTime=end_time,
                        Period=3600,
                        Statistics=['Sum']
                    )
                    
                    if iops_response['Datapoints']:
                        # Calculate average IOPS
                        total_ops = sum(dp['Sum'] for dp in iops_response['Datapoints'])
                        avg_iops = total_ops / (len(iops_response['Datapoints']) * 3600)
                        provisioned_iops = volume.get('Iops', 0)
                        
                        if provisioned_iops > 0 and avg_iops < provisioned_iops * 0.1:
                            low_iops_volumes.append({
                                'id': volume_id,
                                'provisioned': provisioned_iops,
                                'actual': avg_iops
                            })
            
            if unattached_volumes:
                total_size = sum(v['size'] for v in unattached_volumes)
                findings.append(Finding(
                    severity=Severity.HIGH,
                    category=Category.COST_OPTIMIZATION,
                    resource_type="AWS::EC2::Volume",
                    resource_id="multiple",
                    region=region,
                    title="Unattached EBS Volumes",
                    description=f"Found {len(unattached_volumes)} unattached EBS volumes totaling {total_size} GB",
                    impact=f"Wasting ~${total_size * 0.10:.2f} per month on unused storage",
                    recommendation="Delete or snapshot unattached volumes. Implement lifecycle policies for automatic cleanup.",
                    evidence={
                        'affected_resources': [v['id'] for v in unattached_volumes[:10]],
                        'volume_count': len(unattached_volumes),
                        'total_size_gb': total_size,
                        'cost_impact': f"~${total_size * 0.10:.2f} per month for GP2 storage"
                    }
                ))
            
            if low_iops_volumes:
                findings.append(Finding(
                    severity=Severity.MEDIUM,
                    category=Category.COST_OPTIMIZATION,
                    resource_type="AWS::EC2::Volume",
                    resource_id="multiple",
                    region=region,
                    title="Overprovisioned IOPS Volumes",
                    description=f"Found {len(low_iops_volumes)} volumes with less than 10% IOPS utilization",
                    impact="Paying for unused IOPS capacity",
                    recommendation="Convert to GP3 or reduce provisioned IOPS to match actual usage",
                    evidence={
                        'affected_resources': [v['id'] for v in low_iops_volumes[:10]],
                        'volume_count': len(low_iops_volumes),
                        'cost_impact': 'Significant savings on IOPS charges',
                        'sample_volumes': low_iops_volumes[:3]
                    }
                ))
                
        except Exception as e:
            logger.error(f"Error checking EBS utilization: {str(e)}")
            
        return findings
    
    def _check_cost_anomalies(self) -> List[Finding]:
        """Check for cost anomalies using AWS Cost Anomaly Detection"""
        findings = []
        
        try:
            # Get cost anomalies from the last 30 days
            end_date = datetime.now().date()
            start_date = end_date - timedelta(days=30)
            
            response = self.client.get_anomalies(
                DateInterval={
                    'StartDate': start_date.strftime('%Y-%m-%d'),
                    'EndDate': end_date.strftime('%Y-%m-%d')
                }
            )
            
            for anomaly in response.get('Anomalies', []):
                impact = anomaly['Impact']
                total_impact = float(impact['TotalImpact'])
                
                if total_impact > 100:  # Only report anomalies over $100
                    findings.append(Finding(
                        severity=Severity.HIGH if total_impact > 1000 else Severity.MEDIUM,
                        category=Category.COST_OPTIMIZATION,
                        resource_type="AWS::CostExplorer::Anomaly",
                        resource_id=anomaly['AnomalyId'],
                        region="global",
                        title="Cost Anomaly Detected",
                        description=f"{anomaly['DimensionValue']} showed unusual spending of ${total_impact:.2f}",
                        impact=f"Unexpected cost spike of ${total_impact:.2f} detected",
                        recommendation="Investigate the root cause immediately. Check CloudTrail logs for unusual activity.",
                        evidence={
                            'affected_resources': [anomaly['DimensionValue']],
                            'anomaly_id': anomaly['AnomalyId'],
                            'dimension': anomaly['DimensionValue'],
                            'cost_impact': f"${total_impact:.2f} unexpected spend"
                        }
                    ))
                    
        except self.client.exceptions.DataUnavailableException:
            # Cost Anomaly Detection might not be set up
            findings.append(Finding(
                severity=Severity.LOW,
                category=Category.CONFIGURATION,
                resource_type="AWS::CostExplorer::AnomalyDetector",
                resource_id="not-configured",
                region="global",
                title="Cost Anomaly Detection Not Configured",
                description="AWS Cost Anomaly Detection is not enabled for this account",
                impact="Missing automated alerts for unexpected cost increases",
                recommendation="Enable Cost Anomaly Detection for automated cost monitoring and alerts"
            ))
        except Exception as e:
            logger.error(f"Error checking cost anomalies: {str(e)}")
            
        return findings