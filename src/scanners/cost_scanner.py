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
        self.elbv2 = session.client('elbv2')
        self.lambda_client = session.client('lambda')
        self.s3 = session.client('s3')
        self.logs = session.client('logs')
        self.dynamodb = session.client('dynamodb')
        self.elasticache = session.client('elasticache')
        self.redshift = session.client('redshift')
        self.sagemaker = session.client('sagemaker')
        self.ecs = session.client('ecs')
        self.eks = session.client('eks')
    
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
            
            # Additional cost optimization checks
            findings.extend(self._check_nat_gateway_costs())
            findings.extend(self._check_data_transfer_costs())
            findings.extend(self._check_elastic_ip_waste())
            findings.extend(self._check_lambda_costs())
            findings.extend(self._check_s3_request_costs())
            findings.extend(self._check_cloudwatch_logs_retention())
            
            # Cost forecasting
            findings.extend(self._check_cost_forecast())
            
            # Container costs
            findings.extend(self._check_ecs_fargate_costs())
            findings.extend(self._check_eks_costs())
            
            # Spot instance opportunities
            findings.extend(self._check_spot_opportunities())
            
            # Service-specific optimizations
            findings.extend(self._check_dynamodb_costs())
            findings.extend(self._check_elasticache_costs())
            findings.extend(self._check_redshift_costs())
            findings.extend(self._check_sagemaker_costs())
            
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
    
    def _check_nat_gateway_costs(self) -> List[Finding]:
        """Check NAT Gateway costs and usage patterns"""
        findings = []
        
        try:
            # Get NAT Gateways
            nat_gateways = self.ec2.describe_nat_gateways(
                Filter=[{'Name': 'state', 'Values': ['available']}]
            )
            region = self.ec2.meta.region_name
            
            # Get cost data for NAT Gateways
            end_date = datetime.now().date()
            start_date = end_date - timedelta(days=30)
            
            response = self.client.get_cost_and_usage(
                TimePeriod={
                    'Start': start_date.strftime('%Y-%m-%d'),
                    'End': end_date.strftime('%Y-%m-%d')
                },
                Granularity='MONTHLY',
                Metrics=['UNBLENDED_COST'],
                Filter={
                    'And': [
                        {'Dimensions': {'Key': 'SERVICE', 'Values': ['Amazon Elastic Compute Cloud - AWS Outposts']}},
                        {'Dimensions': {'Key': 'USAGE_TYPE_GROUP', 'Values': ['EC2: NAT Gateway']}}
                    ]
                }
            )
            
            if response['ResultsByTime']:
                latest_result = response['ResultsByTime'][-1]
                nat_cost = float(latest_result['Total']['UnblendedCost']['Amount'])
                
                if nat_cost > 100:  # If NAT Gateway costs exceed $100/month
                    # Check for alternatives
                    findings.append(Finding(
                        severity=Severity.MEDIUM,
                        category=Category.COST_OPTIMIZATION,
                        resource_type="AWS::EC2::NATGateway",
                        resource_id="multiple",
                        region=region,
                        title="High NAT Gateway Costs",
                        description=f"NAT Gateway costs are ${nat_cost:.2f} per month across {len(nat_gateways['NatGateways'])} gateways",
                        impact=f"${nat_cost:.2f} monthly spend on NAT Gateways",
                        recommendation="Consider using NAT instances for lower traffic, VPC endpoints for AWS services, or private subnets where possible",
                        evidence={
                            'nat_gateway_count': len(nat_gateways['NatGateways']),
                            'monthly_cost': f"${nat_cost:.2f}",
                            'cost_impact': f"Potential savings of up to ${nat_cost * 0.5:.2f} with optimization"
                        }
                    ))
                    
        except Exception as e:
            logger.error(f"Error checking NAT Gateway costs: {str(e)}")
            
        return findings
    
    def _check_data_transfer_costs(self) -> List[Finding]:
        """Check data transfer costs across regions and AZs"""
        findings = []
        
        try:
            end_date = datetime.now().date()
            start_date = end_date - timedelta(days=30)
            
            # Get data transfer costs
            response = self.client.get_cost_and_usage(
                TimePeriod={
                    'Start': start_date.strftime('%Y-%m-%d'),
                    'End': end_date.strftime('%Y-%m-%d')
                },
                Granularity='MONTHLY',
                Metrics=['UNBLENDED_COST'],
                GroupBy=[{'Type': 'DIMENSION', 'Key': 'USAGE_TYPE'}],
                Filter={'Dimensions': {'Key': 'SERVICE', 'Values': ['Amazon Elastic Compute Cloud - AWS Outposts']}}
            )
            
            transfer_costs = {}
            for result in response['ResultsByTime']:
                for group in result['Groups']:
                    usage_type = group['Keys'][0]
                    if 'DataTransfer' in usage_type or 'data-transfer' in usage_type.lower():
                        cost = float(group['Metrics']['UnblendedCost']['Amount'])
                        if cost > 0:
                            transfer_costs[usage_type] = cost
            
            # Check for high cross-AZ transfer
            cross_az_cost = sum(cost for usage, cost in transfer_costs.items() if 'Regional' in usage)
            if cross_az_cost > 50:
                findings.append(Finding(
                    severity=Severity.MEDIUM,
                    category=Category.COST_OPTIMIZATION,
                    resource_type="AWS::EC2::DataTransfer",
                    resource_id="cross-az",
                    region="multiple",
                    title="High Cross-AZ Data Transfer Costs",
                    description=f"Cross-AZ data transfer costs are ${cross_az_cost:.2f} per month",
                    impact=f"${cross_az_cost:.2f} monthly spend on cross-AZ transfers",
                    recommendation="Consolidate resources in same AZ, use VPC endpoints, implement caching strategies",
                    evidence={
                        'cross_az_cost': f"${cross_az_cost:.2f}",
                        'cost_impact': f"Potential savings by optimizing architecture"
                    }
                ))
            
            # Check for high inter-region transfer
            inter_region_cost = sum(cost for usage, cost in transfer_costs.items() if 'InterRegion' in usage)
            if inter_region_cost > 100:
                findings.append(Finding(
                    severity=Severity.HIGH,
                    category=Category.COST_OPTIMIZATION,
                    resource_type="AWS::EC2::DataTransfer",
                    resource_id="inter-region",
                    region="multiple",
                    title="High Inter-Region Data Transfer Costs",
                    description=f"Inter-region data transfer costs are ${inter_region_cost:.2f} per month",
                    impact=f"${inter_region_cost:.2f} monthly spend on inter-region transfers",
                    recommendation="Use CloudFront for content distribution, implement regional caching, consolidate workloads",
                    evidence={
                        'inter_region_cost': f"${inter_region_cost:.2f}",
                        'cost_impact': f"Significant savings possible with architectural changes"
                    }
                ))
                
        except Exception as e:
            logger.error(f"Error checking data transfer costs: {str(e)}")
            
        return findings
    
    def _check_elastic_ip_waste(self) -> List[Finding]:
        """Check for unattached Elastic IPs"""
        findings = []
        
        try:
            # Get all Elastic IPs
            eips = self.ec2.describe_addresses()
            region = self.ec2.meta.region_name
            
            unattached_eips = []
            for eip in eips['Addresses']:
                if 'AssociationId' not in eip:
                    unattached_eips.append(eip.get('PublicIp', eip.get('AllocationId')))
            
            if unattached_eips:
                # $0.005 per hour per unattached EIP
                monthly_cost = len(unattached_eips) * 0.005 * 24 * 30
                findings.append(Finding(
                    severity=Severity.MEDIUM,
                    category=Category.COST_OPTIMIZATION,
                    resource_type="AWS::EC2::EIP",
                    resource_id="multiple",
                    region=region,
                    title="Unattached Elastic IPs",
                    description=f"Found {len(unattached_eips)} unattached Elastic IPs costing ${monthly_cost:.2f}/month",
                    impact=f"${monthly_cost:.2f} monthly waste on unused Elastic IPs",
                    recommendation="Release unattached Elastic IPs or attach them to instances",
                    evidence={
                        'affected_resources': unattached_eips[:10],
                        'eip_count': len(unattached_eips),
                        'cost_impact': f"${monthly_cost:.2f} per month"
                    }
                ))
                
        except Exception as e:
            logger.error(f"Error checking Elastic IPs: {str(e)}")
            
        return findings
    
    def _check_lambda_costs(self) -> List[Finding]:
        """Check Lambda function costs and optimization opportunities"""
        findings = []
        
        try:
            # Get all Lambda functions
            functions = []
            paginator = self.lambda_client.get_paginator('list_functions')
            for page in paginator.paginate():
                functions.extend(page['Functions'])
            
            region = self.lambda_client.meta.region_name
            overprovisioned_functions = []
            
            end_time = datetime.now()
            start_time = end_time - timedelta(days=7)
            
            for function in functions:
                function_name = function['FunctionName']
                memory_size = function['MemorySize']
                
                # Get memory utilization metrics
                try:
                    metrics = self.cloudwatch.get_metric_statistics(
                        Namespace='AWS/Lambda',
                        MetricName='Duration',
                        Dimensions=[{'Name': 'FunctionName', 'Value': function_name}],
                        StartTime=start_time,
                        EndTime=end_time,
                        Period=3600,
                        Statistics=['Average', 'Maximum']
                    )
                    
                    if metrics['Datapoints']:
                        # Check if function is overprovisioned
                        # Lambda bills in 1ms increments, memory affects CPU allocation
                        avg_duration = sum(dp['Average'] for dp in metrics['Datapoints']) / len(metrics['Datapoints'])
                        max_duration = max(dp['Maximum'] for dp in metrics['Datapoints'])
                        
                        # If max duration is < 1/3 of timeout and memory > 512MB, likely overprovisioned
                        timeout = function.get('Timeout', 3) * 1000  # Convert to ms
                        if max_duration < timeout / 3 and memory_size > 512:
                            overprovisioned_functions.append({
                                'name': function_name,
                                'memory': memory_size,
                                'avg_duration': avg_duration,
                                'max_duration': max_duration
                            })
                            
                except Exception as e:
                    logger.debug(f"Error getting metrics for Lambda {function_name}: {str(e)}")
            
            if overprovisioned_functions:
                findings.append(Finding(
                    severity=Severity.MEDIUM,
                    category=Category.COST_OPTIMIZATION,
                    resource_type="AWS::Lambda::Function",
                    resource_id="multiple",
                    region=region,
                    title="Overprovisioned Lambda Functions",
                    description=f"Found {len(overprovisioned_functions)} Lambda functions with excessive memory allocation",
                    impact="Paying for unused Lambda memory and compute capacity",
                    recommendation="Use AWS Lambda Power Tuning to find optimal memory settings. Consider reducing memory for fast-executing functions.",
                    evidence={
                        'affected_resources': [f['name'] for f in overprovisioned_functions[:10]],
                        'function_count': len(overprovisioned_functions),
                        'sample_functions': overprovisioned_functions[:3],
                        'cost_impact': 'Potential 20-50% reduction in Lambda costs'
                    }
                ))
                
        except Exception as e:
            logger.error(f"Error checking Lambda costs: {str(e)}")
            
        return findings
    
    def _check_s3_request_costs(self) -> List[Finding]:
        """Check S3 request patterns and costs"""
        findings = []
        
        try:
            # Get S3 request costs
            end_date = datetime.now().date()
            start_date = end_date - timedelta(days=30)
            
            response = self.client.get_cost_and_usage(
                TimePeriod={
                    'Start': start_date.strftime('%Y-%m-%d'),
                    'End': end_date.strftime('%Y-%m-%d')
                },
                Granularity='MONTHLY',
                Metrics=['UNBLENDED_COST', 'USAGE_QUANTITY'],
                GroupBy=[{'Type': 'DIMENSION', 'Key': 'USAGE_TYPE'}],
                Filter={'Dimensions': {'Key': 'SERVICE', 'Values': ['Amazon Simple Storage Service']}}
            )
            
            request_costs = {}
            high_request_buckets = []
            
            for result in response['ResultsByTime']:
                for group in result['Groups']:
                    usage_type = group['Keys'][0]
                    if 'Requests' in usage_type:
                        cost = float(group['Metrics']['UnblendedCost']['Amount'])
                        quantity = float(group['Metrics']['UsageQuantity']['Amount'])
                        if cost > 10:  # More than $10 in request costs
                            request_costs[usage_type] = {
                                'cost': cost,
                                'quantity': quantity
                            }
            
            total_request_cost = sum(data['cost'] for data in request_costs.values())
            
            if total_request_cost > 50:
                findings.append(Finding(
                    severity=Severity.MEDIUM,
                    category=Category.COST_OPTIMIZATION,
                    resource_type="AWS::S3::Bucket",
                    resource_id="high-request-patterns",
                    region="multiple",
                    title="High S3 Request Costs",
                    description=f"S3 request costs are ${total_request_cost:.2f} per month",
                    impact=f"${total_request_cost:.2f} monthly spend on S3 API requests",
                    recommendation="Implement CloudFront caching, batch operations, use S3 Transfer Acceleration wisely, consider request patterns",
                    evidence={
                        'total_request_cost': f"${total_request_cost:.2f}",
                        'request_types': list(request_costs.keys())[:5],
                        'cost_impact': 'Potential 50-80% reduction with caching'
                    }
                ))
                
        except Exception as e:
            logger.error(f"Error checking S3 request costs: {str(e)}")
            
        return findings
    
    def _check_cloudwatch_logs_retention(self) -> List[Finding]:
        """Check CloudWatch Logs retention policies"""
        findings = []
        
        try:
            # Get all log groups
            log_groups = []
            paginator = self.logs.get_paginator('describe_log_groups')
            for page in paginator.paginate():
                log_groups.extend(page['logGroups'])
            
            region = self.logs.meta.region_name
            
            # Check retention policies
            no_retention = []
            excessive_retention = []
            total_stored_bytes = 0
            
            for log_group in log_groups:
                stored_bytes = log_group.get('storedBytes', 0)
                total_stored_bytes += stored_bytes
                retention_days = log_group.get('retentionInDays')
                
                if not retention_days:
                    no_retention.append({
                        'name': log_group['logGroupName'],
                        'size_gb': stored_bytes / (1024**3)
                    })
                elif retention_days > 90:
                    # Check if it's a compliance/audit log
                    name = log_group['logGroupName'].lower()
                    if not any(keyword in name for keyword in ['audit', 'compliance', 'security', 'cloudtrail']):
                        excessive_retention.append({
                            'name': log_group['logGroupName'],
                            'retention_days': retention_days,
                            'size_gb': stored_bytes / (1024**3)
                        })
            
            # Estimate monthly cost ($0.50 per GB)
            total_size_gb = total_stored_bytes / (1024**3)
            monthly_cost = total_size_gb * 0.50
            
            if no_retention:
                findings.append(Finding(
                    severity=Severity.HIGH,
                    category=Category.COST_OPTIMIZATION,
                    resource_type="AWS::Logs::LogGroup",
                    resource_id="no-retention",
                    region=region,
                    title="CloudWatch Log Groups Without Retention Policy",
                    description=f"Found {len(no_retention)} log groups without retention policies, storing {sum(lg['size_gb'] for lg in no_retention):.2f} GB",
                    impact="Logs stored indefinitely, increasing storage costs over time",
                    recommendation="Set appropriate retention policies based on compliance requirements. 30-90 days for most logs.",
                    evidence={
                        'affected_resources': [lg['name'] for lg in no_retention[:10]],
                        'log_group_count': len(no_retention),
                        'total_size_gb': f"{sum(lg['size_gb'] for lg in no_retention):.2f}",
                        'cost_impact': f"${sum(lg['size_gb'] for lg in no_retention) * 0.50:.2f} per month"
                    }
                ))
            
            if excessive_retention:
                findings.append(Finding(
                    severity=Severity.MEDIUM,
                    category=Category.COST_OPTIMIZATION,
                    resource_type="AWS::Logs::LogGroup",
                    resource_id="excessive-retention",
                    region=region,
                    title="Excessive CloudWatch Logs Retention",
                    description=f"Found {len(excessive_retention)} non-compliance log groups with retention > 90 days",
                    impact="Storing logs longer than necessary, increasing costs",
                    recommendation="Review retention policies. Use 30-90 days for operational logs, archive to S3 for long-term storage.",
                    evidence={
                        'affected_resources': [lg['name'] for lg in excessive_retention[:10]],
                        'log_group_count': len(excessive_retention),
                        'sample_groups': excessive_retention[:3],
                        'cost_impact': 'Potential 50-70% reduction in storage costs'
                    }
                ))
                
        except Exception as e:
            logger.error(f"Error checking CloudWatch Logs: {str(e)}")
            
        return findings
    
    def _check_cost_forecast(self) -> List[Finding]:
        """Forecast future costs and check for budget risks"""
        findings = []
        
        try:
            # Get cost forecast for next month
            start_date = datetime.now().date() + timedelta(days=1)
            end_date = start_date + timedelta(days=30)
            
            response = self.client.get_cost_forecast(
                TimePeriod={
                    'Start': start_date.strftime('%Y-%m-%d'),
                    'End': end_date.strftime('%Y-%m-%d')
                },
                Metric='UNBLENDED_COST',
                Granularity='MONTHLY'
            )
            
            forecasted_cost = float(response['Total']['Amount'])
            
            # Get last month's actual cost for comparison
            last_month_end = datetime.now().date()
            last_month_start = last_month_end - timedelta(days=30)
            
            historical_response = self.client.get_cost_and_usage(
                TimePeriod={
                    'Start': last_month_start.strftime('%Y-%m-%d'),
                    'End': last_month_end.strftime('%Y-%m-%d')
                },
                Granularity='MONTHLY',
                Metrics=['UNBLENDED_COST']
            )
            
            if historical_response['ResultsByTime']:
                last_month_cost = float(historical_response['ResultsByTime'][0]['Total']['UnblendedCost']['Amount'])
                
                # Check if forecast shows significant increase
                if forecasted_cost > last_month_cost * 1.2:  # 20% increase
                    increase_pct = ((forecasted_cost - last_month_cost) / last_month_cost) * 100
                    findings.append(Finding(
                        severity=Severity.HIGH,
                        category=Category.COST_OPTIMIZATION,
                        resource_type="AWS::CostExplorer::Forecast",
                        resource_id="cost-forecast",
                        region="global",
                        title="Projected Cost Increase",
                        description=f"Costs are forecasted to increase by {increase_pct:.1f}% next month",
                        impact=f"Projected ${forecasted_cost - last_month_cost:.2f} increase in monthly spend",
                        recommendation="Review recent changes, implement cost controls, set up budget alerts with actions",
                        evidence={
                            'last_month_cost': f"${last_month_cost:.2f}",
                            'forecasted_cost': f"${forecasted_cost:.2f}",
                            'increase_percentage': f"{increase_pct:.1f}%",
                            'cost_impact': f"${forecasted_cost - last_month_cost:.2f} projected increase"
                        }
                    ))
                    
        except Exception as e:
            logger.error(f"Error checking cost forecast: {str(e)}")
            
        return findings
    
    def _check_ecs_fargate_costs(self) -> List[Finding]:
        """Check ECS and Fargate cost optimization opportunities"""
        findings = []
        
        try:
            # List all ECS clusters
            clusters = self.ecs.list_clusters()
            region = self.ecs.meta.region_name
            
            if clusters['clusterArns']:
                # Get Fargate costs
                end_date = datetime.now().date()
                start_date = end_date - timedelta(days=30)
                
                response = self.client.get_cost_and_usage(
                    TimePeriod={
                        'Start': start_date.strftime('%Y-%m-%d'),
                        'End': end_date.strftime('%Y-%m-%d')
                    },
                    Granularity='MONTHLY',
                    Metrics=['UNBLENDED_COST'],
                    Filter={'Dimensions': {'Key': 'SERVICE', 'Values': ['Amazon Elastic Container Service']}}
                )
                
                if response['ResultsByTime']:
                    monthly_cost = float(response['ResultsByTime'][0]['Total']['UnblendedCost']['Amount'])
                    
                    if monthly_cost > 100:
                        # Check for Fargate Spot opportunities
                        findings.append(Finding(
                            severity=Severity.MEDIUM,
                            category=Category.COST_OPTIMIZATION,
                            resource_type="AWS::ECS::Service",
                            resource_id="fargate-optimization",
                            region=region,
                            title="ECS Fargate Cost Optimization Opportunities",
                            description=f"ECS/Fargate costs are ${monthly_cost:.2f} per month",
                            impact=f"${monthly_cost:.2f} monthly spend on container services",
                            recommendation="Consider Fargate Spot for non-critical workloads (70% savings), right-size task definitions, use Savings Plans",
                            evidence={
                                'monthly_cost': f"${monthly_cost:.2f}",
                                'cluster_count': len(clusters['clusterArns']),
                                'cost_impact': f"Potential 30-70% savings with Fargate Spot and Savings Plans"
                            }
                        ))
                        
        except Exception as e:
            logger.error(f"Error checking ECS/Fargate costs: {str(e)}")
            
        return findings
    
    def _check_eks_costs(self) -> List[Finding]:
        """Check EKS cluster costs"""
        findings = []
        
        try:
            # List EKS clusters
            clusters = self.eks.list_clusters()
            region = self.eks.meta.region_name
            
            if clusters['clusters']:
                # EKS charges $0.10 per hour per cluster
                cluster_count = len(clusters['clusters'])
                monthly_control_plane_cost = cluster_count * 0.10 * 24 * 30
                
                findings.append(Finding(
                    severity=Severity.LOW,
                    category=Category.COST_OPTIMIZATION,
                    resource_type="AWS::EKS::Cluster",
                    resource_id="control-plane-costs",
                    region=region,
                    title="EKS Control Plane Costs",
                    description=f"Running {cluster_count} EKS clusters with ${monthly_control_plane_cost:.2f}/month control plane costs",
                    impact=f"${monthly_control_plane_cost:.2f} monthly spend on EKS control planes",
                    recommendation="Consolidate development/test clusters, use shared clusters with namespaces for isolation",
                    evidence={
                        'cluster_count': cluster_count,
                        'clusters': clusters['clusters'][:5],
                        'monthly_cost': f"${monthly_control_plane_cost:.2f}",
                        'cost_impact': 'Fixed cost per cluster, consolidation can help'
                    }
                ))
                
        except Exception as e:
            logger.error(f"Error checking EKS costs: {str(e)}")
            
        return findings
    
    def _check_spot_opportunities(self) -> List[Finding]:
        """Identify EC2 instances that could use Spot"""
        findings = []
        
        try:
            # Get all running instances
            instances = self.ec2.describe_instances(
                Filters=[{'Name': 'instance-state-name', 'Values': ['running']}]
            )
            region = self.ec2.meta.region_name
            
            spot_candidates = []
            
            for reservation in instances['Reservations']:
                for instance in reservation['Instances']:
                    # Check if it's already a Spot instance
                    if instance.get('InstanceLifecycle') != 'spot':
                        tags = {tag['Key']: tag['Value'] for tag in instance.get('Tags', [])}
                        
                        # Good Spot candidates: dev/test environments, batch processing, stateless apps
                        env = tags.get('Environment', '').lower()
                        name = tags.get('Name', '').lower()
                        
                        if env in ['dev', 'development', 'test', 'staging'] or \
                           any(keyword in name for keyword in ['batch', 'worker', 'processing', 'compute']):
                            spot_candidates.append({
                                'id': instance['InstanceId'],
                                'type': instance['InstanceType'],
                                'name': tags.get('Name', 'N/A'),
                                'env': env or 'unknown'
                            })
            
            if spot_candidates:
                # Estimate savings (average 70% discount)
                findings.append(Finding(
                    severity=Severity.MEDIUM,
                    category=Category.COST_OPTIMIZATION,
                    resource_type="AWS::EC2::Instance",
                    resource_id="spot-opportunities",
                    region=region,
                    title="EC2 Spot Instance Opportunities",
                    description=f"Found {len(spot_candidates)} instances suitable for Spot deployment",
                    impact="Paying on-demand prices for interruptible workloads",
                    recommendation="Migrate non-critical workloads to Spot instances, use Spot Fleet with mixed instance types",
                    evidence={
                        'affected_resources': [c['id'] for c in spot_candidates[:10]],
                        'candidate_count': len(spot_candidates),
                        'sample_candidates': spot_candidates[:5],
                        'cost_impact': 'Potential 50-90% savings with Spot instances'
                    }
                ))
                
        except Exception as e:
            logger.error(f"Error checking Spot opportunities: {str(e)}")
            
        return findings
    
    def _check_dynamodb_costs(self) -> List[Finding]:
        """Check DynamoDB cost optimization opportunities"""
        findings = []
        
        try:
            # List all DynamoDB tables
            tables = []
            paginator = self.dynamodb.get_paginator('list_tables')
            for page in paginator.paginate():
                tables.extend(page['TableNames'])
            
            region = self.dynamodb.meta.region_name
            on_demand_tables = []
            overprovisioned_tables = []
            
            for table_name in tables:
                table = self.dynamodb.describe_table(TableName=table_name)['Table']
                
                # Check billing mode
                if table.get('BillingModeSummary', {}).get('BillingMode') == 'PAY_PER_REQUEST':
                    on_demand_tables.append(table_name)
                else:
                    # Check if provisioned capacity is being used efficiently
                    # This is a simplified check - real optimization would need CloudWatch metrics
                    read_capacity = table.get('ProvisionedThroughput', {}).get('ReadCapacityUnits', 0)
                    write_capacity = table.get('ProvisionedThroughput', {}).get('WriteCapacityUnits', 0)
                    
                    if read_capacity > 100 or write_capacity > 100:
                        overprovisioned_tables.append({
                            'name': table_name,
                            'read': read_capacity,
                            'write': write_capacity
                        })
            
            if len(on_demand_tables) > 5:
                findings.append(Finding(
                    severity=Severity.MEDIUM,
                    category=Category.COST_OPTIMIZATION,
                    resource_type="AWS::DynamoDB::Table",
                    resource_id="billing-mode",
                    region=region,
                    title="Multiple DynamoDB On-Demand Tables",
                    description=f"Found {len(on_demand_tables)} tables using on-demand billing",
                    impact="On-demand can be 5-7x more expensive than provisioned for steady workloads",
                    recommendation="Analyze usage patterns and switch steady-state tables to provisioned capacity with auto-scaling",
                    evidence={
                        'affected_resources': on_demand_tables[:10],
                        'table_count': len(on_demand_tables),
                        'cost_impact': 'Potential 50-80% savings for predictable workloads'
                    }
                ))
                
        except Exception as e:
            logger.error(f"Error checking DynamoDB costs: {str(e)}")
            
        return findings
    
    def _check_elasticache_costs(self) -> List[Finding]:
        """Check ElastiCache optimization opportunities"""
        findings = []
        
        try:
            # Get cache clusters
            clusters = self.elasticache.describe_cache_clusters()
            region = self.elasticache.meta.region_name
            
            # Check for reserved node opportunities
            reserved_nodes = self.elasticache.describe_reserved_cache_nodes()
            
            active_clusters = [c for c in clusters['CacheClusters'] if c['CacheClusterStatus'] == 'available']
            reserved_count = len([r for r in reserved_nodes['ReservedCacheNodes'] if r['State'] == 'active'])
            
            if active_clusters and reserved_count < len(active_clusters) / 2:
                findings.append(Finding(
                    severity=Severity.MEDIUM,
                    category=Category.COST_OPTIMIZATION,
                    resource_type="AWS::ElastiCache::CacheCluster",
                    resource_id="reserved-nodes",
                    region=region,
                    title="Low ElastiCache Reserved Node Coverage",
                    description=f"Only {reserved_count} of {len(active_clusters)} cache nodes are covered by reservations",
                    impact="Paying on-demand prices for steady-state cache infrastructure",
                    recommendation="Purchase Reserved Cache Nodes for production workloads (up to 55% savings)",
                    evidence={
                        'active_clusters': len(active_clusters),
                        'reserved_nodes': reserved_count,
                        'cost_impact': 'Potential 30-55% savings with reserved nodes'
                    }
                ))
                
        except Exception as e:
            logger.error(f"Error checking ElastiCache costs: {str(e)}")
            
        return findings
    
    def _check_redshift_costs(self) -> List[Finding]:
        """Check Redshift cluster optimization"""
        findings = []
        
        try:
            # Get Redshift clusters
            clusters = self.redshift.describe_clusters()
            region = self.redshift.meta.region_name
            
            for cluster in clusters['Clusters']:
                cluster_id = cluster['ClusterIdentifier']
                node_type = cluster['NodeType']
                node_count = cluster['NumberOfNodes']
                
                # Check if cluster can be paused
                tags = {tag['Key']: tag['Value'] for tag in cluster.get('Tags', [])}
                env = tags.get('Environment', '').lower()
                
                if env in ['dev', 'development', 'test', 'staging']:
                    findings.append(Finding(
                        severity=Severity.HIGH,
                        category=Category.COST_OPTIMIZATION,
                        resource_type="AWS::Redshift::Cluster",
                        resource_id=cluster_id,
                        region=region,
                        title=f"Redshift Cluster Pause Opportunity - {cluster_id}",
                        description=f"Non-production Redshift cluster {cluster_id} ({node_count}x {node_type}) running 24/7",
                        impact="Paying for compute when cluster is not in use",
                        recommendation="Implement automated pause/resume schedule for non-production clusters (save 75% during off-hours)",
                        evidence={
                            'affected_resources': [cluster_id],
                            'environment': env,
                            'node_type': node_type,
                            'node_count': node_count,
                            'cost_impact': 'Save up to 75% by pausing during nights/weekends'
                        }
                    ))
                    
        except Exception as e:
            logger.error(f"Error checking Redshift costs: {str(e)}")
            
        return findings
    
    def _check_sagemaker_costs(self) -> List[Finding]:
        """Check SageMaker notebook instances"""
        findings = []
        
        try:
            # List notebook instances
            notebooks = self.sagemaker.list_notebook_instances()
            region = self.sagemaker.meta.region_name
            
            idle_notebooks = []
            
            for notebook in notebooks['NotebookInstances']:
                if notebook['NotebookInstanceStatus'] == 'InService':
                    # Get more details
                    details = self.sagemaker.describe_notebook_instance(
                        NotebookInstanceName=notebook['NotebookInstanceName']
                    )
                    
                    # Check last modified time
                    last_modified = details['LastModifiedTime']
                    days_idle = (datetime.now(last_modified.tzinfo) - last_modified).days
                    
                    if days_idle > 7:
                        idle_notebooks.append({
                            'name': notebook['NotebookInstanceName'],
                            'type': notebook['InstanceType'],
                            'days_idle': days_idle
                        })
            
            if idle_notebooks:
                findings.append(Finding(
                    severity=Severity.HIGH,
                    category=Category.COST_OPTIMIZATION,
                    resource_type="AWS::SageMaker::NotebookInstance",
                    resource_id="idle-notebooks",
                    region=region,
                    title="Idle SageMaker Notebook Instances",
                    description=f"Found {len(idle_notebooks)} notebook instances idle for over 7 days",
                    impact="Paying for unused SageMaker compute resources",
                    recommendation="Stop idle notebook instances, use lifecycle configurations for auto-stop",
                    evidence={
                        'affected_resources': [n['name'] for n in idle_notebooks],
                        'notebook_count': len(idle_notebooks),
                        'sample_notebooks': idle_notebooks[:5],
                        'cost_impact': 'Significant savings by stopping idle notebooks'
                    }
                ))
                
        except Exception as e:
            logger.error(f"Error checking SageMaker costs: {str(e)}")
            
        return findings