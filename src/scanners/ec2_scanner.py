"""EC2 Security Scanner Module

This module scans EC2 resources for security misconfigurations and compliance issues.
"""

import logging
from typing import List, Dict, Any, Optional
from datetime import datetime, timezone

from .base import BaseScanner
from ..models import Finding, Category, Severity, ComplianceFramework


logger = logging.getLogger(__name__)


class EC2Scanner(BaseScanner):
    """Scanner for EC2 security configurations"""
    
    def __init__(self, session, regions: Optional[List[str]] = None):
        super().__init__(session, regions)
    
    @property
    def service_name(self) -> str:
        """Return the AWS service name"""
        return 'ec2'
    
    def scan(self) -> List[Finding]:
        """Perform EC2 security scan across all regions"""
        findings = []
        
        for region in self.regions:
            logger.info(f"Scanning EC2 in region {region}")
            try:
                ec2_client = self.session.client('ec2', region_name=region)
                
                # Instance security checks
                findings.extend(self._check_instances(ec2_client, region))
                
                # Security group checks
                findings.extend(self._check_security_groups(ec2_client, region))
                
                # EBS volume checks
                findings.extend(self._check_ebs_volumes(ec2_client, region))
                
                # VPC endpoint checks
                findings.extend(self._check_vpc_endpoints(ec2_client, region))
                
                # Network ACL checks
                findings.extend(self._check_network_acls(ec2_client, region))
                
                # Elastic IP checks
                findings.extend(self._check_elastic_ips(ec2_client, region))
                
            except Exception as e:
                logger.error(f"Error scanning EC2 in region {region}: {str(e)}")
                findings.append(Finding(
                    title="EC2 Scan Error",
                    description=f"Failed to scan EC2 resources in region {region}: {str(e)}",
                    severity=Severity.MEDIUM,
                    category=Category.CONFIGURATION,
                    resource_type="AWS::EC2::Region",
                    resource_id=region,
                    region=region,
                    impact="Unable to assess security posture of EC2 resources in this region, potentially missing critical vulnerabilities",
                    recommendation="Check AWS service status and IAM permissions for EC2 access in this region"
                ))
        
        return findings
    
    def _check_instances(self, ec2_client, region: str) -> List[Finding]:
        """Check EC2 instances for security issues"""
        findings = []
        
        try:
            # Get all instances
            paginator = ec2_client.get_paginator('describe_instances')
            
            for page in paginator.paginate():
                for reservation in page.get('Reservations', []):
                    for instance in reservation.get('Instances', []):
                        instance_id = instance['InstanceId']
                        
                        # Skip terminated instances
                        if instance['State']['Name'] == 'terminated':
                            continue
                        
                        # Check IMDSv2 enforcement
                        findings.extend(self._check_imdsv2(instance, region))
                        
                        # Check public IP assignment
                        findings.extend(self._check_public_ip(instance, region))
                        
                        # Check instance profile permissions
                        findings.extend(self._check_instance_profile(instance, region))
                        
                        # Check monitoring status
                        findings.extend(self._check_monitoring(instance, region))
                        
                        # Check termination protection
                        findings.extend(self._check_termination_protection(ec2_client, instance, region))
                        
        except Exception as e:
            logger.error(f"Error checking instances in region {region}: {str(e)}")
            
        return findings
    
    def _check_imdsv2(self, instance: Dict[str, Any], region: str) -> List[Finding]:
        """Check if IMDSv2 is enforced"""
        findings = []
        instance_id = instance['InstanceId']
        
        metadata_options = instance.get('MetadataOptions', {})
        http_tokens = metadata_options.get('HttpTokens', 'optional')
        
        if http_tokens != 'required':
            findings.append(Finding(
                title="EC2 Instance Not Enforcing IMDSv2",
                description=f"Instance {instance_id} does not require IMDSv2 tokens. IMDSv1 is vulnerable to SSRF attacks.",
                severity=Severity.HIGH,
                category=Category.ACCESS_CONTROL,
                resource_type="AWS::EC2::Instance",
                resource_id=instance_id,
                region=region,
                recommendation="Enable IMDSv2 enforcement by setting HttpTokens to 'required'",
                compliance_frameworks=[ComplianceFramework.NIST, ComplianceFramework.CIS],
                impact="Instance is vulnerable to SSRF attacks that could expose credentials and metadata, potentially leading to privilege escalation and unauthorized access to AWS resources",
                evidence={
                    'instance_name': self._get_instance_name(instance),
                    'current_setting': http_tokens,
                    'metadata_options': metadata_options
                }
            ))
        
        return findings
    
    def _check_public_ip(self, instance: Dict[str, Any], region: str) -> List[Finding]:
        """Check for instances with public IP addresses"""
        findings = []
        instance_id = instance['InstanceId']
        
        public_ip = instance.get('PublicIpAddress')
        public_dns = instance.get('PublicDnsName')
        
        if public_ip:
            findings.append(Finding(
                title="EC2 Instance Has Public IP Address",
                description=f"Instance {instance_id} has a public IP address ({public_ip}), increasing attack surface.",
                severity=Severity.MEDIUM,
                category=Category.NETWORK,
                resource_type="AWS::EC2::Instance",
                resource_id=instance_id,
                region=region,
                recommendation="Consider using private IPs with NAT gateways or VPC endpoints for internet access",
                compliance_frameworks=[ComplianceFramework.NIST],
                impact="Instance is directly exposed to the internet, increasing risk of unauthorized access, brute force attacks, and exploitation of unpatched vulnerabilities",
                evidence={
                    'instance_name': self._get_instance_name(instance),
                    'public_ip': public_ip,
                    'public_dns': public_dns,
                    'vpc_id': instance.get('VpcId'),
                    'subnet_id': instance.get('SubnetId')
                }
            ))
        
        return findings
    
    def _check_instance_profile(self, instance: Dict[str, Any], region: str) -> List[Finding]:
        """Check instance profile permissions"""
        findings = []
        instance_id = instance['InstanceId']
        
        iam_profile = instance.get('IamInstanceProfile')
        if not iam_profile:
            findings.append(Finding(
                title="EC2 Instance Without IAM Role",
                description=f"Instance {instance_id} has no IAM role attached. Cannot use AWS services securely.",
                severity=Severity.LOW,
                category=Category.IAM,
                resource_type="AWS::EC2::Instance",
                resource_id=instance_id,
                region=region,
                recommendation="Attach an IAM role with minimal required permissions",
                impact="Applications must use hardcoded credentials for AWS API access, increasing risk of credential exposure and limiting security best practices",
                evidence={
                    'instance_name': self._get_instance_name(instance)
                }
            ))
        
        return findings
    
    def _check_monitoring(self, instance: Dict[str, Any], region: str) -> List[Finding]:
        """Check if detailed monitoring is enabled"""
        findings = []
        instance_id = instance['InstanceId']
        
        monitoring_state = instance.get('Monitoring', {}).get('State', 'disabled')
        
        if monitoring_state != 'enabled':
            findings.append(Finding(
                title="EC2 Instance Detailed Monitoring Disabled",
                description=f"Instance {instance_id} does not have detailed monitoring enabled.",
                severity=Severity.LOW,
                category=Category.LOGGING,
                resource_type="AWS::EC2::Instance",
                resource_id=instance_id,
                region=region,
                recommendation="Enable detailed monitoring for better visibility",
                impact="Limited visibility into instance performance metrics may delay detection of security incidents, performance issues, or abnormal behavior",
                evidence={
                    'instance_name': self._get_instance_name(instance),
                    'monitoring_state': monitoring_state
                }
            ))
        
        return findings
    
    def _check_termination_protection(self, ec2_client, instance: Dict[str, Any], region: str) -> List[Finding]:
        """Check if termination protection is enabled for production instances"""
        findings = []
        instance_id = instance['InstanceId']
        
        try:
            # Check termination protection
            response = ec2_client.describe_instance_attribute(
                InstanceId=instance_id,
                Attribute='disableApiTermination'
            )
            
            termination_protection = response.get('DisableApiTermination', {}).get('Value', False)
            
            # Check if this appears to be a production instance
            instance_name = self._get_instance_name(instance)
            is_production = any(prod_indicator in instance_name.lower() 
                              for prod_indicator in ['prod', 'production', 'prd'])
            
            if is_production and not termination_protection:
                findings.append(Finding(
                    title="Production Instance Without Termination Protection",
                    description=f"Instance {instance_id} appears to be a production instance but lacks termination protection.",
                    severity=Severity.MEDIUM,
                    category=Category.DATA_PROTECTION,
                    resource_type="AWS::EC2::Instance",
                    resource_id=instance_id,
                    region=region,
                    recommendation="Enable termination protection for production instances",
                    impact="Critical production instance can be accidentally or maliciously terminated, causing service outages and potential data loss",
                    evidence={
                        'instance_name': instance_name,
                        'termination_protection': termination_protection
                    }
                ))
                
        except Exception as e:
            logger.warning(f"Could not check termination protection for {instance_id}: {str(e)}")
        
        return findings
    
    def _check_security_groups(self, ec2_client, region: str) -> List[Finding]:
        """Check security groups for overly permissive rules"""
        findings = []
        
        try:
            # Get all security groups
            paginator = ec2_client.get_paginator('describe_security_groups')
            
            for page in paginator.paginate():
                for sg in page.get('SecurityGroups', []):
                    sg_id = sg['GroupId']
                    sg_name = sg.get('GroupName', 'Unknown')
                    
                    # Check ingress rules
                    for rule in sg.get('IpPermissions', []):
                        findings.extend(self._check_sg_rule(sg, rule, 'ingress', region))
                    
                    # Check egress rules
                    for rule in sg.get('IpPermissionsEgress', []):
                        findings.extend(self._check_sg_rule(sg, rule, 'egress', region))
                    
        except Exception as e:
            logger.error(f"Error checking security groups in region {region}: {str(e)}")
        
        return findings
    
    def _check_sg_rule(self, sg: Dict[str, Any], rule: Dict[str, Any], direction: str, region: str) -> List[Finding]:
        """Check individual security group rule"""
        findings = []
        sg_id = sg['GroupId']
        sg_name = sg.get('GroupName', 'Unknown')
        
        # Check for overly permissive rules
        for ip_range in rule.get('IpRanges', []):
            cidr = ip_range.get('CidrIp', '')
            
            if cidr == '0.0.0.0/0':
                from_port = rule.get('FromPort', 'All')
                to_port = rule.get('ToPort', 'All')
                protocol = rule.get('IpProtocol', '-1')
                
                # Determine severity based on port and direction
                if direction == 'ingress':
                    if protocol == '-1' or from_port == 'All':
                        severity = Severity.CRITICAL
                        port_desc = "all ports"
                    elif from_port in [22, 3389]:
                        severity = Severity.HIGH
                        port_desc = f"management port {from_port}"
                    elif from_port in [80, 443]:
                        severity = Severity.MEDIUM
                        port_desc = f"web port {from_port}"
                    else:
                        severity = Severity.MEDIUM
                        port_desc = f"port {from_port}"
                    
                    findings.append(Finding(
                        title=f"Security Group Allows {direction.title()} from Internet",
                        description=f"Security group {sg_name} ({sg_id}) allows {direction} traffic from 0.0.0.0/0 on {port_desc}.",
                        severity=severity,
                        category=Category.NETWORK,
                        resource_type="AWS::EC2::SecurityGroup",
                        resource_id=sg_id,
                        region=region,
                        recommendation="Restrict access to specific IP ranges or use VPN/bastion hosts",
                        compliance_frameworks=[ComplianceFramework.NIST, ComplianceFramework.CIS],
                        impact="Resources are exposed to the entire internet, enabling unauthorized access attempts, brute force attacks, and exploitation of vulnerabilities by malicious actors worldwide",
                        evidence={
                            'group_name': sg_name,
                            'rule_direction': direction,
                            'protocol': protocol,
                            'from_port': from_port,
                            'to_port': to_port,
                            'cidr': cidr,
                            'vpc_id': sg.get('VpcId')
                        }
                    ))
        
        # Check for IPv6 ranges
        for ipv6_range in rule.get('Ipv6Ranges', []):
            cidr_ipv6 = ipv6_range.get('CidrIpv6', '')
            
            if cidr_ipv6 == '::/0' and direction == 'ingress':
                findings.append(Finding(
                    title=f"Security Group Allows {direction.title()} from Internet (IPv6)",
                    description=f"Security group {sg_name} ({sg_id}) allows {direction} traffic from ::/0.",
                    severity=Severity.HIGH,
                    category=Category.NETWORK,
                    resource_type="AWS::EC2::SecurityGroup",
                    resource_id=sg_id,
                    region=region,
                    recommendation="Restrict IPv6 access to specific ranges",
                    impact="Resources are exposed to the entire IPv6 internet, enabling unauthorized access attempts and exploitation of vulnerabilities from global IPv6 addresses",
                    evidence={
                        'group_name': sg_name,
                        'rule_direction': direction,
                        'cidr_ipv6': cidr_ipv6
                    }
                ))
        
        return findings
    
    def _check_ebs_volumes(self, ec2_client, region: str) -> List[Finding]:
        """Check EBS volumes for encryption"""
        findings = []
        
        try:
            # Get all volumes
            paginator = ec2_client.get_paginator('describe_volumes')
            
            for page in paginator.paginate():
                for volume in page.get('Volumes', []):
                    volume_id = volume['VolumeId']
                    
                    # Check encryption
                    if not volume.get('Encrypted', False):
                        findings.append(Finding(
                            title="EBS Volume Not Encrypted",
                            description=f"EBS volume {volume_id} is not encrypted at rest.",
                            severity=Severity.HIGH,
                            category=Category.DATA_PROTECTION,
                            resource_type="AWS::EC2::Volume",
                            resource_id=volume_id,
                            region=region,
                            recommendation="Enable EBS encryption for all volumes",
                            compliance_frameworks=[ComplianceFramework.NIST, ComplianceFramework.SOX],
                            impact="Sensitive data stored on the volume is not encrypted at rest, risking exposure if physical storage is compromised or snapshots are shared",
                            evidence={
                                'volume_type': volume.get('VolumeType'),
                                'size': volume.get('Size'),
                                'state': volume.get('State'),
                                'attachments': len(volume.get('Attachments', []))
                            }
                        ))
                    
                    # Check for volumes without snapshots
                    if volume.get('State') == 'in-use':
                        # This would require checking snapshots separately
                        # Adding as a low-priority finding
                        findings.append(Finding(
                            title="EBS Volume Backup Status Unknown",
                            description=f"EBS volume {volume_id} backup status should be verified.",
                            severity=Severity.LOW,
                            category=Category.DATA_PROTECTION,
                            resource_type="AWS::EC2::Volume",
                            resource_id=volume_id,
                            region=region,
                            recommendation="Ensure regular snapshots are taken for important volumes",
                            impact="Without regular backups, data loss could occur due to volume failure, accidental deletion, or corruption, affecting business continuity",
                            evidence={
                                'volume_type': volume.get('VolumeType'),
                                'size': volume.get('Size')
                            }
                        ))
                    
        except Exception as e:
            logger.error(f"Error checking EBS volumes in region {region}: {str(e)}")
        
        return findings
    
    def _check_vpc_endpoints(self, ec2_client, region: str) -> List[Finding]:
        """Check for VPC endpoints to reduce internet exposure"""
        findings = []
        
        try:
            # Get all VPCs
            vpcs_response = ec2_client.describe_vpcs()
            vpcs = vpcs_response.get('Vpcs', [])
            
            # Get all VPC endpoints
            endpoints_response = ec2_client.describe_vpc_endpoints()
            endpoints = endpoints_response.get('VpcEndpoints', [])
            
            # Create a map of VPC to endpoints
            vpc_endpoints_map = {}
            for endpoint in endpoints:
                vpc_id = endpoint.get('VpcId')
                if vpc_id:
                    if vpc_id not in vpc_endpoints_map:
                        vpc_endpoints_map[vpc_id] = []
                    vpc_endpoints_map[vpc_id].append(endpoint)
            
            # Check each VPC for recommended endpoints
            recommended_services = ['s3', 'dynamodb', 'ec2', 'sts', 'kms']
            
            for vpc in vpcs:
                vpc_id = vpc['VpcId']
                vpc_endpoints = vpc_endpoints_map.get(vpc_id, [])
                
                # Get endpoint service names
                endpoint_services = [ep.get('ServiceName', '').split('.')[-1] 
                                   for ep in vpc_endpoints]
                
                # Check for missing recommended endpoints
                missing_endpoints = []
                for service in recommended_services:
                    if service not in endpoint_services:
                        missing_endpoints.append(service)
                
                if missing_endpoints:
                    findings.append(Finding(
                        title="VPC Missing Recommended Endpoints",
                        description=f"VPC {vpc_id} is missing endpoints for: {', '.join(missing_endpoints)}. This may increase internet traffic and costs.",
                        severity=Severity.LOW,
                        category=Category.NETWORK,
                        resource_type="AWS::EC2::VPC",
                        resource_id=vpc_id,
                        region=region,
                        recommendation="Create VPC endpoints for frequently used AWS services",
                        impact="Traffic to AWS services traverses the internet gateway, increasing data transfer costs, latency, and exposure to internet-based threats",
                        evidence={
                            'missing_endpoints': missing_endpoints,
                            'existing_endpoints': endpoint_services,
                            'vpc_name': self._get_resource_name(vpc)
                        }
                    ))
                    
        except Exception as e:
            logger.error(f"Error checking VPC endpoints in region {region}: {str(e)}")
        
        return findings
    
    def _check_network_acls(self, ec2_client, region: str) -> List[Finding]:
        """Check network ACLs for overly permissive rules"""
        findings = []
        
        try:
            # Get all network ACLs
            nacls_response = ec2_client.describe_network_acls()
            
            for nacl in nacls_response.get('NetworkAcls', []):
                nacl_id = nacl['NetworkAclId']
                
                # Skip default NACLs as they allow all traffic by default
                if nacl.get('IsDefault', False):
                    continue
                
                # Check entries
                for entry in nacl.get('Entries', []):
                    if entry.get('CidrBlock') == '0.0.0.0/0' or entry.get('Ipv6CidrBlock') == '::/0':
                        if entry.get('RuleAction') == 'allow' and entry.get('Protocol') == '-1':
                            findings.append(Finding(
                                title="Network ACL Allows All Traffic",
                                description=f"Network ACL {nacl_id} has a rule allowing all traffic from/to anywhere.",
                                severity=Severity.MEDIUM,
                                category=Category.NETWORK,
                                resource_type="AWS::EC2::NetworkAcl",
                                resource_id=nacl_id,
                                region=region,
                                recommendation="Implement least-privilege network ACL rules",
                                impact="Overly permissive network ACL rules bypass subnet-level security controls, potentially allowing malicious traffic between subnets and external networks",
                                evidence={
                                    'rule_number': entry.get('RuleNumber'),
                                    'egress': entry.get('Egress'),
                                    'protocol': entry.get('Protocol'),
                                    'rule_action': entry.get('RuleAction')
                                }
                            ))
                            
        except Exception as e:
            logger.error(f"Error checking network ACLs in region {region}: {str(e)}")
        
        return findings
    
    def _check_elastic_ips(self, ec2_client, region: str) -> List[Finding]:
        """Check for unassociated Elastic IPs"""
        findings = []
        
        try:
            # Get all Elastic IPs
            eips_response = ec2_client.describe_addresses()
            
            for eip in eips_response.get('Addresses', []):
                allocation_id = eip.get('AllocationId', eip.get('PublicIp'))
                
                # Check if unassociated
                if not eip.get('InstanceId') and not eip.get('NetworkInterfaceId'):
                    findings.append(Finding(
                        title="Unassociated Elastic IP",
                        description=f"Elastic IP {eip.get('PublicIp')} is not associated with any instance or network interface.",
                        severity=Severity.LOW,
                        category=Category.COST_OPTIMIZATION,
                        resource_type="AWS::EC2::EIP",
                        resource_id=allocation_id,
                        region=region,
                        recommendation="Release unassociated Elastic IPs to avoid charges",
                        impact="Unassociated Elastic IPs incur hourly charges without providing value, increasing AWS costs unnecessarily",
                        evidence={
                            'public_ip': eip.get('PublicIp'),
                            'allocation_id': allocation_id,
                            'domain': eip.get('Domain')
                        }
                    ))
                    
        except Exception as e:
            logger.error(f"Error checking Elastic IPs in region {region}: {str(e)}")
        
        return findings
    
    def _get_instance_name(self, instance: Dict[str, Any]) -> str:
        """Get instance name from tags"""
        return self._get_resource_name(instance)
    
    def _get_resource_name(self, resource: Dict[str, Any]) -> str:
        """Get resource name from tags"""
        tags = resource.get('Tags', [])
        for tag in tags:
            if tag.get('Key') == 'Name':
                return tag.get('Value', 'Unknown')
        return 'Unknown'