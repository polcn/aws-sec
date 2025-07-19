"""VPC Security Scanner Module

This module scans VPC resources for security misconfigurations and compliance issues.
"""

import logging
from typing import List, Dict, Any, Optional
from datetime import datetime, timezone

from .base import BaseScanner
from ..models import Finding, Category, Severity, ComplianceFramework


logger = logging.getLogger(__name__)


class VPCScanner(BaseScanner):
    """Scanner for VPC security configurations"""
    
    def __init__(self, session, regions: Optional[List[str]] = None):
        super().__init__(session, regions)
    
    @property
    def service_name(self) -> str:
        """Return the AWS service name"""
        return 'vpc'
    
    def scan(self) -> List[Finding]:
        """Perform VPC security scan across all regions"""
        findings = []
        
        for region in self.regions:
            logger.info(f"Scanning VPC in region {region}")
            try:
                ec2_client = self.session.client('ec2', region_name=region)
                logs_client = self.session.client('logs', region_name=region)
                
                # VPC security checks
                findings.extend(self._check_vpcs(ec2_client, region))
                
                # Flow logs checks
                findings.extend(self._check_flow_logs(ec2_client, logs_client, region))
                
                # Internet Gateway checks
                findings.extend(self._check_internet_gateways(ec2_client, region))
                
                # NAT Gateway checks
                findings.extend(self._check_nat_gateways(ec2_client, region))
                
                # VPC Peering checks
                findings.extend(self._check_vpc_peering(ec2_client, region))
                
                # VPC endpoints checks
                findings.extend(self._check_vpc_endpoints(ec2_client, region))
                
                # Route table checks
                findings.extend(self._check_route_tables(ec2_client, region))
                
                # DHCP options checks
                findings.extend(self._check_dhcp_options(ec2_client, region))
                
                # VPN connection checks
                findings.extend(self._check_vpn_connections(ec2_client, region))
                
            except Exception as e:
                logger.error(f"Error scanning VPC in region {region}: {str(e)}")
                findings.append(Finding(
                    title="VPC Scan Error",
                    description=f"Failed to scan VPC resources in region {region}: {str(e)}",
                    severity=Severity.MEDIUM,
                    category=Category.CONFIGURATION,
                    resource_type="AWS::VPC::Region",
                    resource_id=region,
                    region=region,
                    impact="Unable to assess security posture of VPC resources in this region, potentially missing critical vulnerabilities",
                    recommendation="Check AWS service status and IAM permissions for VPC access in this region"
                ))
        
        return findings
    
    def _check_vpcs(self, ec2_client, region: str) -> List[Finding]:
        """Check VPCs for security issues"""
        findings = []
        
        try:
            vpcs_response = ec2_client.describe_vpcs()
            
            for vpc in vpcs_response.get('Vpcs', []):
                vpc_id = vpc['VpcId']
                
                # Check for VPCs without proper tagging
                if not vpc.get('Tags'):
                    findings.append(Finding(
                        title="VPC Without Tags",
                        description=f"VPC {vpc_id} has no tags for identification and management.",
                        severity=Severity.LOW,
                        category=Category.CONFIGURATION,
                        resource_type="AWS::EC2::VPC",
                        resource_id=vpc_id,
                        region=region,
                        recommendation="Add tags including Name, Environment, and Owner",
                        impact="Untagged resources are difficult to manage, track costs, and apply governance policies",
                        evidence={
                            'vpc_cidr': vpc.get('CidrBlock'),
                            'is_default': vpc.get('IsDefault', False)
                        }
                    ))
                
                # Check DNS settings
                dns_support = vpc.get('EnableDnsSupport', False)
                dns_hostnames = vpc.get('EnableDnsHostnames', False)
                
                if not dns_support or not dns_hostnames:
                    findings.append(Finding(
                        title="VPC DNS Settings Not Optimal",
                        description=f"VPC {vpc_id} does not have both DNS support and DNS hostnames enabled.",
                        severity=Severity.LOW,
                        category=Category.CONFIGURATION,
                        resource_type="AWS::EC2::VPC",
                        resource_id=vpc_id,
                        region=region,
                        recommendation="Enable both DNS support and DNS hostnames for better functionality",
                        impact="Limited DNS functionality may affect service discovery and connectivity within the VPC",
                        evidence={
                            'dns_support': dns_support,
                            'dns_hostnames': dns_hostnames,
                            'vpc_name': self._get_resource_name(vpc)
                        }
                    ))
                
        except Exception as e:
            logger.error(f"Error checking VPCs in region {region}: {str(e)}")
        
        return findings
    
    def _check_flow_logs(self, ec2_client, logs_client, region: str) -> List[Finding]:
        """Check VPC Flow Logs configuration"""
        findings = []
        
        try:
            # Get all VPCs
            vpcs_response = ec2_client.describe_vpcs()
            vpc_ids = [vpc['VpcId'] for vpc in vpcs_response.get('Vpcs', [])]
            
            # Get all flow logs
            flow_logs_response = ec2_client.describe_flow_logs()
            flow_logs = flow_logs_response.get('FlowLogs', [])
            
            # Create a map of resources with flow logs
            resources_with_flow_logs = set()
            for flow_log in flow_logs:
                if flow_log.get('FlowLogStatus') == 'ACTIVE':
                    resources_with_flow_logs.add(flow_log.get('ResourceId'))
            
            # Check each VPC for flow logs
            for vpc_id in vpc_ids:
                if vpc_id not in resources_with_flow_logs:
                    # Get VPC details
                    vpc_details = ec2_client.describe_vpcs(VpcIds=[vpc_id])
                    vpc = vpc_details['Vpcs'][0] if vpc_details['Vpcs'] else {}
                    
                    findings.append(Finding(
                        title="VPC Flow Logs Not Enabled",
                        description=f"VPC {vpc_id} does not have flow logs enabled for network traffic monitoring.",
                        severity=Severity.HIGH,
                        category=Category.LOGGING,
                        resource_type="AWS::EC2::VPC",
                        resource_id=vpc_id,
                        region=region,
                        recommendation="Enable VPC Flow Logs to monitor network traffic",
                        compliance_frameworks=[ComplianceFramework.NIST, ComplianceFramework.CIS],
                        impact="Cannot monitor network traffic for security analysis, incident response, or compliance auditing",
                        evidence={
                            'vpc_name': self._get_resource_name(vpc),
                            'vpc_cidr': vpc.get('CidrBlock'),
                            'is_default': vpc.get('IsDefault', False)
                        }
                    ))
                else:
                    # Check flow log configuration
                    vpc_flow_logs = [fl for fl in flow_logs if fl.get('ResourceId') == vpc_id]
                    for flow_log in vpc_flow_logs:
                        # Check if flow logs are stored encrypted
                        if flow_log.get('LogDestinationType') == 's3':
                            findings.append(Finding(
                                title="VPC Flow Logs S3 Encryption Status Unknown",
                                description=f"VPC {vpc_id} flow logs are stored in S3. Ensure the bucket is encrypted.",
                                severity=Severity.LOW,
                                category=Category.DATA_PROTECTION,
                                resource_type="AWS::EC2::FlowLog",
                                resource_id=flow_log.get('FlowLogId'),
                                region=region,
                                recommendation="Verify S3 bucket encryption for flow logs storage",
                                impact="Flow logs may contain sensitive network traffic patterns and should be encrypted at rest",
                                evidence={
                                    'log_destination': flow_log.get('LogDestination'),
                                    'traffic_type': flow_log.get('TrafficType')
                                }
                            ))
            
        except Exception as e:
            logger.error(f"Error checking flow logs in region {region}: {str(e)}")
        
        return findings
    
    def _check_internet_gateways(self, ec2_client, region: str) -> List[Finding]:
        """Check Internet Gateways for security issues"""
        findings = []
        
        try:
            # Get all Internet Gateways
            igws_response = ec2_client.describe_internet_gateways()
            
            for igw in igws_response.get('InternetGateways', []):
                igw_id = igw['InternetGatewayId']
                attachments = igw.get('Attachments', [])
                
                # Check for detached IGWs (cost optimization)
                if not attachments:
                    findings.append(Finding(
                        title="Detached Internet Gateway",
                        description=f"Internet Gateway {igw_id} is not attached to any VPC.",
                        severity=Severity.LOW,
                        category=Category.COST_OPTIMIZATION,
                        resource_type="AWS::EC2::InternetGateway",
                        resource_id=igw_id,
                        region=region,
                        recommendation="Delete unused Internet Gateways to maintain a clean environment",
                        impact="Unused resources clutter the environment and may cause confusion during incident response",
                        evidence={
                            'igw_name': self._get_resource_name(igw)
                        }
                    ))
                
                # Check for multiple VPC attachments (should not happen)
                if len(attachments) > 1:
                    findings.append(Finding(
                        title="Internet Gateway Multiple Attachments",
                        description=f"Internet Gateway {igw_id} has multiple VPC attachments.",
                        severity=Severity.MEDIUM,
                        category=Category.CONFIGURATION,
                        resource_type="AWS::EC2::InternetGateway",
                        resource_id=igw_id,
                        region=region,
                        recommendation="Review Internet Gateway configuration",
                        impact="Unexpected configuration may lead to routing issues or security concerns",
                        evidence={
                            'attachments': attachments
                        }
                    ))
                
        except Exception as e:
            logger.error(f"Error checking Internet Gateways in region {region}: {str(e)}")
        
        return findings
    
    def _check_nat_gateways(self, ec2_client, region: str) -> List[Finding]:
        """Check NAT Gateways for security and cost optimization"""
        findings = []
        
        try:
            # Get all NAT Gateways
            nat_gateways_response = ec2_client.describe_nat_gateways()
            
            for nat_gw in nat_gateways_response.get('NatGateways', []):
                nat_gw_id = nat_gw['NatGatewayId']
                state = nat_gw.get('State')
                
                # Skip if not available
                if state != 'available':
                    continue
                
                # Check for NAT Gateways in public subnets (they should be)
                subnet_id = nat_gw.get('SubnetId')
                if subnet_id:
                    try:
                        subnet_response = ec2_client.describe_subnets(SubnetIds=[subnet_id])
                        subnet = subnet_response['Subnets'][0] if subnet_response['Subnets'] else {}
                        
                        # Check if the subnet has a route to an IGW (making it public)
                        route_table_response = ec2_client.describe_route_tables(
                            Filters=[{'Name': 'association.subnet-id', 'Values': [subnet_id]}]
                        )
                        
                        is_public = False
                        for rt in route_table_response.get('RouteTables', []):
                            for route in rt.get('Routes', []):
                                if route.get('GatewayId', '').startswith('igw-'):
                                    is_public = True
                                    break
                        
                        if not is_public:
                            findings.append(Finding(
                                title="NAT Gateway in Private Subnet",
                                description=f"NAT Gateway {nat_gw_id} appears to be in a private subnet.",
                                severity=Severity.HIGH,
                                category=Category.NETWORK,
                                resource_type="AWS::EC2::NatGateway",
                                resource_id=nat_gw_id,
                                region=region,
                                recommendation="NAT Gateways should be placed in public subnets",
                                impact="NAT Gateway may not function properly if not in a public subnet with internet access",
                                evidence={
                                    'subnet_id': subnet_id,
                                    'vpc_id': nat_gw.get('VpcId')
                                }
                            ))
                    except Exception as e:
                        logger.warning(f"Could not check subnet for NAT Gateway {nat_gw_id}: {str(e)}")
                
                # Check for multiple NAT Gateways in the same AZ (cost optimization)
                # This would require more complex logic to group by AZ
                
        except Exception as e:
            logger.error(f"Error checking NAT Gateways in region {region}: {str(e)}")
        
        return findings
    
    def _check_vpc_peering(self, ec2_client, region: str) -> List[Finding]:
        """Check VPC Peering connections for security issues"""
        findings = []
        
        try:
            # Get all VPC Peering connections
            peering_response = ec2_client.describe_vpc_peering_connections()
            
            for peering in peering_response.get('VpcPeeringConnections', []):
                peering_id = peering['VpcPeeringConnectionId']
                status = peering.get('Status', {}).get('Code')
                
                if status != 'active':
                    continue
                
                # Check for cross-account peering
                requester_owner = peering.get('RequesterVpcInfo', {}).get('OwnerId')
                accepter_owner = peering.get('AccepterVpcInfo', {}).get('OwnerId')
                
                if requester_owner != accepter_owner:
                    findings.append(Finding(
                        title="Cross-Account VPC Peering Connection",
                        description=f"VPC Peering connection {peering_id} connects VPCs from different AWS accounts.",
                        severity=Severity.MEDIUM,
                        category=Category.NETWORK,
                        resource_type="AWS::EC2::VPCPeeringConnection",
                        resource_id=peering_id,
                        region=region,
                        recommendation="Review cross-account peering connections for necessity and proper security controls",
                        impact="Cross-account connections increase the attack surface and require careful security management",
                        evidence={
                            'requester_account': requester_owner,
                            'accepter_account': accepter_owner,
                            'requester_vpc': peering.get('RequesterVpcInfo', {}).get('VpcId'),
                            'accepter_vpc': peering.get('AccepterVpcInfo', {}).get('VpcId')
                        }
                    ))
                
                # Check for peering without DNS resolution
                peering_options = peering.get('RequesterVpcInfo', {}).get('PeeringOptions', {})
                if not peering_options.get('AllowDnsResolutionFromRemoteVpc'):
                    findings.append(Finding(
                        title="VPC Peering Without DNS Resolution",
                        description=f"VPC Peering connection {peering_id} does not allow DNS resolution between VPCs.",
                        severity=Severity.LOW,
                        category=Category.CONFIGURATION,
                        resource_type="AWS::EC2::VPCPeeringConnection",
                        resource_id=peering_id,
                        region=region,
                        recommendation="Enable DNS resolution for better service discovery",
                        impact="Services may need to use IP addresses instead of DNS names, making configuration more complex",
                        evidence={
                            'peering_options': peering_options
                        }
                    ))
                
        except Exception as e:
            logger.error(f"Error checking VPC Peering in region {region}: {str(e)}")
        
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
    
    def _check_route_tables(self, ec2_client, region: str) -> List[Finding]:
        """Check route tables for security issues"""
        findings = []
        
        try:
            # Get all route tables
            route_tables_response = ec2_client.describe_route_tables()
            
            for rt in route_tables_response.get('RouteTables', []):
                rt_id = rt['RouteTableId']
                
                # Check for routes to 0.0.0.0/0 via IGW (identifies public subnets)
                for route in rt.get('Routes', []):
                    dest_cidr = route.get('DestinationCidrBlock', '')
                    gateway_id = route.get('GatewayId', '')
                    
                    # Check for overly broad routes to NAT instances
                    if dest_cidr == '0.0.0.0/0' and route.get('InstanceId'):
                        findings.append(Finding(
                            title="Route Table Using NAT Instance",
                            description=f"Route table {rt_id} uses a NAT instance instead of NAT Gateway.",
                            severity=Severity.MEDIUM,
                            category=Category.CONFIGURATION,
                            resource_type="AWS::EC2::RouteTable",
                            resource_id=rt_id,
                            region=region,
                            recommendation="Consider using NAT Gateway for better availability and performance",
                            impact="NAT instances require manual management, patching, and may become a single point of failure",
                            evidence={
                                'route': route,
                                'vpc_id': rt.get('VpcId')
                            }
                        ))
                    
                    # Check for routes to VPC peering with broad CIDRs
                    if route.get('VpcPeeringConnectionId') and dest_cidr.endswith('/0'):
                        findings.append(Finding(
                            title="Overly Broad VPC Peering Route",
                            description=f"Route table {rt_id} has a very broad route via VPC peering.",
                            severity=Severity.MEDIUM,
                            category=Category.NETWORK,
                            resource_type="AWS::EC2::RouteTable",
                            resource_id=rt_id,
                            region=region,
                            recommendation="Use specific CIDR blocks for VPC peering routes",
                            impact="Broad routing rules may expose more resources than intended across peered VPCs",
                            evidence={
                                'destination': dest_cidr,
                                'peering_connection': route.get('VpcPeeringConnectionId')
                            }
                        ))
                
                # Check for unused route tables
                associations = rt.get('Associations', [])
                if not associations or all(assoc.get('Main', False) for assoc in associations):
                    # Route table has no subnet associations (except maybe main)
                    if not any(assoc.get('Main', False) for assoc in associations):
                        findings.append(Finding(
                            title="Unused Route Table",
                            description=f"Route table {rt_id} is not associated with any subnets.",
                            severity=Severity.LOW,
                            category=Category.CONFIGURATION,
                            resource_type="AWS::EC2::RouteTable",
                            resource_id=rt_id,
                            region=region,
                            recommendation="Delete unused route tables to maintain a clean environment",
                            impact="Unused resources clutter the environment and may cause confusion",
                            evidence={
                                'vpc_id': rt.get('VpcId'),
                                'route_count': len(rt.get('Routes', []))
                            }
                        ))
                
        except Exception as e:
            logger.error(f"Error checking route tables in region {region}: {str(e)}")
        
        return findings
    
    def _check_dhcp_options(self, ec2_client, region: str) -> List[Finding]:
        """Check DHCP options for security issues"""
        findings = []
        
        try:
            # Get all DHCP options sets
            dhcp_options_response = ec2_client.describe_dhcp_options()
            
            for dhcp_options in dhcp_options_response.get('DhcpOptions', []):
                dhcp_options_id = dhcp_options['DhcpOptionsId']
                
                # Check DHCP configurations
                configurations = dhcp_options.get('DhcpConfigurations', [])
                
                for config in configurations:
                    key = config.get('Key')
                    values = [v.get('Value') for v in config.get('Values', [])]
                    
                    # Check for custom DNS servers
                    if key == 'domain-name-servers' and values:
                        # Check if using custom DNS servers (not AmazonProvidedDNS)
                        if 'AmazonProvidedDNS' not in values:
                            findings.append(Finding(
                                title="Custom DNS Servers Configured",
                                description=f"DHCP options set {dhcp_options_id} uses custom DNS servers: {', '.join(values)}",
                                severity=Severity.LOW,
                                category=Category.NETWORK,
                                resource_type="AWS::EC2::DHCPOptions",
                                resource_id=dhcp_options_id,
                                region=region,
                                recommendation="Ensure custom DNS servers are properly secured and monitored",
                                impact="Custom DNS servers may not provide the same security features as Amazon DNS and could be points of failure",
                                evidence={
                                    'dns_servers': values
                                }
                            ))
                    
                    # Check for custom domain names that might leak information
                    if key == 'domain-name' and values:
                        for domain in values:
                            if any(sensitive in domain.lower() for sensitive in ['internal', 'corp', 'private']):
                                findings.append(Finding(
                                    title="DHCP Domain Name May Leak Information",
                                    description=f"DHCP options set {dhcp_options_id} uses domain name that may reveal internal structure: {domain}",
                                    severity=Severity.LOW,
                                    category=Category.CONFIGURATION,
                                    resource_type="AWS::EC2::DHCPOptions",
                                    resource_id=dhcp_options_id,
                                    region=region,
                                    recommendation="Use generic domain names that don't reveal internal structure",
                                    impact="Domain names in DHCP can be discovered and may provide information useful for attacks",
                                    evidence={
                                        'domain_name': domain
                                    }
                                ))
                
        except Exception as e:
            logger.error(f"Error checking DHCP options in region {region}: {str(e)}")
        
        return findings
    
    def _check_vpn_connections(self, ec2_client, region: str) -> List[Finding]:
        """Check VPN connections for security issues"""
        findings = []
        
        try:
            # Get all VPN connections
            vpn_connections_response = ec2_client.describe_vpn_connections()
            
            for vpn in vpn_connections_response.get('VpnConnections', []):
                vpn_id = vpn['VpnConnectionId']
                state = vpn.get('State')
                
                if state not in ['available', 'attached']:
                    continue
                
                # Check VPN configuration
                options = vpn.get('Options', {})
                
                # Check for static routes only (no BGP)
                if options.get('StaticRoutesOnly'):
                    findings.append(Finding(
                        title="VPN Connection Using Static Routes",
                        description=f"VPN connection {vpn_id} uses static routes instead of dynamic routing (BGP).",
                        severity=Severity.LOW,
                        category=Category.NETWORK,
                        resource_type="AWS::EC2::VpnConnection",
                        resource_id=vpn_id,
                        region=region,
                        recommendation="Consider using BGP for dynamic routing and better failover",
                        impact="Static routes require manual updates and may not handle failover scenarios well",
                        evidence={
                            'customer_gateway_id': vpn.get('CustomerGatewayId'),
                            'vpn_gateway_id': vpn.get('VpnGatewayId')
                        }
                    ))
                
                # Check tunnel options
                tunnel_options = options.get('TunnelOptions', [])
                for i, tunnel in enumerate(tunnel_options):
                    # Check DPD timeout
                    dpd_timeout = tunnel.get('DpdTimeoutSeconds', 0)
                    if dpd_timeout > 30:
                        findings.append(Finding(
                            title="VPN Tunnel High DPD Timeout",
                            description=f"VPN connection {vpn_id} tunnel {i+1} has a high Dead Peer Detection timeout ({dpd_timeout}s).",
                            severity=Severity.LOW,
                            category=Category.NETWORK,
                            resource_type="AWS::EC2::VpnConnection",
                            resource_id=vpn_id,
                            region=region,
                            recommendation="Use lower DPD timeout (30s or less) for faster failover",
                            impact="High DPD timeout delays detection of connection failures and failover to backup tunnels",
                            evidence={
                                'tunnel_number': i+1,
                                'dpd_timeout_seconds': dpd_timeout
                            }
                        ))
                    
                    # Check Phase 1 lifetime
                    phase1_lifetime = tunnel.get('Phase1LifetimeSeconds', 0)
                    if phase1_lifetime > 28800:  # 8 hours
                        findings.append(Finding(
                            title="VPN Tunnel Long Phase 1 Lifetime",
                            description=f"VPN connection {vpn_id} tunnel {i+1} has a long Phase 1 lifetime ({phase1_lifetime}s).",
                            severity=Severity.LOW,
                            category=Category.NETWORK,
                            resource_type="AWS::EC2::VpnConnection",
                            resource_id=vpn_id,
                            region=region,
                            recommendation="Use shorter Phase 1 lifetime (8 hours or less) for better security",
                            impact="Long key lifetimes increase the window for cryptographic attacks",
                            evidence={
                                'tunnel_number': i+1,
                                'phase1_lifetime_seconds': phase1_lifetime
                            }
                        ))
                
        except Exception as e:
            logger.error(f"Error checking VPN connections in region {region}: {str(e)}")
        
        return findings
    
    def _get_resource_name(self, resource: Dict[str, Any]) -> str:
        """Get resource name from tags"""
        tags = resource.get('Tags', [])
        for tag in tags:
            if tag.get('Key') == 'Name':
                return tag.get('Value', 'Unknown')
        return 'Unknown'