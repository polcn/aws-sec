"""Tests for VPC Security Scanner"""

import pytest
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime, timezone

from src.scanners.vpc_scanner import VPCScanner
from src.models import Finding, Severity, Category, ComplianceFramework


class TestVPCScanner:
    """Test cases for VPC Scanner"""
    
    @pytest.fixture
    def vpc_scanner(self, mock_boto3_session):
        """Create a VPCScanner instance with mocked session"""
        return VPCScanner(mock_boto3_session, regions=['us-east-1'])
    
    @pytest.fixture
    def mock_ec2_client(self):
        """Create a mock EC2 client"""
        return Mock()
    
    @pytest.fixture
    def mock_logs_client(self):
        """Create a mock CloudWatch Logs client"""
        return Mock()
    
    def test_service_name(self, vpc_scanner):
        """Test service name property"""
        assert vpc_scanner.service_name == 'vpc'
    
    def test_check_vpcs_without_tags(self, vpc_scanner, mock_ec2_client):
        """Test detection of VPCs without tags"""
        # Mock VPC without tags
        mock_ec2_client.describe_vpcs.return_value = {
            'Vpcs': [{
                'VpcId': 'vpc-12345',
                'CidrBlock': '10.0.0.0/16',
                'IsDefault': False,
                'EnableDnsSupport': True,
                'EnableDnsHostnames': True
            }]
        }
        
        findings = vpc_scanner._check_vpcs(mock_ec2_client, 'us-east-1')
        
        assert len(findings) == 1
        assert findings[0].title == "VPC Without Tags"
        assert findings[0].severity == Severity.LOW
        assert findings[0].resource_id == 'vpc-12345'
    
    def test_check_vpcs_dns_settings(self, vpc_scanner, mock_ec2_client):
        """Test detection of VPCs with suboptimal DNS settings"""
        # Mock VPC with DNS issues
        mock_ec2_client.describe_vpcs.return_value = {
            'Vpcs': [{
                'VpcId': 'vpc-67890',
                'CidrBlock': '10.0.0.0/16',
                'IsDefault': False,
                'EnableDnsSupport': False,
                'EnableDnsHostnames': False,
                'Tags': [{'Key': 'Name', 'Value': 'test-vpc'}]
            }]
        }
        
        findings = vpc_scanner._check_vpcs(mock_ec2_client, 'us-east-1')
        
        assert len(findings) == 1
        assert findings[0].title == "VPC DNS Settings Not Optimal"
        assert findings[0].severity == Severity.LOW
        assert findings[0].resource_id == 'vpc-67890'
    
    def test_check_flow_logs_not_enabled(self, vpc_scanner, mock_ec2_client, mock_logs_client):
        """Test detection of VPCs without flow logs"""
        # Mock VPCs
        mock_ec2_client.describe_vpcs.return_value = {
            'Vpcs': [{
                'VpcId': 'vpc-noflowlogs',
                'CidrBlock': '10.0.0.0/16',
                'Tags': [{'Key': 'Name', 'Value': 'test-vpc'}]
            }]
        }
        
        # Mock flow logs (empty)
        mock_ec2_client.describe_flow_logs.return_value = {
            'FlowLogs': []
        }
        
        findings = vpc_scanner._check_flow_logs(mock_ec2_client, mock_logs_client, 'us-east-1')
        
        assert len(findings) == 1
        assert findings[0].title == "VPC Flow Logs Not Enabled"
        assert findings[0].severity == Severity.HIGH
        assert findings[0].resource_id == 'vpc-noflowlogs'
        assert ComplianceFramework.CIS in findings[0].compliance_frameworks
    
    def test_check_flow_logs_s3_destination(self, vpc_scanner, mock_ec2_client, mock_logs_client):
        """Test detection of flow logs with S3 destination"""
        # Mock VPCs
        mock_ec2_client.describe_vpcs.return_value = {
            'Vpcs': [{
                'VpcId': 'vpc-withflowlogs',
                'CidrBlock': '10.0.0.0/16'
            }]
        }
        
        # Mock flow logs with S3 destination
        mock_ec2_client.describe_flow_logs.return_value = {
            'FlowLogs': [{
                'FlowLogId': 'fl-12345',
                'ResourceId': 'vpc-withflowlogs',
                'FlowLogStatus': 'ACTIVE',
                'LogDestinationType': 's3',
                'LogDestination': 's3://my-bucket/flow-logs/',
                'TrafficType': 'ALL'
            }]
        }
        
        findings = vpc_scanner._check_flow_logs(mock_ec2_client, mock_logs_client, 'us-east-1')
        
        assert len(findings) == 1
        assert findings[0].title == "VPC Flow Logs S3 Encryption Status Unknown"
        assert findings[0].severity == Severity.LOW
        assert findings[0].category == Category.DATA_PROTECTION
    
    def test_check_detached_internet_gateways(self, vpc_scanner, mock_ec2_client):
        """Test detection of detached Internet Gateways"""
        # Mock detached IGW
        mock_ec2_client.describe_internet_gateways.return_value = {
            'InternetGateways': [{
                'InternetGatewayId': 'igw-12345',
                'Attachments': [],
                'Tags': [{'Key': 'Name', 'Value': 'unused-igw'}]
            }]
        }
        
        findings = vpc_scanner._check_internet_gateways(mock_ec2_client, 'us-east-1')
        
        assert len(findings) == 1
        assert findings[0].title == "Detached Internet Gateway"
        assert findings[0].severity == Severity.LOW
        assert findings[0].category == Category.COST_OPTIMIZATION
        assert findings[0].resource_id == 'igw-12345'
    
    def test_check_nat_gateway_in_private_subnet(self, vpc_scanner, mock_ec2_client):
        """Test detection of NAT Gateway in private subnet"""
        # Mock NAT Gateway
        mock_ec2_client.describe_nat_gateways.return_value = {
            'NatGateways': [{
                'NatGatewayId': 'nat-12345',
                'State': 'available',
                'SubnetId': 'subnet-private',
                'VpcId': 'vpc-12345'
            }]
        }
        
        # Mock subnet details
        mock_ec2_client.describe_subnets.return_value = {
            'Subnets': [{
                'SubnetId': 'subnet-private',
                'VpcId': 'vpc-12345'
            }]
        }
        
        # Mock route table without IGW route (private subnet)
        mock_ec2_client.describe_route_tables.return_value = {
            'RouteTables': [{
                'RouteTableId': 'rtb-12345',
                'Routes': [{
                    'DestinationCidrBlock': '10.0.0.0/16',
                    'GatewayId': 'local'
                }]
            }]
        }
        
        findings = vpc_scanner._check_nat_gateways(mock_ec2_client, 'us-east-1')
        
        assert len(findings) == 1
        assert findings[0].title == "NAT Gateway in Private Subnet"
        assert findings[0].severity == Severity.HIGH
        assert findings[0].resource_id == 'nat-12345'
    
    def test_check_cross_account_vpc_peering(self, vpc_scanner, mock_ec2_client):
        """Test detection of cross-account VPC peering"""
        # Mock cross-account peering
        mock_ec2_client.describe_vpc_peering_connections.return_value = {
            'VpcPeeringConnections': [{
                'VpcPeeringConnectionId': 'pcx-12345',
                'Status': {'Code': 'active'},
                'RequesterVpcInfo': {
                    'OwnerId': '111111111111',
                    'VpcId': 'vpc-requester'
                },
                'AccepterVpcInfo': {
                    'OwnerId': '222222222222',
                    'VpcId': 'vpc-accepter'
                }
            }]
        }
        
        findings = vpc_scanner._check_vpc_peering(mock_ec2_client, 'us-east-1')
        
        assert len(findings) == 2  # Cross-account and DNS resolution findings
        
        # Check cross-account finding
        cross_account_finding = next(f for f in findings if "Cross-Account" in f.title)
        assert cross_account_finding.title == "Cross-Account VPC Peering Connection"
        assert cross_account_finding.severity == Severity.MEDIUM
        assert cross_account_finding.resource_id == 'pcx-12345'
        
        # Check DNS resolution finding
        dns_finding = next(f for f in findings if "DNS Resolution" in f.title)
        assert dns_finding.title == "VPC Peering Without DNS Resolution"
        assert dns_finding.severity == Severity.LOW
    
    def test_check_route_table_nat_instance(self, vpc_scanner, mock_ec2_client):
        """Test detection of route tables using NAT instances"""
        # Mock route table with NAT instance
        mock_ec2_client.describe_route_tables.return_value = {
            'RouteTables': [{
                'RouteTableId': 'rtb-12345',
                'VpcId': 'vpc-12345',
                'Routes': [{
                    'DestinationCidrBlock': '0.0.0.0/0',
                    'InstanceId': 'i-nat12345'
                }],
                'Associations': [{
                    'RouteTableAssociationId': 'rtbassoc-12345',
                    'SubnetId': 'subnet-12345'
                }]
            }]
        }
        
        findings = vpc_scanner._check_route_tables(mock_ec2_client, 'us-east-1')
        
        assert len(findings) == 1  # Only NAT instance finding now
        assert findings[0].title == "Route Table Using NAT Instance"
        assert findings[0].severity == Severity.MEDIUM
        assert findings[0].resource_id == 'rtb-12345'
    
    def test_check_dhcp_custom_dns(self, vpc_scanner, mock_ec2_client):
        """Test detection of custom DNS servers in DHCP options"""
        # Mock DHCP options with custom DNS
        mock_ec2_client.describe_dhcp_options.return_value = {
            'DhcpOptions': [{
                'DhcpOptionsId': 'dopt-12345',
                'DhcpConfigurations': [{
                    'Key': 'domain-name-servers',
                    'Values': [
                        {'Value': '8.8.8.8'},
                        {'Value': '8.8.4.4'}
                    ]
                }]
            }]
        }
        
        findings = vpc_scanner._check_dhcp_options(mock_ec2_client, 'us-east-1')
        
        assert len(findings) == 1
        assert findings[0].title == "Custom DNS Servers Configured"
        assert findings[0].severity == Severity.LOW
        assert findings[0].resource_id == 'dopt-12345'
    
    def test_check_vpn_static_routes(self, vpc_scanner, mock_ec2_client):
        """Test detection of VPN connections using static routes"""
        # Mock VPN with static routes
        mock_ec2_client.describe_vpn_connections.return_value = {
            'VpnConnections': [{
                'VpnConnectionId': 'vpn-12345',
                'State': 'available',
                'CustomerGatewayId': 'cgw-12345',
                'VpnGatewayId': 'vgw-12345',
                'Options': {
                    'StaticRoutesOnly': True
                }
            }]
        }
        
        findings = vpc_scanner._check_vpn_connections(mock_ec2_client, 'us-east-1')
        
        assert len(findings) == 1
        assert findings[0].title == "VPN Connection Using Static Routes"
        assert findings[0].severity == Severity.LOW
        assert findings[0].resource_id == 'vpn-12345'
    
    def test_check_vpc_missing_endpoints(self, vpc_scanner, mock_ec2_client):
        """Test detection of VPCs missing recommended endpoints"""
        # Mock VPC
        mock_ec2_client.describe_vpcs.return_value = {
            'Vpcs': [{
                'VpcId': 'vpc-12345',
                'CidrBlock': '10.0.0.0/16'
            }]
        }
        
        # Mock no endpoints
        mock_ec2_client.describe_vpc_endpoints.return_value = {
            'VpcEndpoints': []
        }
        
        findings = vpc_scanner._check_vpc_endpoints(mock_ec2_client, 'us-east-1')
        
        assert len(findings) == 1
        assert findings[0].title == "VPC Missing Recommended Endpoints"
        assert findings[0].severity == Severity.LOW
        assert findings[0].resource_id == 'vpc-12345'
        assert 's3' in findings[0].evidence['missing_endpoints']
        assert 'dynamodb' in findings[0].evidence['missing_endpoints']
    
    def test_scan_with_error_handling(self, mock_boto3_session):
        """Test scan with error handling"""
        # First allow initialization to succeed
        sts_client = Mock()
        sts_client.get_caller_identity.return_value = {'Account': '123456789012'}
        
        # Set up client to return STS for initialization, then raise exception
        call_count = 0
        def client_side_effect(service_name, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 1 and service_name == 'sts':
                return sts_client
            raise Exception("Access denied")
        
        mock_boto3_session.client.side_effect = client_side_effect
        
        vpc_scanner = VPCScanner(mock_boto3_session, regions=['us-east-1'])
        findings = vpc_scanner.scan()
        
        assert len(findings) == 1
        assert findings[0].title == "VPC Scan Error"
        assert findings[0].severity == Severity.MEDIUM
        assert "Access denied" in findings[0].description