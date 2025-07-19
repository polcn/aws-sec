"""Tests for EC2 Security Scanner"""

import pytest
from unittest.mock import Mock, MagicMock, patch
from datetime import datetime, timezone

from src.scanners.ec2_scanner import EC2Scanner
from src.models import Finding, Severity, Category


class TestEC2Scanner:
    """Test cases for EC2Scanner"""
    
    @pytest.fixture
    def ec2_scanner(self, mock_boto3_session):
        """Create an EC2Scanner instance with mocked session"""
        # Mock STS for account ID retrieval
        mock_sts = Mock()
        mock_sts.get_caller_identity.return_value = {'Account': '123456789012'}
        
        # Mock EC2 for region retrieval
        mock_ec2 = Mock()
        mock_ec2.describe_regions.return_value = {
            'Regions': [{'RegionName': 'us-east-1'}]
        }
        
        # Configure session.client to return appropriate mocks
        def get_client(service_name, **kwargs):
            if service_name == 'sts':
                return mock_sts
            elif service_name == 'ec2':
                return mock_ec2
            else:
                return Mock()
        
        mock_boto3_session.client.side_effect = get_client
        
        scanner = EC2Scanner(session=mock_boto3_session)
        return scanner
    
    def test_service_name(self, ec2_scanner):
        """Test service name is correctly set"""
        assert ec2_scanner.service_name == 'ec2'
    
    def test_scan_no_resources(self, ec2_scanner, mock_boto3_session):
        """Test scanning with no EC2 resources"""
        # Mock EC2 client for scanning
        mock_ec2_client = Mock()
        
        # Mock empty responses
        mock_ec2_client.get_paginator.return_value.paginate.return_value = []
        mock_ec2_client.describe_vpcs.return_value = {'Vpcs': []}
        mock_ec2_client.describe_vpc_endpoints.return_value = {'VpcEndpoints': []}
        mock_ec2_client.describe_network_acls.return_value = {'NetworkAcls': []}
        mock_ec2_client.describe_addresses.return_value = {'Addresses': []}
        
        # Override the client method to return our mock
        def get_client(service_name, **kwargs):
            if service_name == 'ec2' and 'region_name' in kwargs:
                return mock_ec2_client
            elif service_name == 'sts':
                mock_sts = Mock()
                mock_sts.get_caller_identity.return_value = {'Account': '123456789012'}
                return mock_sts
            elif service_name == 'ec2':
                mock_ec2 = Mock()
                mock_ec2.describe_regions.return_value = {
                    'Regions': [{'RegionName': 'us-east-1'}]
                }
                return mock_ec2
            return Mock()
        
        mock_boto3_session.client.side_effect = get_client
        
        findings = ec2_scanner.scan()
        assert len(findings) == 0
    
    def test_check_instance_without_imdsv2(self, ec2_scanner, mock_boto3_session):
        """Test detection of instance not enforcing IMDSv2"""
        # Mock EC2 client
        mock_ec2_client = Mock()
        
        # Mock instance without IMDSv2 enforcement
        mock_paginator = Mock()
        mock_paginator.paginate.return_value = [{
            'Reservations': [{
                'Instances': [{
                    'InstanceId': 'i-1234567890abcdef0',
                    'State': {'Name': 'running'},
                    'MetadataOptions': {
                        'HttpTokens': 'optional',
                        'HttpPutResponseHopLimit': 1,
                        'HttpEndpoint': 'enabled'
                    },
                    'Tags': [{'Key': 'Name', 'Value': 'test-instance'}]
                }]
            }]
        }]
        
        mock_ec2_client.get_paginator.return_value = mock_paginator
        mock_ec2_client.describe_instance_attribute.return_value = {
            'DisableApiTermination': {'Value': False}
        }
        mock_ec2_client.describe_security_groups.return_value = {'SecurityGroups': []}
        mock_ec2_client.describe_volumes.return_value = {'Volumes': []}
        mock_ec2_client.describe_vpcs.return_value = {'Vpcs': []}
        mock_ec2_client.describe_vpc_endpoints.return_value = {'VpcEndpoints': []}
        mock_ec2_client.describe_network_acls.return_value = {'NetworkAcls': []}
        mock_ec2_client.describe_addresses.return_value = {'Addresses': []}
        
        # Override the client method
        def get_client(service_name, **kwargs):
            if service_name == 'ec2' and 'region_name' in kwargs:
                return mock_ec2_client
            elif service_name == 'sts':
                mock_sts = Mock()
                mock_sts.get_caller_identity.return_value = {'Account': '123456789012'}
                return mock_sts
            elif service_name == 'ec2':
                mock_ec2 = Mock()
                mock_ec2.describe_regions.return_value = {
                    'Regions': [{'RegionName': 'us-east-1'}]
                }
                return mock_ec2
            return Mock()
        
        mock_boto3_session.client.side_effect = get_client
        
        findings = ec2_scanner.scan()
        
        # Check for IMDSv2 finding
        imdsv2_findings = [f for f in findings if 'IMDSv2' in f.title]
        assert len(imdsv2_findings) == 1
        assert imdsv2_findings[0].severity == Severity.HIGH
        assert imdsv2_findings[0].resource_id == 'i-1234567890abcdef0'
    
    def test_check_instance_with_public_ip(self, ec2_scanner, mock_boto3_session):
        """Test detection of instance with public IP"""
        # Mock EC2 client
        mock_ec2_client = Mock()
        
        # Mock instance with public IP
        mock_paginator = Mock()
        mock_paginator.paginate.return_value = [{
            'Reservations': [{
                'Instances': [{
                    'InstanceId': 'i-1234567890abcdef0',
                    'State': {'Name': 'running'},
                    'PublicIpAddress': '54.123.45.67',
                    'PublicDnsName': 'ec2-54-123-45-67.compute-1.amazonaws.com',
                    'VpcId': 'vpc-12345',
                    'SubnetId': 'subnet-12345',
                    'MetadataOptions': {'HttpTokens': 'required'},
                    'Tags': [{'Key': 'Name', 'Value': 'test-instance'}]
                }]
            }]
        }]
        
        mock_ec2_client.get_paginator.return_value = mock_paginator
        mock_ec2_client.describe_instance_attribute.return_value = {
            'DisableApiTermination': {'Value': False}
        }
        mock_ec2_client.describe_security_groups.return_value = {'SecurityGroups': []}
        mock_ec2_client.describe_volumes.return_value = {'Volumes': []}
        mock_ec2_client.describe_vpcs.return_value = {'Vpcs': []}
        mock_ec2_client.describe_vpc_endpoints.return_value = {'VpcEndpoints': []}
        mock_ec2_client.describe_network_acls.return_value = {'NetworkAcls': []}
        mock_ec2_client.describe_addresses.return_value = {'Addresses': []}
        
        # Override the client method
        def get_client(service_name, **kwargs):
            if service_name == 'ec2' and 'region_name' in kwargs:
                return mock_ec2_client
            elif service_name == 'sts':
                mock_sts = Mock()
                mock_sts.get_caller_identity.return_value = {'Account': '123456789012'}
                return mock_sts
            elif service_name == 'ec2':
                mock_ec2 = Mock()
                mock_ec2.describe_regions.return_value = {
                    'Regions': [{'RegionName': 'us-east-1'}]
                }
                return mock_ec2
            return Mock()
        
        mock_boto3_session.client.side_effect = get_client
        
        findings = ec2_scanner.scan()
        
        # Check for public IP finding
        public_ip_findings = [f for f in findings if 'Public IP' in f.title]
        assert len(public_ip_findings) == 1
        assert public_ip_findings[0].severity == Severity.MEDIUM
        assert public_ip_findings[0].evidence['public_ip'] == '54.123.45.67'
    
    def test_check_security_group_overly_permissive(self, ec2_scanner, mock_boto3_session):
        """Test detection of overly permissive security group"""
        # Mock EC2 client
        mock_ec2_client = Mock()
        
        # Mock instances paginator
        mock_instances_paginator = Mock()
        mock_instances_paginator.paginate.return_value = []
        
        # Mock security groups paginator with overly permissive rule
        mock_sg_paginator = Mock()
        mock_sg_paginator.paginate.return_value = [{
            'SecurityGroups': [{
                'GroupId': 'sg-12345',
                'GroupName': 'test-sg',
                'VpcId': 'vpc-12345',
                'IpPermissions': [{
                    'IpProtocol': '-1',
                    'FromPort': -1,
                    'ToPort': -1,
                    'IpRanges': [{'CidrIp': '0.0.0.0/0'}]
                }],
                'IpPermissionsEgress': []
            }]
        }]
        
        # Configure paginators
        def get_paginator(operation):
            if operation == 'describe_instances':
                return mock_instances_paginator
            elif operation == 'describe_security_groups':
                return mock_sg_paginator
            elif operation == 'describe_volumes':
                mock_volumes_paginator = Mock()
                mock_volumes_paginator.paginate.return_value = []
                return mock_volumes_paginator
            return Mock()
        
        mock_ec2_client.get_paginator.side_effect = get_paginator
        mock_ec2_client.describe_vpcs.return_value = {'Vpcs': []}
        mock_ec2_client.describe_vpc_endpoints.return_value = {'VpcEndpoints': []}
        mock_ec2_client.describe_network_acls.return_value = {'NetworkAcls': []}
        mock_ec2_client.describe_addresses.return_value = {'Addresses': []}
        
        # Override the client method
        def get_client(service_name, **kwargs):
            if service_name == 'ec2' and 'region_name' in kwargs:
                return mock_ec2_client
            elif service_name == 'sts':
                mock_sts = Mock()
                mock_sts.get_caller_identity.return_value = {'Account': '123456789012'}
                return mock_sts
            elif service_name == 'ec2':
                mock_ec2 = Mock()
                mock_ec2.describe_regions.return_value = {
                    'Regions': [{'RegionName': 'us-east-1'}]
                }
                return mock_ec2
            return Mock()
        
        mock_boto3_session.client.side_effect = get_client
        
        findings = ec2_scanner.scan()
        
        # Check for security group finding
        sg_findings = [f for f in findings if 'Security Group' in f.title]
        assert len(sg_findings) == 1
        assert sg_findings[0].severity == Severity.CRITICAL
        assert 'sg-12345' in sg_findings[0].resource_id
    
    def test_check_unencrypted_ebs_volume(self, ec2_scanner, mock_boto3_session):
        """Test detection of unencrypted EBS volume"""
        # Mock EC2 client
        mock_ec2_client = Mock()
        
        # Mock empty instances
        mock_instances_paginator = Mock()
        mock_instances_paginator.paginate.return_value = []
        
        # Mock empty security groups
        mock_sg_paginator = Mock()
        mock_sg_paginator.paginate.return_value = []
        
        # Mock unencrypted volume
        mock_volumes_paginator = Mock()
        mock_volumes_paginator.paginate.return_value = [{
            'Volumes': [{
                'VolumeId': 'vol-12345',
                'Encrypted': False,
                'VolumeType': 'gp3',
                'Size': 100,
                'State': 'in-use',
                'Attachments': [{'InstanceId': 'i-12345'}]
            }]
        }]
        
        # Configure paginators
        def get_paginator(operation):
            if operation == 'describe_instances':
                return mock_instances_paginator
            elif operation == 'describe_security_groups':
                return mock_sg_paginator
            elif operation == 'describe_volumes':
                return mock_volumes_paginator
            return Mock()
        
        mock_ec2_client.get_paginator.side_effect = get_paginator
        mock_ec2_client.describe_vpcs.return_value = {'Vpcs': []}
        mock_ec2_client.describe_vpc_endpoints.return_value = {'VpcEndpoints': []}
        mock_ec2_client.describe_network_acls.return_value = {'NetworkAcls': []}
        mock_ec2_client.describe_addresses.return_value = {'Addresses': []}
        
        # Override the client method
        def get_client(service_name, **kwargs):
            if service_name == 'ec2' and 'region_name' in kwargs:
                return mock_ec2_client
            elif service_name == 'sts':
                mock_sts = Mock()
                mock_sts.get_caller_identity.return_value = {'Account': '123456789012'}
                return mock_sts
            elif service_name == 'ec2':
                mock_ec2 = Mock()
                mock_ec2.describe_regions.return_value = {
                    'Regions': [{'RegionName': 'us-east-1'}]
                }
                return mock_ec2
            return Mock()
        
        mock_boto3_session.client.side_effect = get_client
        
        findings = ec2_scanner.scan()
        
        # Check for EBS encryption finding
        ebs_findings = [f for f in findings if 'EBS Volume Not Encrypted' in f.title]
        assert len(ebs_findings) == 1
        assert ebs_findings[0].severity == Severity.HIGH
        assert ebs_findings[0].resource_id == 'vol-12345'
    
    def test_check_unassociated_elastic_ip(self, ec2_scanner, mock_boto3_session):
        """Test detection of unassociated Elastic IP"""
        # Mock EC2 client
        mock_ec2_client = Mock()
        
        # Mock empty resources
        mock_instances_paginator = Mock()
        mock_instances_paginator.paginate.return_value = []
        mock_sg_paginator = Mock()
        mock_sg_paginator.paginate.return_value = []
        mock_volumes_paginator = Mock()
        mock_volumes_paginator.paginate.return_value = []
        
        def get_paginator(operation):
            if operation == 'describe_instances':
                return mock_instances_paginator
            elif operation == 'describe_security_groups':
                return mock_sg_paginator
            elif operation == 'describe_volumes':
                return mock_volumes_paginator
            return Mock()
        
        mock_ec2_client.get_paginator.side_effect = get_paginator
        mock_ec2_client.describe_vpcs.return_value = {'Vpcs': []}
        mock_ec2_client.describe_vpc_endpoints.return_value = {'VpcEndpoints': []}
        mock_ec2_client.describe_network_acls.return_value = {'NetworkAcls': []}
        
        # Mock unassociated Elastic IP
        mock_ec2_client.describe_addresses.return_value = {
            'Addresses': [{
                'PublicIp': '52.123.45.67',
                'AllocationId': 'eipalloc-12345',
                'Domain': 'vpc'
                # No InstanceId or NetworkInterfaceId
            }]
        }
        
        # Override the client method
        def get_client(service_name, **kwargs):
            if service_name == 'ec2' and 'region_name' in kwargs:
                return mock_ec2_client
            elif service_name == 'sts':
                mock_sts = Mock()
                mock_sts.get_caller_identity.return_value = {'Account': '123456789012'}
                return mock_sts
            elif service_name == 'ec2':
                mock_ec2 = Mock()
                mock_ec2.describe_regions.return_value = {
                    'Regions': [{'RegionName': 'us-east-1'}]
                }
                return mock_ec2
            return Mock()
        
        mock_boto3_session.client.side_effect = get_client
        
        findings = ec2_scanner.scan()
        
        # Check for Elastic IP finding
        eip_findings = [f for f in findings if 'Elastic IP' in f.title]
        assert len(eip_findings) == 1
        assert eip_findings[0].severity == Severity.LOW
        assert eip_findings[0].category == Category.COST_OPTIMIZATION
    
    def test_scan_with_error_handling(self, ec2_scanner, mock_boto3_session):
        """Test error handling during scan"""
        # Override the client method to raise exception when creating EC2 client for scanning
        def get_client(service_name, **kwargs):
            if service_name == 'ec2' and 'region_name' in kwargs:
                # Raise exception when trying to create EC2 client for a region
                raise Exception("API Error")
            elif service_name == 'sts':
                mock_sts = Mock()
                mock_sts.get_caller_identity.return_value = {'Account': '123456789012'}
                return mock_sts
            elif service_name == 'ec2':
                mock_ec2 = Mock()
                mock_ec2.describe_regions.return_value = {
                    'Regions': [{'RegionName': 'us-east-1'}]
                }
                return mock_ec2
            return Mock()
        
        mock_boto3_session.client.side_effect = get_client
        
        findings = ec2_scanner.scan()
        
        # Should have error finding
        assert len(findings) == 1
        assert 'EC2 Scan Error' in findings[0].title
        assert findings[0].severity == Severity.MEDIUM