#!/usr/bin/env python3
"""
Unit tests for S3 Scanner
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
from botocore.exceptions import ClientError
from datetime import datetime, timezone

from src.scanners.s3_scanner import S3Scanner
from src.models import Finding, Severity, Category, ComplianceFramework


class TestS3Scanner:
    """Test cases for S3Scanner"""
    
    @pytest.fixture
    def mock_session(self):
        """Create a mock boto3 session"""
        session = Mock()
        return session
    
    @pytest.fixture
    def s3_scanner(self, mock_session):
        """Create an S3Scanner instance with mocked session"""
        # Mock STS for account ID retrieval
        mock_sts = Mock()
        mock_sts.get_caller_identity.return_value = {'Account': '123456789012'}
        
        # Mock EC2 for region retrieval
        mock_ec2 = Mock()
        mock_ec2.describe_regions.return_value = {
            'Regions': [{'RegionName': 'us-east-1'}, {'RegionName': 'us-west-2'}]
        }
        
        # Configure session.client to return appropriate mocks
        def get_client(service_name, **kwargs):
            if service_name == 'sts':
                return mock_sts
            elif service_name == 'ec2':
                return mock_ec2
            else:
                return Mock()
        
        mock_session.client.side_effect = get_client
        
        scanner = S3Scanner(session=mock_session)
        return scanner
    
    @pytest.fixture
    def mock_s3_client(self):
        """Create a mock S3 client"""
        return Mock()
    
    def test_service_name(self, s3_scanner):
        """Test service_name property"""
        assert s3_scanner.service_name == "s3"
    
    def test_scan_no_buckets(self, s3_scanner, mock_s3_client):
        """Test scan when no buckets exist"""
        # Setup
        original_side_effect = s3_scanner.session.client.side_effect
        
        def get_client_with_s3(service_name, **kwargs):
            if service_name == 's3':
                return mock_s3_client
            else:
                return original_side_effect(service_name, **kwargs)
        
        s3_scanner.session.client.side_effect = get_client_with_s3
        mock_s3_client.list_buckets.return_value = {'Buckets': []}
        
        # Execute
        findings = s3_scanner.scan()
        
        # Assert
        assert findings == []
        mock_s3_client.list_buckets.assert_called_once()
    
    def test_scan_with_client_error(self, s3_scanner, mock_s3_client):
        """Test scan handles ClientError gracefully"""
        # Setup
        original_side_effect = s3_scanner.session.client.side_effect
        
        def get_client_with_s3(service_name, **kwargs):
            if service_name == 's3':
                return mock_s3_client
            else:
                return original_side_effect(service_name, **kwargs)
        
        s3_scanner.session.client.side_effect = get_client_with_s3
        error_response = {'Error': {'Code': 'AccessDenied', 'Message': 'Access Denied'}}
        mock_s3_client.list_buckets.side_effect = ClientError(error_response, 'ListBuckets')
        
        # Execute
        findings = s3_scanner.scan()
        
        # Assert
        assert findings == []
    
    def test_get_bucket_region_us_east_1(self, s3_scanner, mock_s3_client):
        """Test getting bucket region for us-east-1"""
        # Setup
        mock_s3_client.get_bucket_location.return_value = {'LocationConstraint': None}
        
        # Execute
        region = s3_scanner._get_bucket_region(mock_s3_client, 'test-bucket')
        
        # Assert
        assert region == 'us-east-1'
        mock_s3_client.get_bucket_location.assert_called_once_with(Bucket='test-bucket')
    
    def test_get_bucket_region_other_region(self, s3_scanner, mock_s3_client):
        """Test getting bucket region for non-us-east-1 region"""
        # Setup
        mock_s3_client.get_bucket_location.return_value = {'LocationConstraint': 'eu-west-1'}
        
        # Execute
        region = s3_scanner._get_bucket_region(mock_s3_client, 'test-bucket')
        
        # Assert
        assert region == 'eu-west-1'
    
    def test_get_bucket_region_error(self, s3_scanner, mock_s3_client):
        """Test getting bucket region with error"""
        # Setup
        error_response = {'Error': {'Code': 'NoSuchBucket', 'Message': 'Bucket not found'}}
        mock_s3_client.get_bucket_location.side_effect = ClientError(error_response, 'GetBucketLocation')
        
        # Execute
        region = s3_scanner._get_bucket_region(mock_s3_client, 'test-bucket')
        
        # Assert
        assert region is None
    
    def test_check_bucket_encryption_not_enabled(self, s3_scanner, mock_s3_client):
        """Test checking bucket without encryption"""
        # Setup
        error_response = {'Error': {'Code': 'ServerSideEncryptionConfigurationNotFoundError'}}
        mock_s3_client.get_bucket_encryption.side_effect = ClientError(error_response, 'GetBucketEncryption')
        
        # Execute
        findings = s3_scanner._check_bucket_encryption(mock_s3_client, 'test-bucket', 'us-east-1')
        
        # Assert
        assert len(findings) == 1
        finding = findings[0]
        assert finding.severity == Severity.HIGH
        assert finding.category == Category.DATA_PROTECTION
        assert finding.resource_id == 'test-bucket'
        assert finding.title == "S3 Bucket Without Encryption"
        assert finding.automated_remediation_available is True
    
    def test_check_bucket_encryption_sse_s3(self, s3_scanner, mock_s3_client):
        """Test checking bucket with SSE-S3 encryption"""
        # Setup
        mock_s3_client.get_bucket_encryption.return_value = {
            'ServerSideEncryptionConfiguration': {
                'Rules': [{
                    'ApplyServerSideEncryptionByDefault': {
                        'SSEAlgorithm': 'AES256'
                    }
                }]
            }
        }
        
        # Execute
        findings = s3_scanner._check_bucket_encryption(mock_s3_client, 'test-bucket', 'us-east-1')
        
        # Assert
        assert len(findings) == 1
        finding = findings[0]
        assert finding.severity == Severity.LOW
        assert finding.title == "S3 Bucket Using SSE-S3 Instead of SSE-KMS"
    
    def test_check_bucket_encryption_sse_kms(self, s3_scanner, mock_s3_client):
        """Test checking bucket with SSE-KMS encryption"""
        # Setup
        mock_s3_client.get_bucket_encryption.return_value = {
            'ServerSideEncryptionConfiguration': {
                'Rules': [{
                    'ApplyServerSideEncryptionByDefault': {
                        'SSEAlgorithm': 'aws:kms',
                        'KMSMasterKeyID': 'arn:aws:kms:us-east-1:123456789012:key/12345'
                    }
                }]
            }
        }
        
        # Execute
        findings = s3_scanner._check_bucket_encryption(mock_s3_client, 'test-bucket', 'us-east-1')
        
        # Assert
        assert len(findings) == 0  # No findings for KMS encryption
    
    def test_check_bucket_public_access_not_configured(self, s3_scanner, mock_s3_client):
        """Test checking bucket without public access block"""
        # Setup
        error_response = {'Error': {'Code': 'NoSuchPublicAccessBlockConfiguration'}}
        mock_s3_client.get_public_access_block.side_effect = ClientError(error_response, 'GetPublicAccessBlock')
        
        # Execute
        findings = s3_scanner._check_bucket_public_access(mock_s3_client, 'test-bucket', 'us-east-1')
        
        # Assert
        assert len(findings) == 1
        finding = findings[0]
        assert finding.severity == Severity.HIGH
        assert finding.title == "S3 Bucket Without Public Access Block"
    
    def test_check_bucket_public_access_partial_block(self, s3_scanner, mock_s3_client):
        """Test checking bucket with partial public access block"""
        # Setup
        mock_s3_client.get_public_access_block.return_value = {
            'PublicAccessBlockConfiguration': {
                'BlockPublicAcls': True,
                'IgnorePublicAcls': False,
                'BlockPublicPolicy': True,
                'RestrictPublicBuckets': False
            }
        }
        
        # Execute
        findings = s3_scanner._check_bucket_public_access(mock_s3_client, 'test-bucket', 'us-east-1')
        
        # Assert
        assert len(findings) == 1
        finding = findings[0]
        assert finding.severity == Severity.HIGH
        assert finding.title == "S3 Bucket Public Access Not Fully Blocked"
        assert 'IgnorePublicAcls' in finding.evidence['missing_blocks']
        assert 'RestrictPublicBuckets' in finding.evidence['missing_blocks']
    
    def test_check_bucket_public_access_fully_blocked(self, s3_scanner, mock_s3_client):
        """Test checking bucket with all public access blocked"""
        # Setup
        mock_s3_client.get_public_access_block.return_value = {
            'PublicAccessBlockConfiguration': {
                'BlockPublicAcls': True,
                'IgnorePublicAcls': True,
                'BlockPublicPolicy': True,
                'RestrictPublicBuckets': True
            }
        }
        
        # Execute
        findings = s3_scanner._check_bucket_public_access(mock_s3_client, 'test-bucket', 'us-east-1')
        
        # Assert
        assert len(findings) == 0
    
    def test_check_bucket_versioning_disabled(self, s3_scanner, mock_s3_client):
        """Test checking bucket with versioning disabled"""
        # Setup
        mock_s3_client.get_bucket_versioning.return_value = {'Status': 'Disabled'}
        
        # Execute
        findings = s3_scanner._check_bucket_versioning(mock_s3_client, 'test-bucket', 'us-east-1')
        
        # Assert
        assert len(findings) == 1
        finding = findings[0]
        assert finding.severity == Severity.MEDIUM
        assert finding.title == "S3 Bucket Versioning Not Enabled"
    
    def test_check_bucket_versioning_enabled(self, s3_scanner, mock_s3_client):
        """Test checking bucket with versioning enabled"""
        # Setup
        mock_s3_client.get_bucket_versioning.return_value = {'Status': 'Enabled'}
        
        # Execute
        findings = s3_scanner._check_bucket_versioning(mock_s3_client, 'test-bucket', 'us-east-1')
        
        # Assert
        assert len(findings) == 0
    
    def test_check_bucket_logging_disabled(self, s3_scanner, mock_s3_client):
        """Test checking bucket without logging"""
        # Setup
        mock_s3_client.get_bucket_logging.return_value = {}
        
        # Execute
        findings = s3_scanner._check_bucket_logging(mock_s3_client, 'test-bucket', 'us-east-1')
        
        # Assert
        assert len(findings) == 1
        finding = findings[0]
        assert finding.severity == Severity.MEDIUM
        assert finding.category == Category.LOGGING
        assert finding.title == "S3 Bucket Access Logging Not Enabled"
    
    def test_check_bucket_logging_enabled(self, s3_scanner, mock_s3_client):
        """Test checking bucket with logging enabled"""
        # Setup
        mock_s3_client.get_bucket_logging.return_value = {
            'LoggingEnabled': {
                'TargetBucket': 'log-bucket',
                'TargetPrefix': 'logs/'
            }
        }
        
        # Execute
        findings = s3_scanner._check_bucket_logging(mock_s3_client, 'test-bucket', 'us-east-1')
        
        # Assert
        assert len(findings) == 0
    
    def test_check_bucket_lifecycle_not_configured(self, s3_scanner, mock_s3_client):
        """Test checking bucket without lifecycle policies"""
        # Setup
        error_response = {'Error': {'Code': 'NoSuchLifecycleConfiguration'}}
        mock_s3_client.get_bucket_lifecycle_configuration.side_effect = ClientError(error_response, 'GetBucketLifecycle')
        
        # Execute
        findings = s3_scanner._check_bucket_lifecycle(mock_s3_client, 'test-bucket', 'us-east-1')
        
        # Assert
        assert len(findings) == 1
        finding = findings[0]
        assert finding.severity == Severity.LOW
        assert finding.category == Category.COST_OPTIMIZATION
        assert finding.title == "S3 Bucket Without Lifecycle Policy"
    
    def test_check_bucket_policy_public_access(self, s3_scanner, mock_s3_client):
        """Test checking bucket policy with public access"""
        # Setup
        mock_s3_client.get_bucket_policy.return_value = {
            'Policy': '''{
                "Version": "2012-10-17",
                "Statement": [{
                    "Sid": "PublicRead",
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": "s3:GetObject",
                    "Resource": "arn:aws:s3:::test-bucket/*"
                }]
            }'''
        }
        
        # Execute
        findings = s3_scanner._check_bucket_policy(mock_s3_client, 'test-bucket', 'us-east-1')
        
        # Assert
        assert len(findings) == 2  # Public access + no SSL enforcement
        public_finding = next(f for f in findings if "Public Access" in f.title)
        assert public_finding.severity == Severity.HIGH
        assert public_finding.title == "S3 Bucket Policy Allows Public Access"
    
    def test_check_bucket_policy_no_ssl(self, s3_scanner, mock_s3_client):
        """Test checking bucket policy without SSL enforcement"""
        # Setup
        mock_s3_client.get_bucket_policy.return_value = {
            'Policy': '''{
                "Version": "2012-10-17",
                "Statement": [{
                    "Sid": "AllowSpecificUser",
                    "Effect": "Allow",
                    "Principal": {"AWS": "arn:aws:iam::123456789012:user/test"},
                    "Action": "s3:GetObject",
                    "Resource": "arn:aws:s3:::test-bucket/*"
                }]
            }'''
        }
        
        # Execute
        findings = s3_scanner._check_bucket_policy(mock_s3_client, 'test-bucket', 'us-east-1')
        
        # Assert
        assert len(findings) == 1
        finding = findings[0]
        assert finding.severity == Severity.MEDIUM
        assert finding.title == "S3 Bucket Policy Does Not Enforce SSL"
    
    def test_check_bucket_acl_public_access(self, s3_scanner, mock_s3_client):
        """Test checking bucket ACL with public access"""
        # Setup
        mock_s3_client.get_bucket_acl.return_value = {
            'Grants': [{
                'Grantee': {
                    'Type': 'Group',
                    'URI': 'http://acs.amazonaws.com/groups/global/AllUsers'
                },
                'Permission': 'READ'
            }]
        }
        
        # Execute
        findings = s3_scanner._check_bucket_acl(mock_s3_client, 'test-bucket', 'us-east-1')
        
        # Assert
        assert len(findings) == 1
        finding = findings[0]
        assert finding.severity == Severity.HIGH
        assert finding.category == Category.ACCESS_CONTROL
        assert finding.title == "S3 Bucket ACL Allows Public Access"
        assert finding.evidence['grantee'] == 'AllUsers'
    
    def test_check_object_lock_compliance_bucket_without_lock(self, s3_scanner, mock_s3_client):
        """Test checking compliance bucket without object lock"""
        # Setup
        error_response = {'Error': {'Code': 'ObjectLockConfigurationNotFoundError'}}
        mock_s3_client.get_object_lock_configuration.side_effect = ClientError(error_response, 'GetObjectLock')
        
        # Execute
        findings = s3_scanner._check_object_lock(mock_s3_client, 'backup-bucket', 'us-east-1')
        
        # Assert
        assert len(findings) == 1
        finding = findings[0]
        assert finding.severity == Severity.MEDIUM
        assert finding.title == "Compliance Bucket Without Object Lock"
        assert 'backup' in finding.evidence['compliance_keywords_found']
    
    def test_check_object_lock_non_compliance_bucket(self, s3_scanner, mock_s3_client):
        """Test checking non-compliance bucket (should not check object lock)"""
        # Execute
        findings = s3_scanner._check_object_lock(mock_s3_client, 'my-app-bucket', 'us-east-1')
        
        # Assert
        assert len(findings) == 0
    
    def test_full_scan_integration(self, s3_scanner, mock_s3_client):
        """Test full scan with multiple buckets and various configurations"""
        # Setup - Need to reconfigure the session client to return S3 client
        original_side_effect = s3_scanner.session.client.side_effect
        
        def get_client_for_scan(service_name, **kwargs):
            if service_name == 's3':
                return mock_s3_client
            else:
                return original_side_effect(service_name, **kwargs)
        
        s3_scanner.session.client.side_effect = get_client_for_scan
        
        # Mock list_buckets
        mock_s3_client.list_buckets.return_value = {
            'Buckets': [
                {'Name': 'test-bucket-1', 'CreationDate': datetime.now(timezone.utc)},
                {'Name': 'compliance-bucket', 'CreationDate': datetime.now(timezone.utc)}
            ]
        }
        
        # Mock bucket locations
        mock_s3_client.get_bucket_location.side_effect = [
            {'LocationConstraint': None},  # test-bucket-1
            {'LocationConstraint': 'eu-west-1'}  # compliance-bucket
        ]
        
        # Create regional client mock
        regional_client = Mock()
        
        # Update get_client_for_scan to return regional client for eu-west-1
        def get_client_for_scan_with_region(service_name, **kwargs):
            if service_name == 's3':
                if kwargs.get('region_name') == 'eu-west-1':
                    return regional_client
                else:
                    return mock_s3_client
            else:
                return original_side_effect(service_name, **kwargs)
        
        s3_scanner.session.client.side_effect = get_client_for_scan_with_region
        
        # Mock various bucket checks for test-bucket-1 (using main client)
        mock_s3_client.get_bucket_encryption.side_effect = [
            ClientError({'Error': {'Code': 'ServerSideEncryptionConfigurationNotFoundError'}}, 'GetBucketEncryption')
        ]
        mock_s3_client.get_public_access_block.side_effect = [
            {'PublicAccessBlockConfiguration': {'BlockPublicAcls': True, 'IgnorePublicAcls': False, 
                                               'BlockPublicPolicy': True, 'RestrictPublicBuckets': True}}
        ]
        mock_s3_client.get_bucket_versioning.side_effect = [{'Status': 'Disabled'}]
        mock_s3_client.get_bucket_logging.side_effect = [{}]
        mock_s3_client.get_bucket_lifecycle_configuration.side_effect = [
            ClientError({'Error': {'Code': 'NoSuchLifecycleConfiguration'}}, 'GetBucketLifecycle')
        ]
        mock_s3_client.get_bucket_policy.side_effect = [
            ClientError({'Error': {'Code': 'NoSuchBucketPolicy'}}, 'GetBucketPolicy')
        ]
        mock_s3_client.get_bucket_acl.side_effect = [{'Grants': []}]
        mock_s3_client.get_object_lock_configuration.side_effect = [
            ClientError({'Error': {'Code': 'ObjectLockConfigurationNotFoundError'}}, 'GetObjectLock')
        ]
        
        # Mock checks for compliance-bucket (using regional client)
        regional_client.get_bucket_encryption.return_value = {
            'ServerSideEncryptionConfiguration': {
                'Rules': [{'ApplyServerSideEncryptionByDefault': {'SSEAlgorithm': 'AES256'}}]
            }
        }
        regional_client.get_public_access_block.return_value = {
            'PublicAccessBlockConfiguration': {
                'BlockPublicAcls': True, 'IgnorePublicAcls': True,
                'BlockPublicPolicy': True, 'RestrictPublicBuckets': True
            }
        }
        regional_client.get_bucket_versioning.return_value = {'Status': 'Enabled'}
        regional_client.get_bucket_logging.return_value = {
            'LoggingEnabled': {'TargetBucket': 'log-bucket', 'TargetPrefix': 'logs/'}
        }
        regional_client.get_bucket_lifecycle_configuration.return_value = {
            'Rules': [{'ID': 'rule1', 'Status': 'Enabled'}]
        }
        regional_client.get_bucket_policy.side_effect = [
            ClientError({'Error': {'Code': 'NoSuchBucketPolicy'}}, 'GetBucketPolicy')
        ]
        regional_client.get_bucket_acl.return_value = {'Grants': []}
        regional_client.get_object_lock_configuration.side_effect = [
            ClientError({'Error': {'Code': 'ObjectLockConfigurationNotFoundError'}}, 'GetObjectLock')
        ]
        
        # Execute
        findings = s3_scanner.scan()
        
        # Assert
        assert len(findings) > 0
        
        # Check for expected findings
        encryption_findings = [f for f in findings if "Encryption" in f.title]
        versioning_findings = [f for f in findings if "Versioning" in f.title]
        logging_findings = [f for f in findings if "Logging" in f.title]
        
        assert len(encryption_findings) >= 1  # test-bucket-1 no encryption, compliance-bucket SSE-S3
        assert len(versioning_findings) == 1  # test-bucket-1 versioning disabled
        assert len(logging_findings) == 1  # test-bucket-1 logging disabled