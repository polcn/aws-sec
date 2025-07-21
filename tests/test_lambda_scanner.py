"""Tests for Lambda Security Scanner"""

import json
import pytest
from unittest.mock import Mock, patch
from botocore.exceptions import ClientError

from src.scanners.lambda_scanner import LambdaScanner
from src.models import Severity, Category


@pytest.fixture
def mock_session():
    """Create a mock boto3 session"""
    session = Mock()
    
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
    
    session.client.side_effect = get_client
    
    return session


@pytest.fixture
def lambda_scanner(mock_session):
    """Create a Lambda scanner instance with mock session"""
    return LambdaScanner(mock_session, regions=['us-east-1'])


@pytest.fixture
def sample_function():
    """Sample Lambda function configuration"""
    return {
        'FunctionName': 'test-function',
        'FunctionArn': 'arn:aws:lambda:us-east-1:123456789012:function:test-function',
        'Runtime': 'python3.9',
        'Handler': 'index.handler',
        'CodeSize': 1024,
        'Description': 'Test function',
        'Timeout': 3,
        'MemorySize': 128,
        'LastModified': '2024-01-01T00:00:00.000+0000',
        'Version': '$LATEST',
        'Environment': {
            'Variables': {
                'ENV': 'test',
                'API_KEY': 'some-key-value'
            }
        },
        'TracingConfig': {
            'Mode': 'PassThrough'
        },
        'DeadLetterConfig': {}
    }


class TestLambdaScanner:
    def test_service_name(self, lambda_scanner):
        """Test service name property"""
        assert lambda_scanner.service_name == "lambda"
    
    def test_scan_with_no_functions(self, lambda_scanner, mock_session):
        """Test scanning when no functions exist"""
        mock_client = Mock()
        mock_paginator = Mock()
        mock_paginator.paginate.return_value = [
            {'Functions': []}
        ]
        mock_client.get_paginator.return_value = mock_paginator
        
        def get_client(service_name, **kwargs):
            if service_name == 'lambda':
                return mock_client
            return mock_session.client.side_effect(service_name, **kwargs)
        
        mock_session.client.side_effect = get_client
        
        findings = lambda_scanner.scan()
        assert len(findings) == 0
    
    def test_scan_with_unauthorized_error(self, lambda_scanner, mock_session):
        """Test scanning with unauthorized access"""
        mock_client = Mock()
        mock_client.get_paginator.side_effect = ClientError(
            {'Error': {'Code': 'UnauthorizedOperation', 'Message': 'Not authorized'}},
            'list_functions'
        )
        
        def get_client(service_name, **kwargs):
            if service_name == 'lambda':
                return mock_client
            return mock_session.client.side_effect(service_name, **kwargs)
        
        mock_session.client.side_effect = get_client
        
        findings = lambda_scanner.scan()
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH
        assert 'insufficient permissions' in findings[0].title.lower()
    
    def test_check_function_policy_public_access(self, lambda_scanner, mock_session, sample_function):
        """Test detection of public access in function policy"""
        mock_client = Mock()
        mock_client.get_policy.return_value = {
            'Policy': json.dumps({
                'Statement': [{
                    'Sid': 'PublicAccess',
                    'Effect': 'Allow',
                    'Principal': '*',
                    'Action': 'lambda:InvokeFunction',
                    'Resource': sample_function['FunctionArn']
                }]
            })
        }
        
        findings = lambda_scanner._check_function_policy(mock_client, sample_function, 'us-east-1')
        
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH
        assert findings[0].category == Category.ACCESS_CONTROL
        assert 'public access' in findings[0].title.lower()
    
    def test_check_function_policy_any_aws_account(self, lambda_scanner, mock_session, sample_function):
        """Test detection of any AWS account access"""
        mock_client = Mock()
        mock_client.get_policy.return_value = {
            'Policy': json.dumps({
                'Statement': [{
                    'Sid': 'AnyAWSAccount',
                    'Effect': 'Allow',
                    'Principal': {'AWS': '*'},
                    'Action': 'lambda:InvokeFunction',
                    'Resource': sample_function['FunctionArn']
                }]
            })
        }
        
        findings = lambda_scanner._check_function_policy(mock_client, sample_function, 'us-east-1')
        
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH
        assert 'any aws account' in findings[0].title.lower()
    
    def test_check_function_policy_no_policy(self, lambda_scanner, mock_session, sample_function):
        """Test function with no resource policy"""
        mock_client = Mock()
        mock_client.get_policy.side_effect = ClientError(
            {'Error': {'Code': 'ResourceNotFoundException', 'Message': 'No policy'}},
            'get_policy'
        )
        
        findings = lambda_scanner._check_function_policy(mock_client, sample_function, 'us-east-1')
        
        assert len(findings) == 0
    
    def test_check_environment_secrets(self, lambda_scanner, sample_function):
        """Test detection of secrets in environment variables"""
        findings = lambda_scanner._check_environment_secrets(sample_function, 'us-east-1')
        
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH
        assert findings[0].category == Category.DATA_PROTECTION
        assert 'secret in environment' in findings[0].title.lower()
        assert 'API_KEY' in findings[0].evidence['environment_variable']
    
    def test_check_environment_secrets_with_secrets_manager(self, lambda_scanner):
        """Test environment variables using Secrets Manager"""
        function = {
            'FunctionName': 'test-function',
            'FunctionArn': 'arn:aws:lambda:us-east-1:123456789012:function:test-function',
            'Environment': {
                'Variables': {
                    'DB_PASSWORD': 'arn:aws:secretsmanager:us-east-1:123456789012:secret:db-password-abc123'
                }
            }
        }
        
        findings = lambda_scanner._check_environment_secrets(function, 'us-east-1')
        assert len(findings) == 0
    
    def test_check_encryption_no_kms(self, lambda_scanner, sample_function):
        """Test detection of missing KMS encryption"""
        findings = lambda_scanner._check_encryption(sample_function, 'us-east-1')
        
        assert len(findings) == 1
        assert findings[0].severity == Severity.MEDIUM
        assert findings[0].category == Category.ENCRYPTION
        assert 'customer-managed kms' in findings[0].title.lower()
    
    def test_check_encryption_with_kms(self, lambda_scanner):
        """Test function with KMS encryption"""
        function = {
            'FunctionName': 'test-function',
            'FunctionArn': 'arn:aws:lambda:us-east-1:123456789012:function:test-function',
            'KMSKeyArn': 'arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012'
        }
        
        findings = lambda_scanner._check_encryption(function, 'us-east-1')
        assert len(findings) == 0
    
    def test_check_function_url_no_auth(self, lambda_scanner, mock_session, sample_function):
        """Test detection of function URL without authentication"""
        mock_client = Mock()
        mock_client.get_function_url_config.return_value = {
            'FunctionUrl': 'https://abc123.lambda-url.us-east-1.on.aws/',
            'AuthType': 'NONE',
            'CreationTime': '2024-01-01T00:00:00.000+0000'
        }
        
        findings = lambda_scanner._check_function_url(mock_client, sample_function, 'us-east-1')
        
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH
        assert findings[0].category == Category.ACCESS_CONTROL
        assert 'without authentication' in findings[0].title.lower()
    
    def test_check_function_url_with_auth(self, lambda_scanner, mock_session, sample_function):
        """Test function URL with IAM authentication"""
        mock_client = Mock()
        mock_client.get_function_url_config.return_value = {
            'FunctionUrl': 'https://abc123.lambda-url.us-east-1.on.aws/',
            'AuthType': 'AWS_IAM',
            'CreationTime': '2024-01-01T00:00:00.000+0000'
        }
        
        findings = lambda_scanner._check_function_url(mock_client, sample_function, 'us-east-1')
        assert len(findings) == 0
    
    def test_check_vpc_config_no_vpc(self, lambda_scanner, sample_function):
        """Test detection of Lambda not in VPC"""
        findings = lambda_scanner._check_vpc_config(sample_function, 'us-east-1')
        
        assert len(findings) == 1
        assert findings[0].severity == Severity.LOW
        assert findings[0].category == Category.NETWORK
        assert 'not in vpc' in findings[0].title.lower()
    
    def test_check_vpc_config_with_vpc(self, lambda_scanner):
        """Test Lambda configured in VPC"""
        function = {
            'FunctionName': 'test-function',
            'FunctionArn': 'arn:aws:lambda:us-east-1:123456789012:function:test-function',
            'VpcConfig': {
                'SubnetIds': ['subnet-12345', 'subnet-67890'],
                'SecurityGroupIds': ['sg-12345']
            }
        }
        
        findings = lambda_scanner._check_vpc_config(function, 'us-east-1')
        assert len(findings) == 0
    
    def test_check_runtime_deprecated(self, lambda_scanner):
        """Test detection of deprecated runtime"""
        function = {
            'FunctionName': 'test-function',
            'FunctionArn': 'arn:aws:lambda:us-east-1:123456789012:function:test-function',
            'Runtime': 'python2.7'
        }
        
        findings = lambda_scanner._check_runtime(function, 'us-east-1')
        
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH
        assert findings[0].category == Category.CONFIGURATION
        assert 'deprecated runtime' in findings[0].title.lower()
    
    def test_check_runtime_supported(self, lambda_scanner, sample_function):
        """Test supported runtime"""
        findings = lambda_scanner._check_runtime(sample_function, 'us-east-1')
        assert len(findings) == 0
    
    def test_check_dead_letter_queue_missing(self, lambda_scanner, sample_function):
        """Test detection of missing dead letter queue"""
        findings = lambda_scanner._check_dead_letter_queue(sample_function, 'us-east-1')
        
        assert len(findings) == 1
        assert findings[0].severity == Severity.LOW
        assert findings[0].category == Category.OPERATIONAL
        assert 'dead letter queue' in findings[0].title.lower()
    
    def test_check_dead_letter_queue_configured(self, lambda_scanner):
        """Test function with dead letter queue"""
        function = {
            'FunctionName': 'test-function',
            'FunctionArn': 'arn:aws:lambda:us-east-1:123456789012:function:test-function',
            'DeadLetterConfig': {
                'TargetArn': 'arn:aws:sqs:us-east-1:123456789012:dlq'
            }
        }
        
        findings = lambda_scanner._check_dead_letter_queue(function, 'us-east-1')
        assert len(findings) == 0
    
    def test_check_tracing_disabled(self, lambda_scanner, sample_function):
        """Test detection of disabled tracing"""
        findings = lambda_scanner._check_tracing(sample_function, 'us-east-1')
        
        assert len(findings) == 1
        assert findings[0].severity == Severity.LOW
        assert findings[0].category == Category.LOGGING
        assert 'tracing' in findings[0].title.lower()
    
    def test_check_tracing_enabled(self, lambda_scanner):
        """Test function with active tracing"""
        function = {
            'FunctionName': 'test-function',
            'FunctionArn': 'arn:aws:lambda:us-east-1:123456789012:function:test-function',
            'TracingConfig': {
                'Mode': 'Active'
            }
        }
        
        findings = lambda_scanner._check_tracing(function, 'us-east-1')
        assert len(findings) == 0
    
    def test_full_scan(self, lambda_scanner, mock_session, sample_function):
        """Test full scan with multiple findings"""
        mock_client = Mock()
        
        # Mock list_functions
        mock_paginator = Mock()
        mock_paginator.paginate.return_value = [
            {'Functions': [sample_function]}
        ]
        mock_client.get_paginator.return_value = mock_paginator
        
        # Mock get_policy - public access
        mock_client.get_policy.return_value = {
            'Policy': json.dumps({
                'Statement': [{
                    'Effect': 'Allow',
                    'Principal': '*',
                    'Action': 'lambda:InvokeFunction'
                }]
            })
        }
        
        # Mock get_function_url_config - no URL
        mock_client.get_function_url_config.side_effect = ClientError(
            {'Error': {'Code': 'ResourceNotFoundException'}},
            'get_function_url_config'
        )
        
        def get_client(service_name, **kwargs):
            if service_name == 'lambda':
                return mock_client
            return mock_session.client.side_effect(service_name, **kwargs)
        
        mock_session.client.side_effect = get_client
        
        findings = lambda_scanner.scan()
        
        # Should have findings for:
        # 1. Public access policy
        # 2. Environment variable with potential secret
        # 3. No KMS encryption
        # 4. Not in VPC
        # 5. No dead letter queue
        # 6. No active tracing
        assert len(findings) >= 6
        
        # Verify finding types
        severities = [f.severity for f in findings]
        assert Severity.HIGH in severities
        assert Severity.MEDIUM in severities
        assert Severity.LOW in severities