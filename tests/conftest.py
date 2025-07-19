#!/usr/bin/env python3
"""
Pytest configuration and shared fixtures
"""

import pytest
from unittest.mock import Mock
import sys
import os

# Add src to Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))


@pytest.fixture
def mock_boto3_session():
    """Create a mock boto3 session for testing"""
    session = Mock()
    session.region_name = 'us-east-1'
    
    # Mock STS client for get_caller_identity
    sts_client = Mock()
    sts_client.get_caller_identity.return_value = {'Account': '123456789012'}
    
    # Make session.client return appropriate mocks
    def client_side_effect(service_name, **kwargs):
        if service_name == 'sts':
            return sts_client
        return Mock()
    
    session.client.side_effect = client_side_effect
    
    return session


@pytest.fixture
def test_account_id():
    """Test AWS account ID"""
    return "123456789012"


@pytest.fixture
def test_region():
    """Test AWS region"""
    return "us-east-1"