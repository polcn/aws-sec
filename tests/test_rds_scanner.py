"""Unit tests for RDS Scanner"""

import pytest
from unittest.mock import Mock, patch, MagicMock
import boto3
from botocore.exceptions import ClientError
from datetime import datetime

from src.scanners.rds_scanner import RDSScanner
from src.models import Finding, Severity, Category


@pytest.fixture
def mock_session():
    """Create a mock boto3 session"""
    session = Mock()
    return session


@pytest.fixture
def rds_scanner(mock_session):
    """Create an RDS scanner instance with mocked session"""
    with patch.object(RDSScanner, '_get_account_id', return_value='123456789012'):
        with patch.object(RDSScanner, '_get_enabled_regions', return_value=['us-east-1']):
            scanner = RDSScanner(mock_session)
    return scanner


@pytest.fixture
def mock_rds_client():
    """Create a mock RDS client"""
    client = Mock()
    return client


class TestRDSScanner:
    """Test cases for RDS Scanner"""
    
    def test_rds_scanner_initialization(self, rds_scanner):
        """Test RDS scanner initialization"""
        assert rds_scanner.service_name == "rds"
        assert rds_scanner.account_id == "123456789012"
        assert rds_scanner.regions == ["us-east-1"]
    
    def test_check_encryption_at_rest_not_enabled(self, rds_scanner):
        """Test detection of RDS instance without encryption"""
        instance = {
            'DBInstanceIdentifier': 'test-db',
            'StorageEncrypted': False,
            'Engine': 'mysql',
            'EngineVersion': '8.0.35',
            'DBInstanceClass': 'db.t3.micro'
        }
        
        findings = rds_scanner._check_encryption_at_rest(instance, 'us-east-1')
        
        assert len(findings) == 1
        finding = findings[0]
        assert finding.severity == Severity.HIGH
        assert finding.title == "RDS Instance Not Encrypted"
        assert finding.resource_id == "test-db"
        assert finding.category == Category.DATA_PROTECTION
        assert finding.evidence['engine'] == 'mysql'
    
    def test_check_encryption_at_rest_enabled(self, rds_scanner):
        """Test RDS instance with encryption enabled"""
        instance = {
            'DBInstanceIdentifier': 'test-db',
            'StorageEncrypted': True
        }
        
        findings = rds_scanner._check_encryption_at_rest(instance, 'us-east-1')
        
        assert len(findings) == 0
    
    def test_check_backup_configuration_disabled(self, rds_scanner):
        """Test detection of RDS instance with backups disabled"""
        instance = {
            'DBInstanceIdentifier': 'test-db',
            'BackupRetentionPeriod': 0
        }
        
        findings = rds_scanner._check_backup_configuration(instance, 'us-east-1')
        
        assert len(findings) == 3  # Disabled + insufficient + no window
        assert any(f.title == "Automated Backups Disabled" for f in findings)
        assert any(f.severity == Severity.HIGH for f in findings)
    
    def test_check_backup_configuration_insufficient(self, rds_scanner):
        """Test detection of insufficient backup retention"""
        instance = {
            'DBInstanceIdentifier': 'test-db',
            'BackupRetentionPeriod': 3,
            'PreferredBackupWindow': '03:00-04:00'
        }
        
        findings = rds_scanner._check_backup_configuration(instance, 'us-east-1')
        
        assert len(findings) == 1
        finding = findings[0]
        assert finding.title == "Insufficient Backup Retention Period"
        assert finding.severity == Severity.MEDIUM
        assert finding.evidence['current_retention_days'] == 3
    
    def test_check_public_accessibility_enabled(self, rds_scanner):
        """Test detection of publicly accessible RDS instance"""
        instance = {
            'DBInstanceIdentifier': 'test-db',
            'PubliclyAccessible': True,
            'Endpoint': {
                'Address': 'test-db.abcdef.us-east-1.rds.amazonaws.com',
                'Port': 3306
            }
        }
        
        findings = rds_scanner._check_public_accessibility(instance, 'us-east-1')
        
        assert len(findings) == 1
        finding = findings[0]
        assert finding.severity == Severity.HIGH
        assert finding.title == "RDS Instance Publicly Accessible"
        assert finding.evidence['endpoint'] == 'test-db.abcdef.us-east-1.rds.amazonaws.com'
    
    def test_check_multi_az_not_enabled(self, rds_scanner):
        """Test detection of single AZ deployment"""
        instance = {
            'DBInstanceIdentifier': 'test-db',
            'MultiAZ': False,
            'AvailabilityZone': 'us-east-1a'
        }
        
        findings = rds_scanner._check_multi_az(instance, 'us-east-1')
        
        assert len(findings) == 1
        finding = findings[0]
        assert finding.severity == Severity.MEDIUM
        assert finding.title == "Multi-AZ Not Enabled"
        assert finding.evidence['availability_zone'] == 'us-east-1a'
    
    def test_check_multi_az_read_replica(self, rds_scanner):
        """Test that read replicas are skipped for Multi-AZ check"""
        instance = {
            'DBInstanceIdentifier': 'test-db-replica',
            'MultiAZ': False,
            'ReadReplicaSourceDBInstanceIdentifier': 'test-db'
        }
        
        findings = rds_scanner._check_multi_az(instance, 'us-east-1')
        
        assert len(findings) == 0
    
    def test_check_deletion_protection_not_enabled(self, rds_scanner):
        """Test detection of missing deletion protection"""
        instance = {
            'DBInstanceIdentifier': 'test-db',
            'DeletionProtection': False
        }
        
        findings = rds_scanner._check_deletion_protection(instance, 'us-east-1')
        
        assert len(findings) == 1
        finding = findings[0]
        assert finding.severity == Severity.MEDIUM
        assert finding.title == "Deletion Protection Not Enabled"
    
    def test_check_auto_minor_version_upgrade_disabled(self, rds_scanner):
        """Test detection of disabled auto minor version upgrade"""
        instance = {
            'DBInstanceIdentifier': 'test-db',
            'AutoMinorVersionUpgrade': False,
            'EngineVersion': '8.0.35'
        }
        
        findings = rds_scanner._check_auto_minor_version_upgrade(instance, 'us-east-1')
        
        assert len(findings) == 1
        finding = findings[0]
        assert finding.severity == Severity.LOW
        assert finding.title == "Auto Minor Version Upgrade Disabled"
        assert finding.category == Category.PATCHING
    
    def test_check_performance_insights_not_enabled(self, rds_scanner):
        """Test detection of disabled Performance Insights"""
        instance = {
            'DBInstanceIdentifier': 'test-db',
            'PerformanceInsightsEnabled': False
        }
        
        findings = rds_scanner._check_performance_insights(instance, 'us-east-1')
        
        assert len(findings) == 1
        finding = findings[0]
        assert finding.severity == Severity.LOW
        assert finding.title == "Performance Insights Not Enabled"
        assert finding.category == Category.OPERATIONAL
    
    def test_check_iam_authentication_not_enabled(self, rds_scanner):
        """Test detection of disabled IAM authentication"""
        instance = {
            'DBInstanceIdentifier': 'test-db',
            'Engine': 'mysql',
            'IAMDatabaseAuthenticationEnabled': False
        }
        
        findings = rds_scanner._check_iam_authentication(instance, 'us-east-1')
        
        assert len(findings) == 1
        finding = findings[0]
        assert finding.severity == Severity.LOW
        assert finding.title == "IAM Database Authentication Not Enabled"
        assert finding.category == Category.ACCESS_CONTROL
    
    def test_check_iam_authentication_unsupported_engine(self, rds_scanner):
        """Test IAM auth check for unsupported engine"""
        instance = {
            'DBInstanceIdentifier': 'test-db',
            'Engine': 'oracle-ee',
            'IAMDatabaseAuthenticationEnabled': False
        }
        
        findings = rds_scanner._check_iam_authentication(instance, 'us-east-1')
        
        assert len(findings) == 0
    
    def test_check_db_cluster_not_encrypted(self, rds_scanner):
        """Test detection of unencrypted RDS cluster"""
        cluster = {
            'DBClusterIdentifier': 'test-cluster',
            'StorageEncrypted': False,
            'Engine': 'aurora-mysql',
            'EngineVersion': '8.0.mysql_aurora.3.04.0'
        }
        
        findings = rds_scanner._check_db_cluster(cluster, 'us-east-1')
        
        # Should find: not encrypted, insufficient backup, no deletion protection, no IAM auth
        assert len(findings) >= 4
        assert any(f.title == "RDS Cluster Not Encrypted" and f.severity == Severity.HIGH for f in findings)
    
    def test_check_db_snapshot_not_encrypted(self, rds_scanner):
        """Test detection of unencrypted RDS snapshot"""
        snapshot = {
            'DBSnapshotIdentifier': 'test-snapshot',
            'Encrypted': False,
            'DBInstanceIdentifier': 'test-db',
            'SnapshotType': 'manual'
        }
        
        findings = rds_scanner._check_db_snapshot(snapshot, 'us-east-1')
        
        assert len(findings) == 1
        finding = findings[0]
        assert finding.severity == Severity.HIGH
        assert finding.title == "Unencrypted RDS Snapshot"
        assert finding.evidence['source_db'] == 'test-db'
    
    def test_check_parameter_group_insecure_settings(self, rds_scanner, mock_rds_client):
        """Test detection of insecure parameter settings"""
        param_group = {
            'DBParameterGroupName': 'custom-pg'
        }
        
        mock_paginator = Mock()
        mock_rds_client.get_paginator.return_value = mock_paginator
        mock_paginator.paginate.return_value = [
            {
                'Parameters': [
                    {'ParameterName': 'rds.force_ssl', 'ParameterValue': '0'},
                    {'ParameterName': 'log_statement', 'ParameterValue': 'none'}
                ]
            }
        ]
        
        findings = rds_scanner._check_parameter_group(param_group, mock_rds_client, 'us-east-1')
        
        assert len(findings) == 2
        assert all(f.title.startswith("Insecure Parameter Setting:") for f in findings)
        assert all(f.severity == Severity.MEDIUM for f in findings)
    
    def test_scan_with_client_error(self, rds_scanner, mock_session):
        """Test scanner behavior when AWS API returns error"""
        mock_client = Mock()
        mock_session.client.return_value = mock_client
        
        # Mock all paginators to return empty results (simulating successful but empty responses)
        mock_paginator = Mock()
        mock_client.get_paginator.return_value = mock_paginator
        mock_paginator.paginate.return_value = []
        
        # Now simulate a ClientError during the actual scan operations
        mock_client.describe_db_instances.side_effect = ClientError(
            {'Error': {'Code': 'AccessDenied', 'Message': 'Access denied'}},
            'DescribeDBInstances'
        )
        
        findings = rds_scanner.scan()
        
        # Since errors are caught in helper methods, scan should complete with no findings
        assert len(findings) == 0
    
    def test_full_scan_flow(self, rds_scanner, mock_session):
        """Test complete scan flow with mixed findings"""
        mock_client = Mock()
        mock_session.client.return_value = mock_client
        
        # Mock paginator for instances
        instances_paginator = Mock()
        clusters_paginator = Mock()
        snapshots_paginator = Mock()
        param_groups_paginator = Mock()
        
        mock_client.get_paginator.side_effect = lambda x: {
            'describe_db_instances': instances_paginator,
            'describe_db_clusters': clusters_paginator,
            'describe_db_snapshots': snapshots_paginator,
            'describe_db_parameter_groups': param_groups_paginator
        }.get(x)
        
        # Mock responses
        instances_paginator.paginate.return_value = [
            {
                'DBInstances': [
                    {
                        'DBInstanceIdentifier': 'prod-db',
                        'StorageEncrypted': False,
                        'PubliclyAccessible': True,
                        'BackupRetentionPeriod': 1,
                        'MultiAZ': False,
                        'DeletionProtection': False,
                        'AutoMinorVersionUpgrade': False,
                        'PerformanceInsightsEnabled': False,
                        'Engine': 'postgres',
                        'IAMDatabaseAuthenticationEnabled': False,
                        'EngineVersion': '13.7',
                        'DBInstanceClass': 'db.t3.large',
                        'AvailabilityZone': 'us-east-1a',
                        'Endpoint': {'Address': 'prod-db.abc.rds.amazonaws.com', 'Port': 5432}
                    }
                ]
            }
        ]
        
        clusters_paginator.paginate.return_value = [{'DBClusters': []}]
        snapshots_paginator.paginate.return_value = [{'DBSnapshots': []}]
        param_groups_paginator.paginate.return_value = [{'DBParameterGroups': []}]
        
        findings = rds_scanner.scan()
        
        # Should find multiple issues with the instance
        assert len(findings) > 0
        assert any(f.title == "RDS Instance Not Encrypted" for f in findings)
        assert any(f.title == "RDS Instance Publicly Accessible" for f in findings)
        assert any(f.severity == Severity.HIGH for f in findings)