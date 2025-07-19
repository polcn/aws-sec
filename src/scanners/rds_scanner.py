"""RDS Security Scanner

This module implements security scanning for AWS RDS (Relational Database Service)
including checks for encryption, backups, public access, and security configurations.
"""

from typing import List, Dict, Any, Optional
import boto3
from botocore.exceptions import ClientError
from datetime import datetime, timedelta, timezone

from .base import BaseScanner
from ..models import Finding, Severity, Category


class RDSScanner(BaseScanner):
    """Scanner for RDS security configurations"""
    
    @property
    def service_name(self) -> str:
        return "rds"
    
    def scan(self) -> List[Finding]:
        """Perform RDS security scan across all regions"""
        findings = []
        
        for region in self.regions:
            self.logger.info(f"Scanning RDS in region {region}")
            try:
                rds_client = self.session.client('rds', region_name=region)
                
                # Get all DB instances
                db_instances = self._get_all_db_instances(rds_client)
                for db_instance in db_instances:
                    findings.extend(self._check_db_instance(db_instance, region))
                
                # Get all DB clusters (Aurora)
                db_clusters = self._get_all_db_clusters(rds_client)
                for db_cluster in db_clusters:
                    findings.extend(self._check_db_cluster(db_cluster, region))
                
                # Get all DB snapshots
                db_snapshots = self._get_all_db_snapshots(rds_client)
                for snapshot in db_snapshots:
                    findings.extend(self._check_db_snapshot(snapshot, region))
                
                # Check parameter groups
                param_groups = self._get_all_parameter_groups(rds_client)
                for param_group in param_groups:
                    findings.extend(self._check_parameter_group(param_group, rds_client, region))
                
            except ClientError as e:
                self.logger.error(f"Error scanning RDS in region {region}: {e}")
                findings.append(Finding(
                    severity=Severity.MEDIUM,
                    region=region,
                    resource_type="RDS",
                    resource_id="unknown",
                    title="RDS Scan Error",
                    description=f"Failed to scan RDS resources in region {region}: {str(e)}",
                    impact="Unable to assess RDS security posture in this region",
                    recommendation="Check IAM permissions for RDS:Describe* actions",
                    category=Category.ACCESS_CONTROL,
                    account_id=self.account_id
                ))
        
        return findings
    
    def _get_all_db_instances(self, client) -> List[Dict[str, Any]]:
        """Get all DB instances in the region"""
        instances = []
        try:
            paginator = client.get_paginator('describe_db_instances')
            for page in paginator.paginate():
                instances.extend(page.get('DBInstances', []))
        except ClientError as e:
            self.logger.error(f"Error getting DB instances: {e}")
        return instances
    
    def _get_all_db_clusters(self, client) -> List[Dict[str, Any]]:
        """Get all DB clusters in the region"""
        clusters = []
        try:
            paginator = client.get_paginator('describe_db_clusters')
            for page in paginator.paginate():
                clusters.extend(page.get('DBClusters', []))
        except ClientError as e:
            self.logger.error(f"Error getting DB clusters: {e}")
        return clusters
    
    def _get_all_db_snapshots(self, client) -> List[Dict[str, Any]]:
        """Get all DB snapshots in the region"""
        snapshots = []
        try:
            paginator = client.get_paginator('describe_db_snapshots')
            for page in paginator.paginate(SnapshotType='manual'):
                snapshots.extend(page.get('DBSnapshots', []))
        except ClientError as e:
            self.logger.error(f"Error getting DB snapshots: {e}")
        return snapshots
    
    def _get_all_parameter_groups(self, client) -> List[Dict[str, Any]]:
        """Get all DB parameter groups in the region"""
        param_groups = []
        try:
            paginator = client.get_paginator('describe_db_parameter_groups')
            for page in paginator.paginate():
                # Skip default parameter groups
                for pg in page.get('DBParameterGroups', []):
                    if not pg['DBParameterGroupName'].startswith('default.'):
                        param_groups.append(pg)
        except ClientError as e:
            self.logger.error(f"Error getting parameter groups: {e}")
        return param_groups
    
    def _check_db_instance(self, instance: Dict[str, Any], region: str) -> List[Finding]:
        """Check security configuration of a DB instance"""
        findings = []
        instance_id = instance['DBInstanceIdentifier']
        
        # Check encryption at rest
        findings.extend(self._check_encryption_at_rest(instance, region))
        
        # Check backup configuration
        findings.extend(self._check_backup_configuration(instance, region))
        
        # Check public accessibility
        findings.extend(self._check_public_accessibility(instance, region))
        
        # Check Multi-AZ deployment
        findings.extend(self._check_multi_az(instance, region))
        
        # Check deletion protection
        findings.extend(self._check_deletion_protection(instance, region))
        
        # Check auto minor version upgrade
        findings.extend(self._check_auto_minor_version_upgrade(instance, region))
        
        # Check performance insights
        findings.extend(self._check_performance_insights(instance, region))
        
        # Check IAM authentication
        findings.extend(self._check_iam_authentication(instance, region))
        
        return findings
    
    def _check_db_cluster(self, cluster: Dict[str, Any], region: str) -> List[Finding]:
        """Check security configuration of a DB cluster"""
        findings = []
        cluster_id = cluster['DBClusterIdentifier']
        
        # Check encryption at rest
        if not cluster.get('StorageEncrypted', False):
            findings.append(Finding(
                severity=Severity.HIGH,
                                region=region,
                resource_type="DBCluster",
                resource_id=cluster_id,
                title="RDS Cluster Not Encrypted",
                description=f"RDS cluster '{cluster_id}' does not have encryption at rest enabled",
                impact="Unencrypted data at rest is vulnerable to unauthorized access if storage media is compromised",
                recommendation="Enable encryption for the cluster. Note: This requires creating a new encrypted cluster and migrating data.",
                category=Category.DATA_PROTECTION,
                account_id=self.account_id,
                evidence={
                    "engine": cluster.get('Engine', 'unknown'),
                    "engine_version": cluster.get('EngineVersion', 'unknown')
                }
            ))
        
        # Check backup retention
        retention_period = cluster.get('BackupRetentionPeriod', 0)
        if retention_period < 7:
            findings.append(Finding(
                severity=Severity.MEDIUM,
                                region=region,
                resource_type="DBCluster",
                resource_id=cluster_id,
                title="Insufficient Backup Retention Period",
                description=f"RDS cluster '{cluster_id}' has backup retention period of {retention_period} days",
                impact="Insufficient backup retention limits disaster recovery capabilities",
                recommendation="Set backup retention period to at least 7 days for production databases",
                category=Category.DATA_PROTECTION,
                account_id=self.account_id,
                evidence={
                    "current_retention_days": retention_period
                }
            ))
        
        # Check deletion protection
        if not cluster.get('DeletionProtection', False):
            findings.append(Finding(
                severity=Severity.MEDIUM,
                                region=region,
                resource_type="DBCluster",
                resource_id=cluster_id,
                title="Deletion Protection Not Enabled",
                description=f"RDS cluster '{cluster_id}' does not have deletion protection enabled",
                impact="Database can be accidentally deleted without deletion protection",
                recommendation="Enable deletion protection to prevent accidental cluster deletion",
                category=Category.DATA_PROTECTION,
                account_id=self.account_id
            ))
        
        # Check IAM authentication
        if not cluster.get('IAMDatabaseAuthenticationEnabled', False):
            findings.append(Finding(
                severity=Severity.LOW,
                                region=region,
                resource_type="DBCluster",
                resource_id=cluster_id,
                title="IAM Database Authentication Not Enabled",
                description=f"RDS cluster '{cluster_id}' does not use IAM authentication",
                impact="Using only database passwords is less secure than IAM-based authentication",
                recommendation="Enable IAM database authentication for better access control",
                category=Category.ACCESS_CONTROL,
                account_id=self.account_id
            ))
        
        return findings
    
    def _check_db_snapshot(self, snapshot: Dict[str, Any], region: str) -> List[Finding]:
        """Check security configuration of a DB snapshot"""
        findings = []
        snapshot_id = snapshot['DBSnapshotIdentifier']
        
        # Check if snapshot is encrypted
        if not snapshot.get('Encrypted', False):
            findings.append(Finding(
                severity=Severity.HIGH,
                                region=region,
                resource_type="DBSnapshot",
                resource_id=snapshot_id,
                title="Unencrypted RDS Snapshot",
                description=f"RDS snapshot '{snapshot_id}' is not encrypted",
                impact="Unencrypted snapshots can expose sensitive data if accessed by unauthorized parties",
                recommendation="Create encrypted snapshots by enabling encryption on the source database",
                category=Category.DATA_PROTECTION,
                account_id=self.account_id,
                evidence={
                    "source_db": snapshot.get('DBInstanceIdentifier', 'unknown'),
                    "snapshot_type": snapshot.get('SnapshotType', 'unknown')
                }
            ))
        
        return findings
    
    def _check_parameter_group(self, param_group: Dict[str, Any], client, region: str) -> List[Finding]:
        """Check security-related parameters in parameter groups"""
        findings = []
        pg_name = param_group['DBParameterGroupName']
        
        try:
            # Get parameters for this group
            parameters = []
            paginator = client.get_paginator('describe_db_parameters')
            for page in paginator.paginate(DBParameterGroupName=pg_name):
                parameters.extend(page.get('Parameters', []))
            
            # Check security-related parameters
            security_params = {
                'rds.force_ssl': '1',  # Force SSL connections
                'log_statement': 'all',  # Log all statements
                'log_connections': '1',  # Log connections
                'log_disconnections': '1',  # Log disconnections
                'shared_preload_libraries': 'pg_stat_statements'  # For PostgreSQL monitoring
            }
            
            for param_name, expected_value in security_params.items():
                param = next((p for p in parameters if p['ParameterName'] == param_name), None)
                if param:
                    current_value = param.get('ParameterValue', '')
                    if current_value != expected_value:
                        findings.append(Finding(
                            severity=Severity.MEDIUM,
                                                        region=region,
                            resource_type="DBParameterGroup",
                            resource_id=pg_name,
                            title=f"Insecure Parameter Setting: {param_name}",
                            description=f"Parameter '{param_name}' in group '{pg_name}' is set to '{current_value}' instead of recommended '{expected_value}'",
                            impact="Insecure parameter settings can expose the database to security risks",
                            recommendation=f"Set parameter '{param_name}' to '{expected_value}' for better security",
                            category=Category.ACCESS_CONTROL,
                            account_id=self.account_id,
                            evidence={
                                "parameter_name": param_name,
                                "current_value": current_value,
                                "recommended_value": expected_value
                            }
                        ))
        
        except ClientError as e:
            self.logger.error(f"Error checking parameter group {pg_name}: {e}")
        
        return findings
    
    def _check_encryption_at_rest(self, instance: Dict[str, Any], region: str) -> List[Finding]:
        """Check if DB instance has encryption at rest enabled"""
        findings = []
        instance_id = instance['DBInstanceIdentifier']
        
        if not instance.get('StorageEncrypted', False):
            findings.append(Finding(
                severity=Severity.HIGH,
                                region=region,
                resource_type="DBInstance",
                resource_id=instance_id,
                title="RDS Instance Not Encrypted",
                description=f"RDS instance '{instance_id}' does not have encryption at rest enabled",
                impact="Unencrypted data at rest is vulnerable to unauthorized access if storage media is compromised",
                recommendation="Enable encryption for the instance. Note: This requires creating a new encrypted instance and migrating data.",
                category=Category.DATA_PROTECTION,
                account_id=self.account_id,
                evidence={
                    "engine": instance.get('Engine', 'unknown'),
                    "engine_version": instance.get('EngineVersion', 'unknown'),
                    "instance_class": instance.get('DBInstanceClass', 'unknown')
                }
            ))
        
        return findings
    
    def _check_backup_configuration(self, instance: Dict[str, Any], region: str) -> List[Finding]:
        """Check backup configuration of DB instance"""
        findings = []
        instance_id = instance['DBInstanceIdentifier']
        
        # Check backup retention period
        retention_period = instance.get('BackupRetentionPeriod', 0)
        if retention_period < 7:
            findings.append(Finding(
                severity=Severity.MEDIUM,
                                region=region,
                resource_type="DBInstance",
                resource_id=instance_id,
                title="Insufficient Backup Retention Period",
                description=f"RDS instance '{instance_id}' has backup retention period of {retention_period} days",
                impact="Insufficient backup retention limits disaster recovery capabilities",
                recommendation="Set backup retention period to at least 7 days for production databases",
                category=Category.DATA_PROTECTION,
                account_id=self.account_id,
                evidence={
                    "current_retention_days": retention_period
                }
            ))
        
        # Check if automated backups are enabled
        if retention_period == 0:
            findings.append(Finding(
                severity=Severity.HIGH,
                                region=region,
                resource_type="DBInstance",
                resource_id=instance_id,
                title="Automated Backups Disabled",
                description=f"RDS instance '{instance_id}' has automated backups disabled",
                impact="No automated backups means potential data loss in case of failures",
                recommendation="Enable automated backups by setting retention period > 0",
                category=Category.DATA_PROTECTION,
                account_id=self.account_id
            ))
        
        # Check backup window
        backup_window = instance.get('PreferredBackupWindow', '')
        if not backup_window:
            findings.append(Finding(
                severity=Severity.LOW,
                                region=region,
                resource_type="DBInstance",
                resource_id=instance_id,
                title="No Preferred Backup Window Set",
                description=f"RDS instance '{instance_id}' does not have a preferred backup window",
                impact="Backups during peak hours can impact performance",
                recommendation="Set a preferred backup window during low-traffic hours",
                category=Category.OPERATIONAL,
                account_id=self.account_id
            ))
        
        return findings
    
    def _check_public_accessibility(self, instance: Dict[str, Any], region: str) -> List[Finding]:
        """Check if DB instance is publicly accessible"""
        findings = []
        instance_id = instance['DBInstanceIdentifier']
        
        if instance.get('PubliclyAccessible', False):
            findings.append(Finding(
                severity=Severity.HIGH,
                                region=region,
                resource_type="DBInstance",
                resource_id=instance_id,
                title="RDS Instance Publicly Accessible",
                description=f"RDS instance '{instance_id}' is configured to be publicly accessible",
                impact="Publicly accessible databases are exposed to internet-based attacks",
                recommendation="Disable public accessibility and use VPN or bastion hosts for access",
                category=Category.ACCESS_CONTROL,
                account_id=self.account_id,
                evidence={
                    "endpoint": instance.get('Endpoint', {}).get('Address', 'unknown'),
                    "port": instance.get('Endpoint', {}).get('Port', 'unknown')
                }
            ))
        
        return findings
    
    def _check_multi_az(self, instance: Dict[str, Any], region: str) -> List[Finding]:
        """Check if DB instance has Multi-AZ deployment"""
        findings = []
        instance_id = instance['DBInstanceIdentifier']
        
        # Skip read replicas as they don't support Multi-AZ in the same way
        if instance.get('ReadReplicaSourceDBInstanceIdentifier'):
            return findings
        
        if not instance.get('MultiAZ', False):
            findings.append(Finding(
                severity=Severity.MEDIUM,
                                region=region,
                resource_type="DBInstance",
                resource_id=instance_id,
                title="Multi-AZ Not Enabled",
                description=f"RDS instance '{instance_id}' does not have Multi-AZ deployment enabled",
                impact="Single AZ deployment has no automatic failover capability",
                recommendation="Enable Multi-AZ deployment for high availability",
                category=Category.OPERATIONAL,
                account_id=self.account_id,
                evidence={
                    "availability_zone": instance.get('AvailabilityZone', 'unknown')
                }
            ))
        
        return findings
    
    def _check_deletion_protection(self, instance: Dict[str, Any], region: str) -> List[Finding]:
        """Check if deletion protection is enabled"""
        findings = []
        instance_id = instance['DBInstanceIdentifier']
        
        if not instance.get('DeletionProtection', False):
            findings.append(Finding(
                severity=Severity.MEDIUM,
                                region=region,
                resource_type="DBInstance",
                resource_id=instance_id,
                title="Deletion Protection Not Enabled",
                description=f"RDS instance '{instance_id}' does not have deletion protection enabled",
                impact="Database can be accidentally deleted without deletion protection",
                recommendation="Enable deletion protection to prevent accidental instance deletion",
                category=Category.DATA_PROTECTION,
                account_id=self.account_id
            ))
        
        return findings
    
    def _check_auto_minor_version_upgrade(self, instance: Dict[str, Any], region: str) -> List[Finding]:
        """Check if auto minor version upgrade is enabled"""
        findings = []
        instance_id = instance['DBInstanceIdentifier']
        
        if not instance.get('AutoMinorVersionUpgrade', False):
            findings.append(Finding(
                severity=Severity.LOW,
                                region=region,
                resource_type="DBInstance",
                resource_id=instance_id,
                title="Auto Minor Version Upgrade Disabled",
                description=f"RDS instance '{instance_id}' does not have auto minor version upgrade enabled",
                impact="Missing security patches can leave the database vulnerable to known exploits",
                recommendation="Enable auto minor version upgrade to receive security patches automatically",
                category=Category.PATCHING,
                account_id=self.account_id,
                evidence={
                    "current_version": instance.get('EngineVersion', 'unknown')
                }
            ))
        
        return findings
    
    def _check_performance_insights(self, instance: Dict[str, Any], region: str) -> List[Finding]:
        """Check if Performance Insights is enabled"""
        findings = []
        instance_id = instance['DBInstanceIdentifier']
        
        if not instance.get('PerformanceInsightsEnabled', False):
            findings.append(Finding(
                severity=Severity.LOW,
                                region=region,
                resource_type="DBInstance",
                resource_id=instance_id,
                title="Performance Insights Not Enabled",
                description=f"RDS instance '{instance_id}' does not have Performance Insights enabled",
                impact="Limited visibility into database performance issues",
                recommendation="Enable Performance Insights for better monitoring and troubleshooting",
                category=Category.OPERATIONAL,
                account_id=self.account_id
            ))
        
        return findings
    
    def _check_iam_authentication(self, instance: Dict[str, Any], region: str) -> List[Finding]:
        """Check if IAM database authentication is enabled"""
        findings = []
        instance_id = instance['DBInstanceIdentifier']
        
        # IAM auth is only supported for certain engines
        supported_engines = ['mysql', 'postgres', 'mariadb']
        engine = instance.get('Engine', '').lower()
        
        if engine in supported_engines and not instance.get('IAMDatabaseAuthenticationEnabled', False):
            findings.append(Finding(
                severity=Severity.LOW,
                                region=region,
                resource_type="DBInstance",
                resource_id=instance_id,
                title="IAM Database Authentication Not Enabled",
                description=f"RDS instance '{instance_id}' does not use IAM authentication",
                impact="Using only database passwords is less secure than IAM-based authentication",
                recommendation="Enable IAM database authentication for better access control",
                category=Category.ACCESS_CONTROL,
                account_id=self.account_id,
                evidence={
                    "engine": engine
                }
            ))
        
        return findings