import json
import logging
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional
import boto3
from botocore.exceptions import ClientError
from .base import BaseScanner
from ..models import Finding, Severity, Category, ComplianceFramework

logger = logging.getLogger(__name__)


class S3Scanner(BaseScanner):
    """Scanner for S3 security issues"""
    
    @property
    def service_name(self) -> str:
        return "s3"
    
    def scan(self) -> List[Finding]:
        """Perform S3 security scan"""
        findings = []
        
        try:
            s3_client = self.session.client('s3')
            
            # Get all buckets
            buckets = s3_client.list_buckets().get('Buckets', [])
            
            for bucket in buckets:
                bucket_name = bucket['Name']
                bucket_region = self._get_bucket_region(s3_client, bucket_name)
                
                # Create regional client if needed
                if bucket_region and bucket_region != 'us-east-1':
                    regional_s3 = self.session.client('s3', region_name=bucket_region)
                else:
                    regional_s3 = s3_client
                
                # Run security checks for each bucket
                findings.extend(self._check_bucket_encryption(regional_s3, bucket_name, bucket_region))
                findings.extend(self._check_bucket_public_access(regional_s3, bucket_name, bucket_region))
                findings.extend(self._check_bucket_versioning(regional_s3, bucket_name, bucket_region))
                findings.extend(self._check_bucket_logging(regional_s3, bucket_name, bucket_region))
                findings.extend(self._check_bucket_lifecycle(regional_s3, bucket_name, bucket_region))
                findings.extend(self._check_bucket_policy(regional_s3, bucket_name, bucket_region))
                findings.extend(self._check_bucket_acl(regional_s3, bucket_name, bucket_region))
                findings.extend(self._check_object_lock(regional_s3, bucket_name, bucket_region))
                
        except ClientError as e:
            self._handle_error(e, "S3 scan")
        
        return findings
    
    def _get_bucket_region(self, s3_client, bucket_name: str) -> Optional[str]:
        """Get the region of a bucket"""
        try:
            response = s3_client.get_bucket_location(Bucket=bucket_name)
            region = response.get('LocationConstraint')
            # get_bucket_location returns None for us-east-1
            return region if region else 'us-east-1'
        except ClientError as e:
            logger.warning(f"Could not determine region for bucket {bucket_name}: {e}")
            return None
    
    def _check_bucket_encryption(self, s3_client, bucket_name: str, region: str) -> List[Finding]:
        """Check if bucket has encryption enabled"""
        findings = []
        
        try:
            # Check bucket encryption
            try:
                encryption = s3_client.get_bucket_encryption(Bucket=bucket_name)
                has_encryption = True
                encryption_type = encryption['ServerSideEncryptionConfiguration']['Rules'][0]['ApplyServerSideEncryptionByDefault']['SSEAlgorithm']
            except ClientError as e:
                if e.response['Error']['Code'] == 'ServerSideEncryptionConfigurationNotFoundError':
                    has_encryption = False
                    encryption_type = None
                else:
                    raise
            
            if not has_encryption:
                findings.append(Finding(
                    severity=Severity.HIGH,
                    category=Category.DATA_PROTECTION,
                    resource_type="AWS::S3::Bucket",
                    resource_id=bucket_name,
                    region=region or "global",
                    account_id=self.account_id,
                    title="S3 Bucket Without Encryption",
                    description=f"S3 bucket '{bucket_name}' does not have default encryption enabled.",
                    impact="Data stored in the bucket is not encrypted at rest, potentially exposing sensitive information.",
                    recommendation="Enable default encryption for the bucket using SSE-S3 or SSE-KMS.",
                    compliance_frameworks=[ComplianceFramework.NIST, ComplianceFramework.SOX],
                    automated_remediation_available=True,
                    evidence={
                        "bucket_name": bucket_name,
                        "encryption_enabled": False
                    }
                ))
            elif encryption_type == 'AES256':
                # SSE-S3 is good but SSE-KMS is better for compliance
                findings.append(Finding(
                    severity=Severity.LOW,
                    category=Category.DATA_PROTECTION,
                    resource_type="AWS::S3::Bucket",
                    resource_id=bucket_name,
                    region=region or "global",
                    account_id=self.account_id,
                    title="S3 Bucket Using SSE-S3 Instead of SSE-KMS",
                    description=f"S3 bucket '{bucket_name}' uses SSE-S3 encryption instead of SSE-KMS.",
                    impact="SSE-S3 provides encryption but lacks the additional key management features and audit trail of KMS.",
                    recommendation="Consider using SSE-KMS for enhanced security and compliance requirements.",
                    compliance_frameworks=[ComplianceFramework.SOX],
                    automated_remediation_available=True,
                    evidence={
                        "bucket_name": bucket_name,
                        "encryption_type": encryption_type
                    }
                ))
                
        except ClientError as e:
            self._handle_error(e, f"encryption check for bucket {bucket_name}")
        
        return findings
    
    def _check_bucket_public_access(self, s3_client, bucket_name: str, region: str) -> List[Finding]:
        """Check bucket public access settings"""
        findings = []
        
        try:
            # Check Public Access Block configuration
            try:
                pab = s3_client.get_public_access_block(Bucket=bucket_name)
                pab_config = pab['PublicAccessBlockConfiguration']
                
                # Check if all public access is blocked
                all_blocked = all([
                    pab_config.get('BlockPublicAcls', False),
                    pab_config.get('IgnorePublicAcls', False),
                    pab_config.get('BlockPublicPolicy', False),
                    pab_config.get('RestrictPublicBuckets', False)
                ])
                
                if not all_blocked:
                    missing_blocks = []
                    if not pab_config.get('BlockPublicAcls', False):
                        missing_blocks.append('BlockPublicAcls')
                    if not pab_config.get('IgnorePublicAcls', False):
                        missing_blocks.append('IgnorePublicAcls')
                    if not pab_config.get('BlockPublicPolicy', False):
                        missing_blocks.append('BlockPublicPolicy')
                    if not pab_config.get('RestrictPublicBuckets', False):
                        missing_blocks.append('RestrictPublicBuckets')
                    
                    findings.append(Finding(
                        severity=Severity.HIGH,
                        category=Category.DATA_PROTECTION,
                        resource_type="AWS::S3::Bucket",
                        resource_id=bucket_name,
                        region=region or "global",
                        account_id=self.account_id,
                        title="S3 Bucket Public Access Not Fully Blocked",
                        description=f"S3 bucket '{bucket_name}' does not have all public access block settings enabled.",
                        impact="Bucket may be exposed to public access, potentially leaking sensitive data.",
                        recommendation="Enable all public access block settings unless public access is explicitly required.",
                        compliance_frameworks=[ComplianceFramework.NIST, ComplianceFramework.CIS],
                        automated_remediation_available=True,
                        evidence={
                            "bucket_name": bucket_name,
                            "missing_blocks": missing_blocks,
                            "current_settings": pab_config
                        }
                    ))
                    
            except ClientError as e:
                if e.response['Error']['Code'] == 'NoSuchPublicAccessBlockConfiguration':
                    # No public access block configured at all
                    findings.append(Finding(
                        severity=Severity.HIGH,
                        category=Category.DATA_PROTECTION,
                        resource_type="AWS::S3::Bucket",
                        resource_id=bucket_name,
                        region=region or "global",
                        account_id=self.account_id,
                        title="S3 Bucket Without Public Access Block",
                        description=f"S3 bucket '{bucket_name}' does not have public access block configuration.",
                        impact="Bucket is vulnerable to accidental public exposure through ACLs or bucket policies.",
                        recommendation="Enable public access block configuration with all settings set to true.",
                        compliance_frameworks=[ComplianceFramework.NIST, ComplianceFramework.CIS],
                        automated_remediation_available=True,
                        evidence={
                            "bucket_name": bucket_name,
                            "public_access_block_configured": False
                        }
                    ))
                else:
                    raise
                    
        except ClientError as e:
            self._handle_error(e, f"public access check for bucket {bucket_name}")
        
        return findings
    
    def _check_bucket_versioning(self, s3_client, bucket_name: str, region: str) -> List[Finding]:
        """Check if bucket versioning is enabled"""
        findings = []
        
        try:
            versioning = s3_client.get_bucket_versioning(Bucket=bucket_name)
            status = versioning.get('Status', 'Disabled')
            
            if status != 'Enabled':
                findings.append(Finding(
                    severity=Severity.MEDIUM,
                    category=Category.DATA_PROTECTION,
                    resource_type="AWS::S3::Bucket",
                    resource_id=bucket_name,
                    region=region or "global",
                    account_id=self.account_id,
                    title="S3 Bucket Versioning Not Enabled",
                    description=f"S3 bucket '{bucket_name}' does not have versioning enabled.",
                    impact="Cannot recover from accidental deletions or overwrites. No protection against ransomware.",
                    recommendation="Enable versioning to protect against accidental data loss and maintain data integrity.",
                    compliance_frameworks=[ComplianceFramework.NIST, ComplianceFramework.SOX],
                    automated_remediation_available=True,
                    evidence={
                        "bucket_name": bucket_name,
                        "versioning_status": status
                    }
                ))
                
        except ClientError as e:
            self._handle_error(e, f"versioning check for bucket {bucket_name}")
        
        return findings
    
    def _check_bucket_logging(self, s3_client, bucket_name: str, region: str) -> List[Finding]:
        """Check if bucket logging is enabled"""
        findings = []
        
        try:
            logging_config = s3_client.get_bucket_logging(Bucket=bucket_name)
            
            if 'LoggingEnabled' not in logging_config:
                findings.append(Finding(
                    severity=Severity.MEDIUM,
                    category=Category.LOGGING,
                    resource_type="AWS::S3::Bucket",
                    resource_id=bucket_name,
                    region=region or "global",
                    account_id=self.account_id,
                    title="S3 Bucket Access Logging Not Enabled",
                    description=f"S3 bucket '{bucket_name}' does not have access logging enabled.",
                    impact="Cannot audit access to bucket objects. Limited visibility for security investigations.",
                    recommendation="Enable S3 access logging to track requests made to the bucket.",
                    compliance_frameworks=[ComplianceFramework.NIST, ComplianceFramework.CIS, ComplianceFramework.SOX],
                    automated_remediation_available=True,
                    evidence={
                        "bucket_name": bucket_name,
                        "logging_enabled": False
                    }
                ))
                
        except ClientError as e:
            self._handle_error(e, f"logging check for bucket {bucket_name}")
        
        return findings
    
    def _check_bucket_lifecycle(self, s3_client, bucket_name: str, region: str) -> List[Finding]:
        """Check if bucket has lifecycle policies"""
        findings = []
        
        try:
            try:
                lifecycle = s3_client.get_bucket_lifecycle_configuration(Bucket=bucket_name)
                has_lifecycle = len(lifecycle.get('Rules', [])) > 0
            except ClientError as e:
                if e.response['Error']['Code'] == 'NoSuchLifecycleConfiguration':
                    has_lifecycle = False
                else:
                    raise
            
            if not has_lifecycle:
                findings.append(Finding(
                    severity=Severity.LOW,
                    category=Category.COST_OPTIMIZATION,
                    resource_type="AWS::S3::Bucket",
                    resource_id=bucket_name,
                    region=region or "global",
                    account_id=self.account_id,
                    title="S3 Bucket Without Lifecycle Policy",
                    description=f"S3 bucket '{bucket_name}' does not have lifecycle policies configured.",
                    impact="May result in unnecessary storage costs and retention of outdated data.",
                    recommendation="Configure lifecycle policies to automatically transition or expire objects based on age.",
                    compliance_frameworks=[ComplianceFramework.NIST],
                    automated_remediation_available=False,
                    evidence={
                        "bucket_name": bucket_name,
                        "has_lifecycle_policy": False
                    }
                ))
                
        except ClientError as e:
            self._handle_error(e, f"lifecycle check for bucket {bucket_name}")
        
        return findings
    
    def _check_bucket_policy(self, s3_client, bucket_name: str, region: str) -> List[Finding]:
        """Check bucket policy for security issues"""
        findings = []
        
        try:
            try:
                policy_response = s3_client.get_bucket_policy(Bucket=bucket_name)
                policy = json.loads(policy_response['Policy'])
                
                # Check for overly permissive policies
                for statement in policy.get('Statement', []):
                    # Check for wildcard principal
                    principal = statement.get('Principal', {})
                    if principal == '*' or (isinstance(principal, dict) and principal.get('AWS') == '*'):
                        if statement.get('Effect') == 'Allow':
                            findings.append(Finding(
                                severity=Severity.HIGH,
                                category=Category.ACCESS_CONTROL,
                                resource_type="AWS::S3::Bucket",
                                resource_id=bucket_name,
                                region=region or "global",
                                account_id=self.account_id,
                                title="S3 Bucket Policy Allows Public Access",
                                description=f"S3 bucket '{bucket_name}' has a policy that allows access to everyone.",
                                impact="Bucket contents may be accessible to unauthorized users.",
                                recommendation="Restrict bucket policy to specific principals and add conditions.",
                                compliance_frameworks=[ComplianceFramework.NIST, ComplianceFramework.CIS],
                                automated_remediation_available=False,
                                evidence={
                                    "bucket_name": bucket_name,
                                    "statement_sid": statement.get('Sid', 'No SID'),
                                    "actions": statement.get('Action', [])
                                }
                            ))
                    
                    # Check for missing SSL enforcement
                    has_ssl_condition = False
                    conditions = statement.get('Condition', {})
                    for condition_type, condition_values in conditions.items():
                        if 'aws:SecureTransport' in str(condition_values):
                            has_ssl_condition = True
                            break
                    
                    if not has_ssl_condition and statement.get('Effect') == 'Allow':
                        findings.append(Finding(
                            severity=Severity.MEDIUM,
                            category=Category.DATA_PROTECTION,
                            resource_type="AWS::S3::Bucket",
                            resource_id=bucket_name,
                            region=region or "global",
                            account_id=self.account_id,
                            title="S3 Bucket Policy Does Not Enforce SSL",
                            description=f"S3 bucket '{bucket_name}' policy does not require SSL/TLS for access.",
                            impact="Data may be transmitted in plain text over the network.",
                            recommendation="Add a condition to deny requests when aws:SecureTransport is false.",
                            compliance_frameworks=[ComplianceFramework.NIST],
                            automated_remediation_available=True,
                            evidence={
                                "bucket_name": bucket_name,
                                "statement_sid": statement.get('Sid', 'No SID')
                            }
                        ))
                        
            except ClientError as e:
                if e.response['Error']['Code'] != 'NoSuchBucketPolicy':
                    raise
                    
        except ClientError as e:
            self._handle_error(e, f"policy check for bucket {bucket_name}")
        
        return findings
    
    def _check_bucket_acl(self, s3_client, bucket_name: str, region: str) -> List[Finding]:
        """Check bucket ACL for public access"""
        findings = []
        
        try:
            acl = s3_client.get_bucket_acl(Bucket=bucket_name)
            
            # Check for public access grants
            for grant in acl.get('Grants', []):
                grantee = grant.get('Grantee', {})
                permission = grant.get('Permission', '')
                
                # Check if grant is to AllUsers or AuthenticatedUsers
                if grantee.get('Type') == 'Group':
                    uri = grantee.get('URI', '')
                    if 'AllUsers' in uri or 'AuthenticatedUsers' in uri:
                        findings.append(Finding(
                            severity=Severity.HIGH,
                            category=Category.ACCESS_CONTROL,
                            resource_type="AWS::S3::Bucket",
                            resource_id=bucket_name,
                            region=region or "global",
                            account_id=self.account_id,
                            title="S3 Bucket ACL Allows Public Access",
                            description=f"S3 bucket '{bucket_name}' ACL grants {permission} to {uri.split('/')[-1]}.",
                            impact="Bucket may be accessible to unauthorized users.",
                            recommendation="Remove public access grants and use bucket policies for access control.",
                            compliance_frameworks=[ComplianceFramework.NIST, ComplianceFramework.CIS],
                            automated_remediation_available=True,
                            evidence={
                                "bucket_name": bucket_name,
                                "grantee": uri.split('/')[-1],
                                "permission": permission
                            }
                        ))
                        
        except ClientError as e:
            self._handle_error(e, f"ACL check for bucket {bucket_name}")
        
        return findings
    
    def _check_object_lock(self, s3_client, bucket_name: str, region: str) -> List[Finding]:
        """Check if Object Lock is enabled for compliance buckets"""
        findings = []
        
        try:
            # Check if bucket name suggests it contains compliance data
            compliance_keywords = ['backup', 'archive', 'compliance', 'audit', 'legal', 'retain']
            is_compliance_bucket = any(keyword in bucket_name.lower() for keyword in compliance_keywords)
            
            if is_compliance_bucket:
                try:
                    object_lock = s3_client.get_object_lock_configuration(Bucket=bucket_name)
                    has_object_lock = object_lock.get('ObjectLockConfiguration', {}).get('ObjectLockEnabled') == 'Enabled'
                except ClientError as e:
                    if e.response['Error']['Code'] == 'ObjectLockConfigurationNotFoundError':
                        has_object_lock = False
                    else:
                        raise
                
                if not has_object_lock:
                    findings.append(Finding(
                        severity=Severity.MEDIUM,
                        category=Category.DATA_PROTECTION,
                        resource_type="AWS::S3::Bucket",
                        resource_id=bucket_name,
                        region=region or "global",
                        account_id=self.account_id,
                        title="Compliance Bucket Without Object Lock",
                        description=f"S3 bucket '{bucket_name}' appears to be for compliance but lacks Object Lock.",
                        impact="Cannot guarantee immutability of compliance data. Risk of tampering or deletion.",
                        recommendation="Enable Object Lock for compliance and backup buckets.",
                        compliance_frameworks=[ComplianceFramework.SOX],
                        automated_remediation_available=False,
                        evidence={
                            "bucket_name": bucket_name,
                            "object_lock_enabled": False,
                            "compliance_keywords_found": [kw for kw in compliance_keywords if kw in bucket_name.lower()]
                        }
                    ))
                    
        except ClientError as e:
            self._handle_error(e, f"object lock check for bucket {bucket_name}")
        
        return findings