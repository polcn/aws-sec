from typing import List, Dict, Any, Optional
from datetime import datetime
from ..models import Finding, RemediationScript, Severity, Category
import textwrap


class RemediationGenerator:
    """Generates remediation scripts for security findings"""
    
    def __init__(self):
        self.templates = self._load_templates()
    
    def generate_remediation_script(self, finding: Finding) -> Optional[RemediationScript]:
        """Generate a remediation script for a specific finding"""
        
        # Map finding titles to remediation methods
        remediation_map = {
            # IAM findings
            "IAM User Without MFA": self._generate_enforce_mfa_script,
            "User Without MFA Enforcement Policy": self._generate_enforce_mfa_script,
            "Inactive IAM User": self._generate_disable_inactive_user_script,
            "Unused IAM User": self._generate_disable_unused_user_script,
            "Weak Password Length Requirement": self._generate_password_policy_script,
            "No Password Policy Configured": self._generate_password_policy_script,
            "Password Expiration Not Configured": self._generate_password_policy_script,
            "Service Account with Console Access": self._generate_remove_console_access_script,
            "Old Access Key Needs Rotation": self._generate_access_key_rotation_reminder,
            # S3 findings
            "S3 Bucket Without Encryption": self._generate_s3_encryption_script,
            "S3 Bucket Using SSE-S3 Instead of SSE-KMS": self._generate_s3_kms_encryption_script,
            "S3 Bucket Public Access Not Fully Blocked": self._generate_s3_block_public_access_script,
            "S3 Bucket Without Public Access Block": self._generate_s3_block_public_access_script,
            "S3 Bucket Versioning Not Enabled": self._generate_s3_versioning_script,
            "S3 Bucket Access Logging Not Enabled": self._generate_s3_logging_script,
            "S3 Bucket Policy Does Not Enforce SSL": self._generate_s3_ssl_policy_script,
            "S3 Bucket ACL Allows Public Access": self._generate_s3_remove_public_acl_script,
            # EC2 findings
            "EC2 Instance Not Enforcing IMDSv2": self._generate_ec2_imdsv2_script,
            "EBS Volume Not Encrypted": self._generate_ebs_encryption_script,
            "Security Group Allows Ingress from Internet": self._generate_sg_restriction_script,
            "Security Group Allows Egress from Internet": self._generate_sg_restriction_script,
            # VPC findings
            "VPC Flow Logs Not Enabled": self._generate_vpc_flow_logs_script,
            "VPC Missing Recommended Endpoints": self._generate_vpc_endpoints_script,
            "NAT Gateway in Private Subnet": self._generate_nat_gateway_fix_script,
            # RDS findings
            "RDS Instance Not Encrypted": self._generate_rds_encryption_reminder,
            "RDS Cluster Not Encrypted": self._generate_rds_encryption_reminder,
            "Insufficient Backup Retention Period": self._generate_rds_backup_retention_script,
            "Automated Backups Disabled": self._generate_rds_backup_retention_script,
            "RDS Instance Publicly Accessible": self._generate_rds_disable_public_access_script,
            "Multi-AZ Not Enabled": self._generate_rds_multi_az_script,
            "Deletion Protection Not Enabled": self._generate_rds_deletion_protection_script,
            "Auto Minor Version Upgrade Disabled": self._generate_rds_auto_upgrade_script,
            "Performance Insights Not Enabled": self._generate_rds_performance_insights_script,
            "IAM Database Authentication Not Enabled": self._generate_rds_iam_auth_script,
        }
        
        # Find matching remediation generator
        for pattern, generator in remediation_map.items():
            if pattern in finding.title:
                return generator(finding)
        
        return None
    
    def generate_batch_remediation_script(self, findings: List[Finding]) -> str:
        """Generate a batch remediation script for multiple findings"""
        script_parts = [self._generate_header()]
        
        # Group findings by type for efficient remediation
        grouped_findings = self._group_findings_by_type(findings)
        
        for finding_type, findings_list in grouped_findings.items():
            if finding_type == "mfa":
                script_parts.append(self._generate_batch_mfa_enforcement(findings_list))
            elif finding_type == "inactive_users":
                script_parts.append(self._generate_batch_user_cleanup(findings_list))
            elif finding_type == "password_policy":
                script_parts.append(self._generate_comprehensive_password_policy())
        
        script_parts.append(self._generate_footer())
        
        return "\n\n".join(script_parts)
    
    def _generate_header(self) -> str:
        """Generate script header"""
        return textwrap.dedent(f"""
        #!/usr/bin/env python3
        '''
        AWS Security Remediation Script
        Generated: {datetime.utcnow().isoformat()}
        
        This script addresses security findings identified by the AWS Security Tool.
        Please review each remediation before execution.
        
        Requirements:
        - Python 3.6+
        - boto3
        - Appropriate AWS permissions
        '''
        
        import boto3
        import sys
        import json
        from datetime import datetime
        from botocore.exceptions import ClientError
        
        # Initialize AWS clients
        iam = boto3.client('iam')
        
        # Dry run mode - set to False to apply changes
        DRY_RUN = True
        
        def log_action(action, resource, dry_run=True):
            prefix = "[DRY RUN] " if dry_run else "[APPLIED] "
            print(prefix + action + ": " + resource)
        
        def confirm_action(prompt):
            if DRY_RUN:
                return True
            response = input(prompt + " (yes/no): ").lower()
            return response == 'yes'
        """).strip()
    
    def _generate_footer(self) -> str:
        """Generate script footer"""
        return textwrap.dedent("""
        if __name__ == "__main__":
            print("AWS Security Remediation Script")
            print("=" * 50)
            
            if DRY_RUN:
                print("\\nRunning in DRY RUN mode - no changes will be made")
                print("Set DRY_RUN = False to apply changes\\n")
            else:
                print("\\nWARNING: This script will make changes to your AWS account")
                if not confirm_action("Do you want to continue?"):
                    print("Aborted.")
                    sys.exit(0)
            
            try:
                main()
                print("\\nRemediation complete!")
            except Exception as e:
                print(f"\\nError during remediation: {e}")
                sys.exit(1)
        """).strip()
    
    def _generate_enforce_mfa_script(self, finding: Finding) -> RemediationScript:
        """Generate script to enforce MFA for a user"""
        user_name = finding.evidence.get('user_name', 'unknown')
        
        script_content = self._generate_header() + textwrap.dedent(f"""
        
        def enforce_mfa_for_user(user_name):
            '''Enforce MFA requirement for IAM user'''
            
            # Note: This creates an inline policy that denies most actions without MFA
            policy_name = 'ForceMFAPolicy'
            policy_document = {{
                "Version": "2012-10-17",
                "Statement": [
                    {{
                        "Sid": "AllowViewAccountInfo",
                        "Effect": "Allow",
                        "Action": [
                            "iam:GetUser",
                            "iam:ListMFADevices"
                        ],
                        "Resource": "*"
                    }},
                    {{
                        "Sid": "AllowManageOwnMFA",
                        "Effect": "Allow",
                        "Action": [
                            "iam:CreateVirtualMFADevice",
                            "iam:EnableMFADevice",
                            "iam:ResyncMFADevice"
                        ],
                        "Resource": [
                            f"arn:aws:iam::*:mfa/${{aws:username}}",
                            f"arn:aws:iam::*:user/${{aws:username}}"
                        ]
                    }},
                    {{
                        "Sid": "DenyAllExceptListedIfNoMFA",
                        "Effect": "Deny",
                        "NotAction": [
                            "iam:CreateVirtualMFADevice",
                            "iam:EnableMFADevice",
                            "iam:GetUser",
                            "iam:ListMFADevices",
                            "iam:ResyncMFADevice",
                            "sts:GetSessionToken"
                        ],
                        "Resource": "*",
                        "Condition": {{
                            "BoolIfExists": {{
                                "aws:MultiFactorAuthPresent": "false"
                            }}
                        }}
                    }}
                ]
            }}
            
            try:
                if not DRY_RUN:
                    iam.put_user_policy(
                        UserName=user_name,
                        PolicyName=policy_name,
                        PolicyDocument=json.dumps(policy_document)
                    )
                log_action(f"Applied MFA enforcement policy", user_name, DRY_RUN)
                return True
            except ClientError as e:
                print(f"Error enforcing MFA for {{user_name}}: {{e}}")
                return False
        
        def main():
            print(f"Enforcing MFA for user: {user_name}")
            if confirm_action(f"Apply MFA enforcement policy to {user_name}?"):
                enforce_mfa_for_user("{user_name}")
        
        """) + self._generate_footer()
        
        return RemediationScript(
            finding_id=finding.finding_id,
            script_name=f"enforce_mfa_{user_name}.py",
            description=f"Enforce MFA requirement for user {user_name}",
            script_content=script_content,
            prerequisites="User must set up MFA device after this policy is applied",
            rollback_instructions=f"Remove the 'ForceMFAPolicy' inline policy from user {user_name}",
            estimated_impact="User will be unable to perform most actions until MFA is configured",
            requires_confirmation=True
        )
    
    def _generate_disable_inactive_user_script(self, finding: Finding) -> RemediationScript:
        """Generate script to disable inactive user"""
        user_name = finding.evidence.get('user_name', 'unknown')
        days_inactive = finding.evidence.get('days_inactive', 'unknown')
        
        script_content = self._generate_header() + textwrap.dedent(f"""
        
        def disable_user_credentials(user_name):
            '''Disable all credentials for an inactive user'''
            
            actions_taken = []
            
            # Disable console access
            try:
                iam.delete_login_profile(UserName=user_name)
                log_action("Removed console access", user_name, DRY_RUN)
                actions_taken.append("console_access_removed")
            except ClientError as e:
                if e.response['Error']['Code'] != 'NoSuchEntity':
                    print(f"Error removing console access: {{e}}")
            
            # Deactivate access keys
            try:
                access_keys = iam.list_access_keys(UserName=user_name)
                for key in access_keys.get('AccessKeyMetadata', []):
                    if key['Status'] == 'Active':
                        if not DRY_RUN:
                            iam.update_access_key(
                                UserName=user_name,
                                AccessKeyId=key['AccessKeyId'],
                                Status='Inactive'
                            )
                        log_action(f"Deactivated access key {{key['AccessKeyId']}}", user_name, DRY_RUN)
                        actions_taken.append(f"key_{{key['AccessKeyId']}}_deactivated")
            except ClientError as e:
                print(f"Error deactivating access keys: {{e}}")
            
            # Add tag to indicate user was auto-disabled
            try:
                if not DRY_RUN:
                    iam.tag_user(
                        UserName=user_name,
                        Tags=[
                            {{
                                'Key': 'AutoDisabled',
                                'Value': datetime.utcnow().isoformat()
                            }},
                            {{
                                'Key': 'DisableReason',
                                'Value': f'Inactive for {days_inactive} days'
                            }}
                        ]
                    )
                log_action("Tagged user as auto-disabled", user_name, DRY_RUN)
            except ClientError as e:
                print(f"Error tagging user: {{e}}")
            
            return actions_taken
        
        def main():
            print(f"Disabling inactive user: {user_name}")
            print(f"User has been inactive for {days_inactive} days")
            
            if confirm_action(f"Disable all credentials for {user_name}?"):
                actions = disable_user_credentials("{user_name}")
                print(f"\\nCompleted actions: {{', '.join(actions)}}")
        
        """) + self._generate_footer()
        
        return RemediationScript(
            finding_id=finding.finding_id,
            script_name=f"disable_inactive_user_{user_name}.py",
            description=f"Disable credentials for inactive user {user_name}",
            script_content=script_content,
            prerequisites="Ensure user is truly inactive and not needed",
            rollback_instructions="Re-enable access keys and recreate login profile if needed",
            estimated_impact="User will lose all access to AWS",
            requires_confirmation=True
        )
    
    def _generate_disable_unused_user_script(self, finding: Finding) -> RemediationScript:
        """Generate script to disable unused user"""
        # Similar to inactive user but with different messaging
        user_name = finding.evidence.get('user_name', 'unknown')
        
        script_content = self._generate_header() + textwrap.dedent(f"""
        
        def remove_unused_user(user_name):
            '''Remove an unused IAM user'''
            
            # First, remove all dependencies
            try:
                # Remove from groups
                groups = iam.list_groups_for_user(UserName=user_name)
                for group in groups.get('Groups', []):
                    if not DRY_RUN:
                        iam.remove_user_from_group(
                            GroupName=group['GroupName'],
                            UserName=user_name
                        )
                    log_action(f"Removed from group {{group['GroupName']}}", user_name, DRY_RUN)
                
                # Delete access keys
                access_keys = iam.list_access_keys(UserName=user_name)
                for key in access_keys.get('AccessKeyMetadata', []):
                    if not DRY_RUN:
                        iam.delete_access_key(
                            UserName=user_name,
                            AccessKeyId=key['AccessKeyId']
                        )
                    log_action(f"Deleted access key {{key['AccessKeyId']}}", user_name, DRY_RUN)
                
                # Delete login profile
                try:
                    if not DRY_RUN:
                        iam.delete_login_profile(UserName=user_name)
                    log_action("Deleted login profile", user_name, DRY_RUN)
                except ClientError as e:
                    if e.response['Error']['Code'] != 'NoSuchEntity':
                        raise
                
                # Delete inline policies
                policies = iam.list_user_policies(UserName=user_name)
                for policy_name in policies.get('PolicyNames', []):
                    if not DRY_RUN:
                        iam.delete_user_policy(
                            UserName=user_name,
                            PolicyName=policy_name
                        )
                    log_action(f"Deleted inline policy {{policy_name}}", user_name, DRY_RUN)
                
                # Detach managed policies
                attached_policies = iam.list_attached_user_policies(UserName=user_name)
                for policy in attached_policies.get('AttachedPolicies', []):
                    if not DRY_RUN:
                        iam.detach_user_policy(
                            UserName=user_name,
                            PolicyArn=policy['PolicyArn']
                        )
                    log_action(f"Detached policy {{policy['PolicyName']}}", user_name, DRY_RUN)
                
                # Finally, delete the user
                if not DRY_RUN:
                    iam.delete_user(UserName=user_name)
                log_action("Deleted user", user_name, DRY_RUN)
                
                return True
                
            except ClientError as e:
                print(f"Error removing user {{user_name}}: {{e}}")
                return False
        
        def main():
            print(f"Removing unused user: {user_name}")
            print("This user has never been used and has no activity.")
            
            if confirm_action(f"Permanently delete user {user_name} and all associated resources?"):
                if remove_unused_user("{user_name}"):
                    print("User successfully removed")
                else:
                    print("Failed to remove user completely")
        
        """) + self._generate_footer()
        
        return RemediationScript(
            finding_id=finding.finding_id,
            script_name=f"remove_unused_user_{user_name}.py",
            description=f"Remove unused IAM user {user_name}",
            script_content=script_content,
            prerequisites="Verify user is not needed by any applications or services",
            rollback_instructions="User deletion cannot be undone - recreate user if needed",
            estimated_impact="Permanent deletion of user and all associated resources",
            requires_confirmation=True
        )
    
    def _generate_password_policy_script(self, finding: Finding) -> RemediationScript:
        """Generate script to update password policy"""
        script_content = self._generate_header() + textwrap.dedent("""
        
        def update_password_policy():
            '''Update account password policy to meet security requirements'''
            
            policy_params = {
                'MinimumPasswordLength': 14,
                'RequireSymbols': True,
                'RequireNumbers': True,
                'RequireUppercaseCharacters': True,
                'RequireLowercaseCharacters': True,
                'AllowUsersToChangePassword': True,
                'MaxPasswordAge': 90,
                'PasswordReusePrevention': 5,
                'HardExpiry': False
            }
            
            try:
                if not DRY_RUN:
                    iam.update_account_password_policy(**policy_params)
                
                log_action("Updated password policy", "Account", DRY_RUN)
                print("\\nNew password policy settings:")
                for key, value in policy_params.items():
                    print(f"  - {key}: {value}")
                
                return True
                
            except ClientError as e:
                print(f"Error updating password policy: {e}")
                return False
        
        def main():
            print("Updating account password policy")
            print("This will enforce stronger password requirements for all users")
            
            if confirm_action("Update account password policy?"):
                if update_password_policy():
                    print("\\nPassword policy successfully updated")
                    print("Note: Existing passwords will expire based on the new policy")
        
        """) + self._generate_footer()
        
        return RemediationScript(
            finding_id=finding.finding_id,
            script_name="update_password_policy.py",
            description="Update account password policy to meet security standards",
            script_content=script_content,
            prerequisites="Have communication plan for users about new password requirements",
            rollback_instructions="Modify the policy parameters and re-run the script",
            estimated_impact="Users will need to update passwords on next expiration",
            requires_confirmation=True
        )
    
    def _generate_remove_console_access_script(self, finding: Finding) -> RemediationScript:
        """Generate script to remove console access from service account"""
        user_name = finding.evidence.get('user_name', 'unknown')
        
        script_content = self._generate_header() + textwrap.dedent(f"""
        
        def remove_console_access(user_name):
            '''Remove console access from service account'''
            
            try:
                # Check if login profile exists
                try:
                    iam.get_login_profile(UserName=user_name)
                    has_login_profile = True
                except ClientError as e:
                    if e.response['Error']['Code'] == 'NoSuchEntity':
                        has_login_profile = False
                        print(f"User {{user_name}} already has no console access")
                        return True
                    else:
                        raise
                
                if has_login_profile:
                    if not DRY_RUN:
                        iam.delete_login_profile(UserName=user_name)
                    log_action("Removed console access", user_name, DRY_RUN)
                    
                    # Add tag to indicate this is a service account
                    if not DRY_RUN:
                        iam.tag_user(
                            UserName=user_name,
                            Tags=[
                                {{
                                    'Key': 'AccountType',
                                    'Value': 'Service'
                                }},
                                {{
                                    'Key': 'ConsoleAccessRemoved',
                                    'Value': datetime.utcnow().isoformat()
                                }}
                            ]
                        )
                    log_action("Tagged as service account", user_name, DRY_RUN)
                
                return True
                
            except ClientError as e:
                print(f"Error removing console access: {{e}}")
                return False
        
        def main():
            print(f"Removing console access from service account: {user_name}")
            print("Service accounts should only have programmatic access")
            
            if confirm_action(f"Remove console access from {user_name}?"):
                if remove_console_access("{user_name}"):
                    print("Console access successfully removed")
        
        """) + self._generate_footer()
        
        return RemediationScript(
            finding_id=finding.finding_id,
            script_name=f"remove_console_access_{user_name}.py",
            description=f"Remove console access from service account {user_name}",
            script_content=script_content,
            prerequisites="Ensure this is truly a service account and not a human user",
            rollback_instructions=f"Create new login profile for user {user_name} if needed",
            estimated_impact="User will no longer be able to log into AWS Console",
            requires_confirmation=True
        )
    
    def _generate_access_key_rotation_reminder(self, finding: Finding) -> RemediationScript:
        """Generate script with instructions for access key rotation"""
        user_name = finding.evidence.get('user_name', 'unknown')
        key_age = finding.evidence.get('key_age_days', 'unknown')
        
        script_content = textwrap.dedent(f"""
        #!/usr/bin/env python3
        '''
        Access Key Rotation Guide for {user_name}
        
        This access key is {key_age} days old and should be rotated.
        Access key rotation requires coordination with the key user.
        '''
        
        print("Access Key Rotation Process:")
        print("=" * 50)
        print(f"User: {user_name}")
        print(f"Key Age: {key_age} days")
        print()
        print("Steps to rotate access key:")
        print("1. Create a new access key for the user")
        print("2. Update all applications/services with the new key")
        print("3. Test that everything works with the new key")
        print("4. Deactivate the old key (don't delete yet)")
        print("5. Monitor for any issues for 24-48 hours")
        print("6. Delete the old key once confirmed working")
        print()
        print("AWS CLI commands:")
        print(f"  aws iam create-access-key --user-name {user_name}")
        print(f"  aws iam update-access-key --user-name {user_name} --access-key-id OLD_KEY_ID --status Inactive")
        print(f"  aws iam delete-access-key --user-name {user_name} --access-key-id OLD_KEY_ID")
        """)
        
        return RemediationScript(
            finding_id=finding.finding_id,
            script_name=f"rotate_access_key_{user_name}.py",
            description=f"Instructions for rotating access key for {user_name}",
            script_content=script_content,
            prerequisites="Identify all systems using this access key",
            rollback_instructions="Reactivate old key if issues arise",
            estimated_impact="Temporary service disruption if not coordinated properly",
            requires_confirmation=False
        )
    
    def _generate_s3_encryption_script(self, finding: Finding) -> RemediationScript:
        """Generate script to enable S3 bucket encryption"""
        bucket_name = finding.evidence.get('bucket_name', 'unknown')
        
        script_content = self._generate_header() + textwrap.dedent(f"""
        
        s3 = boto3.client('s3')
        
        def enable_bucket_encryption(bucket_name):
            '''Enable default encryption for S3 bucket'''
            
            encryption_configuration = {{
                'Rules': [{{
                    'ApplyServerSideEncryptionByDefault': {{
                        'SSEAlgorithm': 'AES256'
                    }}
                }}]
            }}
            
            try:
                if not DRY_RUN:
                    s3.put_bucket_encryption(
                        Bucket=bucket_name,
                        ServerSideEncryptionConfiguration=encryption_configuration
                    )
                log_action("Enabled SSE-S3 encryption", bucket_name, DRY_RUN)
                return True
            except ClientError as e:
                print(f"Error enabling encryption for {{bucket_name}}: {{e}}")
                return False
        
        def main():
            print(f"Enabling encryption for S3 bucket: {bucket_name}")
            if confirm_action(f"Enable SSE-S3 encryption for bucket {bucket_name}?"):
                if enable_bucket_encryption("{bucket_name}"):
                    print("Encryption successfully enabled")
        
        """) + self._generate_footer()
        
        return RemediationScript(
            finding_id=finding.finding_id,
            script_name=f"enable_s3_encryption_{bucket_name}.py",
            description=f"Enable SSE-S3 encryption for bucket {bucket_name}",
            script_content=script_content,
            prerequisites="Ensure no applications depend on unencrypted access",
            rollback_instructions="Remove encryption configuration if issues arise",
            estimated_impact="Minimal - encryption is transparent to applications",
            requires_confirmation=True
        )
    
    def _generate_s3_kms_encryption_script(self, finding: Finding) -> RemediationScript:
        """Generate script to upgrade S3 encryption to KMS"""
        bucket_name = finding.evidence.get('bucket_name', 'unknown')
        
        script_content = self._generate_header() + textwrap.dedent(f"""
        
        s3 = boto3.client('s3')
        
        def upgrade_to_kms_encryption(bucket_name, kms_key_id=None):
            '''Upgrade bucket encryption from SSE-S3 to SSE-KMS'''
            
            # If no KMS key specified, use AWS managed key
            encryption_configuration = {{
                'Rules': [{{
                    'ApplyServerSideEncryptionByDefault': {{
                        'SSEAlgorithm': 'aws:kms'
                    }}
                }}]
            }}
            
            if kms_key_id:
                encryption_configuration['Rules'][0]['ApplyServerSideEncryptionByDefault']['KMSMasterKeyID'] = kms_key_id
            
            try:
                if not DRY_RUN:
                    s3.put_bucket_encryption(
                        Bucket=bucket_name,
                        ServerSideEncryptionConfiguration=encryption_configuration
                    )
                log_action("Upgraded to SSE-KMS encryption", bucket_name, DRY_RUN)
                return True
            except ClientError as e:
                print(f"Error upgrading encryption for {{bucket_name}}: {{e}}")
                return False
        
        def main():
            print(f"Upgrading encryption to SSE-KMS for S3 bucket: {bucket_name}")
            print("Note: This will use AWS managed KMS key. Specify a custom key if needed.")
            
            if confirm_action(f"Upgrade to SSE-KMS encryption for bucket {bucket_name}?"):
                if upgrade_to_kms_encryption("{bucket_name}"):
                    print("Encryption successfully upgraded to SSE-KMS")
        
        """) + self._generate_footer()
        
        return RemediationScript(
            finding_id=finding.finding_id,
            script_name=f"upgrade_s3_kms_encryption_{bucket_name}.py",
            description=f"Upgrade bucket {bucket_name} from SSE-S3 to SSE-KMS encryption",
            script_content=script_content,
            prerequisites="Ensure IAM roles have KMS permissions if using custom key",
            rollback_instructions="Revert to SSE-S3 if KMS permissions cause issues",
            estimated_impact="May require IAM policy updates for KMS access",
            requires_confirmation=True
        )
    
    def _generate_s3_block_public_access_script(self, finding: Finding) -> RemediationScript:
        """Generate script to block public access on S3 bucket"""
        bucket_name = finding.evidence.get('bucket_name', 'unknown')
        
        script_content = self._generate_header() + textwrap.dedent(f"""
        
        s3 = boto3.client('s3')
        
        def block_public_access(bucket_name):
            '''Enable all public access block settings for S3 bucket'''
            
            public_access_block_config = {{
                'BlockPublicAcls': True,
                'IgnorePublicAcls': True,
                'BlockPublicPolicy': True,
                'RestrictPublicBuckets': True
            }}
            
            try:
                if not DRY_RUN:
                    s3.put_public_access_block(
                        Bucket=bucket_name,
                        PublicAccessBlockConfiguration=public_access_block_config
                    )
                log_action("Enabled public access block", bucket_name, DRY_RUN)
                
                # List current settings
                print("\\nPublic Access Block Settings:")
                for setting, value in public_access_block_config.items():
                    print(f"  {{setting}}: {{value}}")
                
                return True
            except ClientError as e:
                print(f"Error blocking public access for {{bucket_name}}: {{e}}")
                return False
        
        def main():
            print(f"Blocking public access for S3 bucket: {bucket_name}")
            print("This will prevent all public access to the bucket.")
            
            if confirm_action(f"Block all public access for bucket {bucket_name}?"):
                if block_public_access("{bucket_name}"):
                    print("\\nPublic access successfully blocked")
                    print("Note: Existing public policies and ACLs will be ignored")
        
        """) + self._generate_footer()
        
        return RemediationScript(
            finding_id=finding.finding_id,
            script_name=f"block_s3_public_access_{bucket_name}.py",
            description=f"Block all public access for bucket {bucket_name}",
            script_content=script_content,
            prerequisites="Ensure no legitimate public access is required",
            rollback_instructions="Disable specific block settings if public access needed",
            estimated_impact="Will block all public access - ensure this is intended",
            requires_confirmation=True
        )
    
    def _generate_s3_versioning_script(self, finding: Finding) -> RemediationScript:
        """Generate script to enable S3 bucket versioning"""
        bucket_name = finding.evidence.get('bucket_name', 'unknown')
        
        script_content = self._generate_header() + textwrap.dedent(f"""
        
        s3 = boto3.client('s3')
        
        def enable_versioning(bucket_name):
            '''Enable versioning for S3 bucket'''
            
            versioning_configuration = {{
                'Status': 'Enabled'
            }}
            
            try:
                if not DRY_RUN:
                    s3.put_bucket_versioning(
                        Bucket=bucket_name,
                        VersioningConfiguration=versioning_configuration
                    )
                log_action("Enabled versioning", bucket_name, DRY_RUN)
                
                # Get current versioning status
                if not DRY_RUN:
                    response = s3.get_bucket_versioning(Bucket=bucket_name)
                    print(f"\\nVersioning Status: {{response.get('Status', 'Disabled')}}")
                
                return True
            except ClientError as e:
                print(f"Error enabling versioning for {{bucket_name}}: {{e}}")
                return False
        
        def main():
            print(f"Enabling versioning for S3 bucket: {bucket_name}")
            print("This will keep multiple versions of each object.")
            print("Consider setting up lifecycle policies to manage old versions.")
            
            if confirm_action(f"Enable versioning for bucket {bucket_name}?"):
                if enable_versioning("{bucket_name}"):
                    print("\\nVersioning successfully enabled")
                    print("Tip: Configure lifecycle policies to expire old versions")
        
        """) + self._generate_footer()
        
        return RemediationScript(
            finding_id=finding.finding_id,
            script_name=f"enable_s3_versioning_{bucket_name}.py",
            description=f"Enable versioning for bucket {bucket_name}",
            script_content=script_content,
            prerequisites="Plan for increased storage costs from multiple versions",
            rollback_instructions="Suspend versioning if storage costs become excessive",
            estimated_impact="Increased storage costs due to multiple object versions",
            requires_confirmation=True
        )
    
    def _generate_s3_logging_script(self, finding: Finding) -> RemediationScript:
        """Generate script to enable S3 access logging"""
        bucket_name = finding.evidence.get('bucket_name', 'unknown')
        
        script_content = self._generate_header() + textwrap.dedent(f"""
        
        s3 = boto3.client('s3')
        
        def enable_access_logging(bucket_name, target_bucket, target_prefix):
            '''Enable access logging for S3 bucket'''
            
            logging_config = {{
                'LoggingEnabled': {{
                    'TargetBucket': target_bucket,
                    'TargetPrefix': target_prefix
                }}
            }}
            
            try:
                # First, grant log delivery permissions to target bucket
                if not DRY_RUN:
                    # Get current ACL
                    acl = s3.get_bucket_acl(Bucket=target_bucket)
                    
                    # Add log delivery group
                    log_delivery_grant = {{
                        'Grantee': {{
                            'Type': 'Group',
                            'URI': 'http://acs.amazonaws.com/groups/s3/LogDelivery'
                        }},
                        'Permission': 'WRITE'
                    }}
                    
                    if log_delivery_grant not in acl['Grants']:
                        acl['Grants'].append(log_delivery_grant)
                        
                        # Put updated ACL
                        s3.put_bucket_acl(
                            Bucket=target_bucket,
                            AccessControlPolicy={{
                                'Grants': acl['Grants'],
                                'Owner': acl['Owner']
                            }}
                        )
                
                # Enable logging
                if not DRY_RUN:
                    s3.put_bucket_logging(
                        Bucket=bucket_name,
                        BucketLoggingStatus=logging_config
                    )
                
                log_action(f"Enabled access logging to {{target_bucket}}/{{target_prefix}}", bucket_name, DRY_RUN)
                return True
                
            except ClientError as e:
                print(f"Error enabling logging for {{bucket_name}}: {{e}}")
                return False
        
        def main():
            print(f"Enabling access logging for S3 bucket: {bucket_name}")
            print("\\nYou need to specify:")
            print("1. Target bucket for logs (can be the same bucket)")
            print("2. Prefix for log files (e.g., 'logs/')")
            
            # For this example, we'll use the same bucket with 'access-logs/' prefix
            target_bucket = "{bucket_name}"
            target_prefix = "access-logs/"
            
            print(f"\\nLogging configuration:")
            print(f"  Target bucket: {{target_bucket}}")
            print(f"  Target prefix: {{target_prefix}}")
            
            if confirm_action(f"Enable access logging for bucket {bucket_name}?"):
                if enable_access_logging("{bucket_name}", target_bucket, target_prefix):
                    print("\\nAccess logging successfully enabled")
                    print("Logs will be delivered to the specified location")
        
        """) + self._generate_footer()
        
        return RemediationScript(
            finding_id=finding.finding_id,
            script_name=f"enable_s3_logging_{bucket_name}.py",
            description=f"Enable access logging for bucket {bucket_name}",
            script_content=script_content,
            prerequisites="Decide on target bucket and prefix for logs",
            rollback_instructions="Disable logging configuration if not needed",
            estimated_impact="Additional storage costs for access logs",
            requires_confirmation=True
        )
    
    def _generate_s3_ssl_policy_script(self, finding: Finding) -> RemediationScript:
        """Generate script to enforce SSL in bucket policy"""
        bucket_name = finding.evidence.get('bucket_name', 'unknown')
        
        script_content = self._generate_header() + textwrap.dedent(f"""
        
        s3 = boto3.client('s3')
        
        def add_ssl_enforcement_to_policy(bucket_name):
            '''Add SSL enforcement to bucket policy'''
            
            # Get current bucket policy
            try:
                response = s3.get_bucket_policy(Bucket=bucket_name)
                policy = json.loads(response['Policy'])
            except ClientError as e:
                if e.response['Error']['Code'] == 'NoSuchBucketPolicy':
                    # Create new policy
                    policy = {{
                        "Version": "2012-10-17",
                        "Statement": []
                    }}
                else:
                    raise
            
            # SSL enforcement statement
            ssl_statement = {{
                "Sid": "DenyInsecureConnections",
                "Effect": "Deny",
                "Principal": "*",
                "Action": "s3:*",
                "Resource": [
                    f"arn:aws:s3:::{bucket_name}/*",
                    f"arn:aws:s3:::{bucket_name}"
                ],
                "Condition": {{
                    "Bool": {{
                        "aws:SecureTransport": "false"
                    }}
                }}
            }}
            
            # Check if SSL enforcement already exists
            ssl_exists = False
            for statement in policy['Statement']:
                if statement.get('Sid') == 'DenyInsecureConnections':
                    ssl_exists = True
                    break
            
            if not ssl_exists:
                policy['Statement'].append(ssl_statement)
                
                try:
                    if not DRY_RUN:
                        s3.put_bucket_policy(
                            Bucket=bucket_name,
                            Policy=json.dumps(policy)
                        )
                    log_action("Added SSL enforcement to bucket policy", bucket_name, DRY_RUN)
                    return True
                except ClientError as e:
                    print(f"Error updating bucket policy: {{e}}")
                    return False
            else:
                print("SSL enforcement already exists in bucket policy")
                return True
        
        def main():
            print(f"Enforcing SSL/TLS for S3 bucket: {bucket_name}")
            print("This will deny all non-HTTPS requests to the bucket.")
            
            if confirm_action(f"Add SSL enforcement to bucket {bucket_name} policy?"):
                if add_ssl_enforcement_to_policy("{bucket_name}"):
                    print("\\nSSL enforcement successfully added")
                    print("All future requests must use HTTPS")
        
        """) + self._generate_footer()
        
        return RemediationScript(
            finding_id=finding.finding_id,
            script_name=f"enforce_s3_ssl_{bucket_name}.py",
            description=f"Enforce SSL/TLS for bucket {bucket_name}",
            script_content=script_content,
            prerequisites="Ensure all clients support HTTPS",
            rollback_instructions="Remove the DenyInsecureConnections statement from policy",
            estimated_impact="HTTP requests will be denied - ensure all clients use HTTPS",
            requires_confirmation=True
        )
    
    def _generate_s3_remove_public_acl_script(self, finding: Finding) -> RemediationScript:
        """Generate script to remove public access from bucket ACL"""
        bucket_name = finding.evidence.get('bucket_name', 'unknown')
        grantee = finding.evidence.get('grantee', 'unknown')
        
        script_content = self._generate_header() + textwrap.dedent(f"""
        
        s3 = boto3.client('s3')
        
        def remove_public_acl_grants(bucket_name):
            '''Remove public access grants from bucket ACL'''
            
            try:
                # Get current ACL
                acl = s3.get_bucket_acl(Bucket=bucket_name)
                
                # Filter out public grants
                public_uris = [
                    'http://acs.amazonaws.com/groups/global/AllUsers',
                    'http://acs.amazonaws.com/groups/global/AuthenticatedUsers'
                ]
                
                original_grant_count = len(acl['Grants'])
                filtered_grants = []
                
                for grant in acl['Grants']:
                    grantee = grant.get('Grantee', {{}})
                    if grantee.get('Type') == 'Group' and grantee.get('URI') in public_uris:
                        log_action(f"Removing public grant: {{grant.get('Permission')}}", grantee.get('URI'), DRY_RUN)
                    else:
                        filtered_grants.append(grant)
                
                if len(filtered_grants) < original_grant_count:
                    # Update ACL
                    if not DRY_RUN:
                        s3.put_bucket_acl(
                            Bucket=bucket_name,
                            AccessControlPolicy={{
                                'Grants': filtered_grants,
                                'Owner': acl['Owner']
                            }}
                        )
                    
                    removed_count = original_grant_count - len(filtered_grants)
                    log_action(f"Removed {{removed_count}} public grants", bucket_name, DRY_RUN)
                    return True
                else:
                    print("No public grants found in bucket ACL")
                    return True
                    
            except ClientError as e:
                print(f"Error updating bucket ACL: {{e}}")
                return False
        
        def main():
            print(f"Removing public access from S3 bucket ACL: {bucket_name}")
            print(f"This will remove grants to: {grantee}")
            
            if confirm_action(f"Remove public ACL grants from bucket {bucket_name}?"):
                if remove_public_acl_grants("{bucket_name}"):
                    print("\\nPublic ACL grants successfully removed")
                    print("Consider using bucket policies for access control instead")
        
        """) + self._generate_footer()
        
        return RemediationScript(
            finding_id=finding.finding_id,
            script_name=f"remove_s3_public_acl_{bucket_name}.py",
            description=f"Remove public ACL grants from bucket {bucket_name}",
            script_content=script_content,
            prerequisites="Ensure no legitimate public access is required",
            rollback_instructions="Re-add specific ACL grants if needed",
            estimated_impact="Public access via ACL will be removed",
            requires_confirmation=True
        )
    
    def _group_findings_by_type(self, findings: List[Finding]) -> Dict[str, List[Finding]]:
        """Group findings by remediation type"""
        groups = {
            'mfa': [],
            'inactive_users': [],
            'password_policy': [],
            'access_keys': [],
            'other': []
        }
        
        for finding in findings:
            if 'MFA' in finding.title:
                groups['mfa'].append(finding)
            elif 'Inactive' in finding.title or 'Unused' in finding.title:
                groups['inactive_users'].append(finding)
            elif 'Password' in finding.title:
                groups['password_policy'].append(finding)
            elif 'Access Key' in finding.title:
                groups['access_keys'].append(finding)
            else:
                groups['other'].append(finding)
        
        return {k: v for k, v in groups.items() if v}
    
    def _generate_batch_mfa_enforcement(self, findings: List[Finding]) -> str:
        """Generate batch MFA enforcement for multiple users"""
        users = [f.evidence.get('user_name', '') for f in findings if f.evidence.get('user_name')]
        
        return textwrap.dedent(f"""
        def enforce_mfa_batch():
            '''Enforce MFA for multiple users'''
            users_without_mfa = {users}
            
            print(f"Enforcing MFA for {{len(users_without_mfa)}} users")
            
            for user in users_without_mfa:
                print(f"\\nProcessing user: {{user}}")
                enforce_mfa_for_user(user)
        """)
    
    def _generate_batch_user_cleanup(self, findings: List[Finding]) -> str:
        """Generate batch cleanup for inactive users"""
        users = [f.evidence.get('user_name', '') for f in findings if f.evidence.get('user_name')]
        
        return textwrap.dedent(f"""
        def cleanup_inactive_users():
            '''Cleanup multiple inactive users'''
            inactive_users = {users}
            
            print(f"Processing {{len(inactive_users)}} inactive users")
            
            for user in inactive_users:
                print(f"\\nProcessing user: {{user}}")
                if confirm_action(f"Disable credentials for {{user}}?"):
                    disable_user_credentials(user)
        """)
    
    def _generate_comprehensive_password_policy(self) -> str:
        """Generate comprehensive password policy update"""
        return textwrap.dedent("""
        def apply_comprehensive_password_policy():
            '''Apply comprehensive password policy'''
            
            print("Applying comprehensive password policy...")
            update_password_policy()
            
            # Additional password policy checks
            try:
                policy = iam.get_account_password_policy()['PasswordPolicy']
                print("\\nCurrent password policy:")
                for key, value in policy.items():
                    print(f"  {key}: {value}")
            except ClientError as e:
                print(f"Error retrieving password policy: {e}")
        """)
    
    def _generate_ec2_imdsv2_script(self, finding: Finding) -> RemediationScript:
        """Generate script to enforce IMDSv2 on EC2 instance"""
        instance_id = finding.resource_id
        region = finding.region
        
        script_content = textwrap.dedent(f"""
        #!/usr/bin/env python3
        '''
        Remediation: Enable IMDSv2 enforcement for EC2 instance
        Finding: {finding.title}
        Resource: {instance_id}
        '''
        
        import boto3
        from botocore.exceptions import ClientError
        
        def enforce_imdsv2(instance_id, region):
            '''Enforce IMDSv2 on EC2 instance'''
            ec2 = boto3.client('ec2', region_name=region)
            
            try:
                response = ec2.modify_instance_metadata_options(
                    InstanceId=instance_id,
                    HttpTokens='required',
                    HttpPutResponseHopLimit=1,
                    HttpEndpoint='enabled'
                )
                print(f"Successfully enforced IMDSv2 on instance {{instance_id}}")
                return True
            except ClientError as e:
                print(f"Error enforcing IMDSv2: {{e}}")
                return False
        
        if __name__ == "__main__":
            instance_id = "{instance_id}"
            region = "{region}"
            
            print(f"Enforcing IMDSv2 on instance {{instance_id}} in region {{region}}")
            if enforce_imdsv2(instance_id, region):
                print("Remediation completed successfully")
            else:
                print("Remediation failed")
        """)
        
        return RemediationScript(
            finding_id=finding.id,
            title=f"Enable IMDSv2 for {instance_id}",
            description="Enforce Instance Metadata Service version 2 for better security",
            script_type="python",
            script_content=script_content,
            risk_level="low",
            estimated_impact="Minimal - applications using IMDSv1 may need updates"
        )
    
    def _generate_ebs_encryption_script(self, finding: Finding) -> RemediationScript:
        """Generate script to enable EBS encryption"""
        volume_id = finding.resource_id
        region = finding.region
        
        script_content = textwrap.dedent(f"""
        #!/usr/bin/env python3
        '''
        Remediation: Enable default EBS encryption for the region
        Finding: {finding.title}
        Note: Cannot encrypt existing unencrypted volumes. Must create encrypted snapshot and new volume.
        '''
        
        import boto3
        from botocore.exceptions import ClientError
        
        def enable_ebs_encryption_by_default(region):
            '''Enable EBS encryption by default for the region'''
            ec2 = boto3.client('ec2', region_name=region)
            
            try:
                response = ec2.enable_ebs_encryption_by_default()
                if response['EbsEncryptionByDefault']:
                    print(f"Successfully enabled EBS encryption by default in {{region}}")
                    return True
            except ClientError as e:
                print(f"Error enabling EBS encryption: {{e}}")
                return False
        
        def create_encrypted_volume_from_snapshot(volume_id, region):
            '''Create encrypted copy of unencrypted volume'''
            ec2 = boto3.client('ec2', region_name=region)
            
            print(f"Creating encrypted copy of volume {{volume_id}}...")
            print("Note: This is a manual process requiring:")
            print("1. Create snapshot of the unencrypted volume")
            print("2. Copy snapshot with encryption enabled")
            print("3. Create new encrypted volume from snapshot")
            print("4. Stop instance and replace volume")
            print("\\nRecommended AWS CLI commands:")
            print(f"aws ec2 create-snapshot --volume-id {{volume_id}} --region {{region}}")
            print("aws ec2 copy-snapshot --source-snapshot-id <snapshot-id> --encrypted --region {{region}}")
            print("aws ec2 create-volume --snapshot-id <encrypted-snapshot-id> --encrypted --region {{region}}")
        
        if __name__ == "__main__":
            volume_id = "{volume_id}"
            region = "{region}"
            
            print(f"Enabling EBS encryption by default for region {{region}}")
            if enable_ebs_encryption_by_default(region):
                print("\\nDefault encryption enabled for new volumes")
                print(f"\\nFor existing volume {{volume_id}}:")
                create_encrypted_volume_from_snapshot(volume_id, region)
            else:
                print("Failed to enable default encryption")
        """)
        
        return RemediationScript(
            finding_id=finding.id,
            title=f"Enable EBS encryption for {volume_id}",
            description="Enable default EBS encryption and provide guidance for encrypting existing volume",
            script_type="python",
            script_content=script_content,
            risk_level="medium",
            estimated_impact="Requires downtime to replace unencrypted volumes"
        )
    
    def _generate_sg_restriction_script(self, finding: Finding) -> RemediationScript:
        """Generate script to restrict security group rules"""
        sg_id = finding.resource_id
        region = finding.region
        metadata = finding.evidence or {}
        
        script_content = textwrap.dedent(f"""
        #!/usr/bin/env python3
        '''
        Remediation: Restrict overly permissive security group rule
        Finding: {finding.title}
        Resource: {sg_id}
        '''
        
        import boto3
        from botocore.exceptions import ClientError
        
        def restrict_security_group_rule(sg_id, region, rule_direction, protocol, from_port, to_port):
            '''Remove overly permissive rule and suggest replacement'''
            ec2 = boto3.client('ec2', region_name=region)
            
            try:
                if rule_direction == 'ingress':
                    # Revoke the overly permissive rule
                    if protocol == '-1':
                        ec2.revoke_security_group_ingress(
                            GroupId=sg_id,
                            IpPermissions=[{{
                                'IpProtocol': '-1',
                                'IpRanges': [{{'CidrIp': '0.0.0.0/0'}}]
                            }}]
                        )
                    else:
                        ec2.revoke_security_group_ingress(
                            GroupId=sg_id,
                            IpPermissions=[{{
                                'IpProtocol': protocol,
                                'FromPort': from_port,
                                'ToPort': to_port,
                                'IpRanges': [{{'CidrIp': '0.0.0.0/0'}}]
                            }}]
                        )
                    print(f"Successfully revoked overly permissive ingress rule from {{sg_id}}")
                    
                    # Suggest adding more restrictive rules
                    print("\\nSuggested replacements:")
                    print("1. Restrict to specific IP ranges (e.g., corporate network)")
                    print("2. Use VPN or bastion host for management access")
                    print("3. For web traffic, consider using ALB/CloudFront")
                    
                else:
                    print("Note: Egress rules to 0.0.0.0/0 are often necessary for internet access")
                    print("Consider using VPC endpoints for AWS services to reduce internet exposure")
                
                return True
                
            except ClientError as e:
                print(f"Error modifying security group: {{e}}")
                return False
        
        if __name__ == "__main__":
            sg_id = "{sg_id}"
            region = "{region}"
            rule_direction = "{metadata.get('rule_direction', 'ingress')}"
            protocol = "{metadata.get('protocol', '-1')}"
            from_port = {metadata.get('from_port', -1)}
            to_port = {metadata.get('to_port', -1)}
            
            print(f"Restricting security group {{sg_id}} in region {{region}}")
            print(f"Rule: {{rule_direction}} {{protocol}} ports {{from_port}}-{{to_port}} from 0.0.0.0/0")
            
            if input("\\nProceed with remediation? (yes/no): ").lower() == 'yes':
                if restrict_security_group_rule(sg_id, region, rule_direction, protocol, from_port, to_port):
                    print("\\nRemediation completed successfully")
                else:
                    print("\\nRemediation failed")
            else:
                print("\\nRemediation cancelled")
        """)
        
        return RemediationScript(
            finding_id=finding.id,
            title=f"Restrict security group {sg_id}",
            description=f"Remove overly permissive {metadata.get('rule_direction', 'ingress')} rule allowing 0.0.0.0/0",
            script_type="python",
            script_content=script_content,
            risk_level="high",
            estimated_impact="May disrupt connectivity - ensure alternative access before applying"
        )
    
    def _generate_vpc_flow_logs_script(self, finding: Finding) -> RemediationScript:
        """Generate script to enable VPC Flow Logs"""
        vpc_id = finding.resource_id
        region = finding.region
        
        script_content = textwrap.dedent(f"""
        #!/usr/bin/env python3
        '''
        Remediation: Enable VPC Flow Logs
        Finding: {finding.title}
        Resource: {vpc_id}
        '''
        
        import boto3
        from botocore.exceptions import ClientError
        import time
        
        def enable_vpc_flow_logs(vpc_id, region, log_destination_type='cloud-watch-logs'):
            '''Enable VPC Flow Logs for network traffic monitoring'''
            ec2 = boto3.client('ec2', region_name=region)
            logs = boto3.client('logs', region_name=region)
            iam = boto3.client('iam')
            
            try:
                # Create CloudWatch Logs group
                log_group_name = f'/aws/vpc/flowlogs/{{vpc_id}}'
                
                try:
                    logs.create_log_group(logGroupName=log_group_name)
                    print(f"Created CloudWatch Logs group: {{log_group_name}}")
                except logs.exceptions.ResourceAlreadyExistsException:
                    print(f"CloudWatch Logs group already exists: {{log_group_name}}")
                
                # Create IAM role for Flow Logs
                role_name = f'vpc-flow-logs-role-{{vpc_id}}'
                trust_policy = {{
                    'Version': '2012-10-17',
                    'Statement': [{{
                        'Effect': 'Allow',
                        'Principal': {{'Service': 'vpc-flow-logs.amazonaws.com'}},
                        'Action': 'sts:AssumeRole'
                    }}]
                }}
                
                try:
                    iam.create_role(
                        RoleName=role_name,
                        AssumeRolePolicyDocument=json.dumps(trust_policy),
                        Description='Role for VPC Flow Logs'
                    )
                    
                    # Attach policy to role
                    policy_document = {{
                        'Version': '2012-10-17',
                        'Statement': [{{
                            'Effect': 'Allow',
                            'Action': [
                                'logs:CreateLogGroup',
                                'logs:CreateLogStream',
                                'logs:PutLogEvents',
                                'logs:DescribeLogGroups',
                                'logs:DescribeLogStreams'
                            ],
                            'Resource': '*'
                        }}]
                    }}
                    
                    iam.put_role_policy(
                        RoleName=role_name,
                        PolicyName='vpc-flow-logs-policy',
                        PolicyDocument=json.dumps(policy_document)
                    )
                    
                    print(f"Created IAM role: {{role_name}}")
                    time.sleep(10)  # Wait for role to be available
                    
                except iam.exceptions.EntityAlreadyExistsException:
                    print(f"IAM role already exists: {{role_name}}")
                
                # Get role ARN
                role = iam.get_role(RoleName=role_name)
                role_arn = role['Role']['Arn']
                
                # Enable Flow Logs
                response = ec2.create_flow_logs(
                    ResourceIds=[vpc_id],
                    ResourceType='VPC',
                    TrafficType='ALL',
                    LogDestinationType=log_destination_type,
                    LogGroupName=log_group_name,
                    DeliverLogsPermissionArn=role_arn
                )
                
                if response['Unsuccessful']:
                    print(f"Failed to create flow logs: {{response['Unsuccessful']}}")
                    return False
                else:
                    flow_log_id = response['FlowLogIds'][0]
                    print(f"Successfully enabled VPC Flow Logs: {{flow_log_id}}")
                    print(f"Logs will be delivered to: {{log_group_name}}")
                    return True
                    
            except ClientError as e:
                print(f"Error enabling VPC Flow Logs: {{e}}")
                return False
        
        if __name__ == "__main__":
            vpc_id = "{vpc_id}"
            region = "{region}"
            
            print(f"Enabling Flow Logs for VPC {{vpc_id}} in region {{region}}")
            print("\\nThis will:")
            print("1. Create a CloudWatch Logs group")
            print("2. Create an IAM role for Flow Logs")
            print("3. Enable Flow Logs for ALL traffic")
            
            if input("\\nProceed with remediation? (yes/no): ").lower() == 'yes':
                if enable_vpc_flow_logs(vpc_id, region):
                    print("\\nRemediation completed successfully")
                    print("Note: Flow logs may take a few minutes to start appearing")
                else:
                    print("\\nRemediation failed")
            else:
                print("\\nRemediation cancelled")
        """)
        
        return RemediationScript(
            finding_id=finding.id,
            title=f"Enable Flow Logs for VPC {vpc_id}",
            description="Enable VPC Flow Logs for network traffic monitoring and security analysis",
            script_type="python",
            script_content=script_content,
            risk_level="low",
            estimated_impact="No service disruption - adds monitoring capability"
        )
    
    def _generate_vpc_endpoints_script(self, finding: Finding) -> RemediationScript:
        """Generate script to create VPC endpoints"""
        vpc_id = finding.resource_id
        region = finding.region
        missing_endpoints = finding.evidence.get('missing_endpoints', [])
        
        script_content = textwrap.dedent(f"""
        #!/usr/bin/env python3
        '''
        Remediation: Create recommended VPC endpoints
        Finding: {finding.title}
        Resource: {vpc_id}
        '''
        
        import boto3
        from botocore.exceptions import ClientError
        
        def create_vpc_endpoint(vpc_id, service_name, region, endpoint_type='Gateway'):
            '''Create VPC endpoint for AWS service'''
            ec2 = boto3.client('ec2', region_name=region)
            
            try:
                # Get route tables for the VPC
                route_tables = ec2.describe_route_tables(
                    Filters=[{{'Name': 'vpc-id', 'Values': [vpc_id]}}]
                )
                route_table_ids = [rt['RouteTableId'] for rt in route_tables['RouteTables']]
                
                # Create endpoint
                if endpoint_type == 'Gateway':
                    response = ec2.create_vpc_endpoint(
                        VpcId=vpc_id,
                        ServiceName=f'com.amazonaws.{{region}}.{{service_name}}',
                        RouteTableIds=route_table_ids
                    )
                else:
                    # For interface endpoints, get subnets
                    subnets = ec2.describe_subnets(
                        Filters=[{{'Name': 'vpc-id', 'Values': [vpc_id]}}]
                    )
                    subnet_ids = [subnet['SubnetId'] for subnet in subnets['Subnets']]
                    
                    response = ec2.create_vpc_endpoint(
                        VpcId=vpc_id,
                        ServiceName=f'com.amazonaws.{{region}}.{{service_name}}',
                        VpcEndpointType='Interface',
                        SubnetIds=subnet_ids
                    )
                
                endpoint_id = response['VpcEndpoint']['VpcEndpointId']
                print(f"Created VPC endpoint for {{service_name}}: {{endpoint_id}}")
                return endpoint_id
                
            except ClientError as e:
                if 'already exists' in str(e):
                    print(f"VPC endpoint for {{service_name}} already exists")
                else:
                    print(f"Error creating endpoint for {{service_name}}: {{e}}")
                return None
        
        def main():
            vpc_id = "{vpc_id}"
            region = "{region}"
            missing_endpoints = {missing_endpoints}
            
            # Service configurations
            service_configs = {{
                's3': {{'type': 'Gateway'}},
                'dynamodb': {{'type': 'Gateway'}},
                'ec2': {{'type': 'Interface'}},
                'sts': {{'type': 'Interface'}},
                'kms': {{'type': 'Interface'}}
            }}
            
            print(f"Creating VPC endpoints for VPC {{vpc_id}} in region {{region}}")
            print(f"Missing endpoints: {{', '.join(missing_endpoints)}}")
            
            created_count = 0
            for service in missing_endpoints:
                config = service_configs.get(service, {{'type': 'Interface'}})
                print(f"\\nCreating {{config['type']}} endpoint for {{service}}...")
                
                if create_vpc_endpoint(vpc_id, service, region, config['type']):
                    created_count += 1
            
            print(f"\\nCreated {{created_count}} out of {{len(missing_endpoints)}} endpoints")
            print("\\nNote: Interface endpoints may incur hourly charges")
            print("Gateway endpoints (S3, DynamoDB) are free")
        
        if __name__ == "__main__":
            if input("\\nProceed with creating VPC endpoints? (yes/no): ").lower() == 'yes':
                main()
            else:
                print("\\nRemediation cancelled")
        """)
        
        return RemediationScript(
            finding_id=finding.id,
            title=f"Create VPC endpoints for {vpc_id}",
            description=f"Create missing VPC endpoints for services: {', '.join(missing_endpoints)}",
            script_type="python",
            script_content=script_content,
            risk_level="low",
            estimated_impact="Interface endpoints incur hourly charges; improves security and may reduce data transfer costs"
        )
    
    def _generate_nat_gateway_fix_script(self, finding: Finding) -> RemediationScript:
        """Generate guidance for NAT Gateway configuration"""
        nat_gw_id = finding.resource_id
        region = finding.region
        
        script_content = textwrap.dedent(f"""
        #!/usr/bin/env python3
        '''
        Remediation: Fix NAT Gateway configuration
        Finding: {finding.title}
        Resource: {nat_gw_id}
        '''
        
        import boto3
        from botocore.exceptions import ClientError
        
        def check_nat_gateway_configuration(nat_gw_id, region):
            '''Check and provide guidance for NAT Gateway configuration'''
            ec2 = boto3.client('ec2', region_name=region)
            
            try:
                # Get NAT Gateway details
                response = ec2.describe_nat_gateways(NatGatewayIds=[nat_gw_id])
                nat_gateway = response['NatGateways'][0]
                
                subnet_id = nat_gateway['SubnetId']
                vpc_id = nat_gateway['VpcId']
                
                print(f"NAT Gateway {{nat_gw_id}} Configuration:")
                print(f"- VPC: {{vpc_id}}")
                print(f"- Subnet: {{subnet_id}}")
                print(f"- State: {{nat_gateway['State']}}")
                
                # Check subnet routing
                route_tables = ec2.describe_route_tables(
                    Filters=[
                        {{'Name': 'association.subnet-id', 'Values': [subnet_id]}}
                    ]
                )
                
                print("\\nSubnet Route Table Analysis:")
                for rt in route_tables['RouteTables']:
                    for route in rt['Routes']:
                        if route.get('GatewayId', '').startswith('igw-'):
                            print("✓ Subnet has route to Internet Gateway (public subnet)")
                            return True
                
                print("✗ Subnet does not have route to Internet Gateway")
                print("\\nRemediation Steps:")
                print("1. Create a new NAT Gateway in a public subnet")
                print("2. Update route tables to use the new NAT Gateway")
                print("3. Delete the incorrectly placed NAT Gateway")
                
                return False
                
            except ClientError as e:
                print(f"Error checking NAT Gateway: {{e}}")
                return False
        
        if __name__ == "__main__":
            nat_gw_id = "{nat_gw_id}"
            region = "{region}"
            
            print(f"Checking NAT Gateway {{nat_gw_id}} in region {{region}}")
            print("\\nNAT Gateways must be placed in public subnets to function correctly")
            
            if check_nat_gateway_configuration(nat_gw_id, region):
                print("\\nNAT Gateway is correctly configured")
            else:
                print("\\nManual remediation required - see steps above")
                print("\\nAWS CLI commands for remediation:")
                print("# 1. Create new NAT Gateway in public subnet:")
                print("aws ec2 create-nat-gateway --subnet-id <public-subnet-id> --allocation-id <eip-allocation-id>")
                print("\\n# 2. Update route table:")
                print("aws ec2 create-route --route-table-id <rtb-id> --destination-cidr-block 0.0.0.0/0 --nat-gateway-id <new-nat-gw-id>")
                print("\\n# 3. Delete old NAT Gateway:")
                print(f"aws ec2 delete-nat-gateway --nat-gateway-id {{nat_gw_id}}")
        """)
        
        return RemediationScript(
            finding_id=finding.id,
            title=f"Fix NAT Gateway {nat_gw_id} configuration",
            description="Provide guidance for moving NAT Gateway to public subnet",
            script_type="python",
            script_content=script_content,
            risk_level="high",
            estimated_impact="Requires creating new NAT Gateway and updating routes - plan for brief connectivity disruption"
        )
    
    def _generate_rds_encryption_reminder(self, finding: Finding) -> RemediationScript:
        """Generate reminder script for RDS encryption (requires data migration)"""
        resource_id = finding.resource_id
        region = finding.region
        
        script_content = textwrap.dedent(f"""
        #!/usr/bin/env python3
        '''
        Remediation: Enable encryption for RDS instance/cluster
        Finding: {finding.title}
        Resource: {resource_id}
        
        NOTE: Encryption cannot be enabled on existing RDS instances.
        You must create a new encrypted instance and migrate data.
        '''
        
        print("RDS ENCRYPTION REMEDIATION STEPS:")
        print("=" * 50)
        print()
        print("Encryption cannot be enabled on existing RDS instances/clusters.")
        print("You must create a new encrypted instance and migrate your data.")
        print()
        print("Steps to remediate:")
        print("1. Create a snapshot of the existing database:")
        print(f"   aws rds create-db-snapshot --db-instance-identifier {resource_id} \\\\")
        print(f"        --db-snapshot-identifier {resource_id}-migration-snapshot")
        print()
        print("2. Copy the snapshot with encryption enabled:")
        print(f"   aws rds copy-db-snapshot --source-db-snapshot-identifier {resource_id}-migration-snapshot \\\\")
        print(f"        --target-db-snapshot-identifier {resource_id}-encrypted-snapshot \\\\")
        print("        --kms-key-id alias/aws/rds")
        print()
        print("3. Restore from the encrypted snapshot:")
        print(f"   aws rds restore-db-instance-from-db-snapshot --db-instance-identifier {resource_id}-encrypted \\\\")
        print(f"        --db-snapshot-identifier {resource_id}-encrypted-snapshot")
        print()
        print("4. Update your application connection strings to use the new encrypted instance")
        print()
        print("5. After verifying the new instance works correctly, delete the old unencrypted instance")
        print()
        print("For automated migration scripts, see AWS Database Migration Service (DMS)")
        """)
        
        return RemediationScript(
            finding_id=finding.finding_id,
            title=f"Enable encryption for {resource_id}",
            description=f"Steps to migrate {resource_id} to an encrypted instance",
            script_type="python",
            script_content=script_content,
            risk_level="high",
            estimated_impact="Requires downtime for data migration"
        )
    
    def _generate_rds_backup_retention_script(self, finding: Finding) -> RemediationScript:
        """Generate script to configure RDS backup retention"""
        resource_id = finding.resource_id
        region = finding.region
        
        script_content = textwrap.dedent(f"""
        #!/usr/bin/env python3
        '''
        Remediation: Configure RDS backup retention
        Finding: {finding.title}
        Resource: {resource_id}
        '''
        
        import boto3
        from botocore.exceptions import ClientError
        
        def configure_backup_retention(db_identifier, region, retention_days=7):
            '''Configure backup retention for RDS instance'''
            rds = boto3.client('rds', region_name=region)
            
            try:
                response = rds.modify_db_instance(
                    DBInstanceIdentifier=db_identifier,
                    BackupRetentionPeriod=retention_days,
                    PreferredBackupWindow='03:00-04:00',  # 3-4 AM UTC
                    ApplyImmediately=True
                )
                print(f"Successfully configured backup retention for {{db_identifier}}")
                print(f"Retention period: {{retention_days}} days")
                print(f"Backup window: 03:00-04:00 UTC")
                return True
            except ClientError as e:
                print(f"Error configuring backup retention: {{e}}")
                if e.response['Error']['Code'] == 'InvalidDBInstanceState':
                    print("Instance may be in an invalid state. Please check AWS console.")
                return False
        
        if __name__ == "__main__":
            db_identifier = "{resource_id}"
            region = "{region}"
            
            print(f"Configuring backup retention for {{db_identifier}} in {{region}}")
            
            # Prompt for retention period
            retention = input("Enter backup retention period in days (recommended: 7-35): ")
            try:
                retention_days = int(retention)
                if retention_days < 1 or retention_days > 35:
                    print("Retention period must be between 1 and 35 days")
                    exit(1)
            except ValueError:
                print("Invalid retention period")
                exit(1)
            
            if configure_backup_retention(db_identifier, region, retention_days):
                print("\\nBackup retention configured successfully!")
            else:
                print("\\nFailed to configure backup retention")
        """)
        
        return RemediationScript(
            finding_id=finding.finding_id,
            title=f"Configure backup retention for {resource_id}",
            description=f"Enable and configure automated backups for RDS instance",
            script_type="python",
            script_content=script_content,
            risk_level="low",
            estimated_impact="No downtime - backup configuration change only"
        )
    
    def _generate_rds_disable_public_access_script(self, finding: Finding) -> RemediationScript:
        """Generate script to disable public access for RDS instance"""
        resource_id = finding.resource_id
        region = finding.region
        
        script_content = textwrap.dedent(f"""
        #!/usr/bin/env python3
        '''
        Remediation: Disable public access for RDS instance
        Finding: {finding.title}
        Resource: {resource_id}
        '''
        
        import boto3
        from botocore.exceptions import ClientError
        
        def disable_public_access(db_identifier, region):
            '''Disable public access for RDS instance'''
            rds = boto3.client('rds', region_name=region)
            
            try:
                response = rds.modify_db_instance(
                    DBInstanceIdentifier=db_identifier,
                    PubliclyAccessible=False,
                    ApplyImmediately=True
                )
                print(f"Successfully disabled public access for {{db_identifier}}")
                return True
            except ClientError as e:
                print(f"Error disabling public access: {{e}}")
                return False
        
        if __name__ == "__main__":
            db_identifier = "{resource_id}"
            region = "{region}"
            
            print(f"Disabling public access for {{db_identifier}} in {{region}}")
            print("\\nWARNING: This will prevent direct internet access to your database.")
            print("Ensure you have alternative access methods configured (VPN, bastion host, etc.)")
            
            confirm = input("\\nProceed with disabling public access? (yes/no): ")
            if confirm.lower() == 'yes':
                if disable_public_access(db_identifier, region):
                    print("\\nPublic access disabled successfully!")
                    print("Update your application connection methods as needed.")
                else:
                    print("\\nFailed to disable public access")
            else:
                print("\\nOperation cancelled")
        """)
        
        return RemediationScript(
            finding_id=finding.finding_id,
            title=f"Disable public access for {resource_id}",
            description=f"Remove public accessibility from RDS instance",
            script_type="python",
            script_content=script_content,
            risk_level="medium",
            estimated_impact="May affect connectivity - ensure alternative access methods exist"
        )
    
    def _generate_rds_multi_az_script(self, finding: Finding) -> RemediationScript:
        """Generate script to enable Multi-AZ for RDS instance"""
        resource_id = finding.resource_id
        region = finding.region
        
        script_content = textwrap.dedent(f"""
        #!/usr/bin/env python3
        '''
        Remediation: Enable Multi-AZ deployment for RDS instance
        Finding: {finding.title}
        Resource: {resource_id}
        '''
        
        import boto3
        from botocore.exceptions import ClientError
        
        def enable_multi_az(db_identifier, region):
            '''Enable Multi-AZ for RDS instance'''
            rds = boto3.client('rds', region_name=region)
            
            try:
                # First get instance details
                response = rds.describe_db_instances(DBInstanceIdentifier=db_identifier)
                instance = response['DBInstances'][0]
                
                if instance.get('ReadReplicaSourceDBInstanceIdentifier'):
                    print("This is a read replica - Multi-AZ not applicable")
                    return False
                
                print(f"Enabling Multi-AZ for {{db_identifier}}...")
                response = rds.modify_db_instance(
                    DBInstanceIdentifier=db_identifier,
                    MultiAZ=True,
                    ApplyImmediately=False  # Schedule for maintenance window
                )
                print(f"Successfully scheduled Multi-AZ enablement for {{db_identifier}}")
                print("Change will be applied during the next maintenance window")
                return True
            except ClientError as e:
                print(f"Error enabling Multi-AZ: {{e}}")
                return False
        
        if __name__ == "__main__":
            db_identifier = "{resource_id}"
            region = "{region}"
            
            print(f"Enabling Multi-AZ deployment for {{db_identifier}} in {{region}}")
            print("\\nNOTE: This operation will:")
            print("- Create a standby replica in another availability zone")
            print("- Increase costs (roughly double the instance cost)")
            print("- Provide automatic failover capability")
            print("- Be applied during maintenance window to minimize impact")
            
            confirm = input("\\nProceed with enabling Multi-AZ? (yes/no): ")
            if confirm.lower() == 'yes':
                if enable_multi_az(db_identifier, region):
                    print("\\nMulti-AZ enablement scheduled successfully!")
                else:
                    print("\\nFailed to enable Multi-AZ")
            else:
                print("\\nOperation cancelled")
        """)
        
        return RemediationScript(
            finding_id=finding.finding_id,
            title=f"Enable Multi-AZ for {resource_id}",
            description=f"Enable Multi-AZ deployment for high availability",
            script_type="python",
            script_content=script_content,
            risk_level="low",
            estimated_impact="Brief interruption during failover testing - applied in maintenance window"
        )
    
    def _generate_rds_deletion_protection_script(self, finding: Finding) -> RemediationScript:
        """Generate script to enable deletion protection for RDS"""
        resource_id = finding.resource_id
        region = finding.region
        resource_type = finding.resource_type
        
        script_content = textwrap.dedent(f"""
        #!/usr/bin/env python3
        '''
        Remediation: Enable deletion protection for RDS resource
        Finding: {finding.title}
        Resource: {resource_id}
        '''
        
        import boto3
        from botocore.exceptions import ClientError
        
        def enable_deletion_protection(resource_id, region, resource_type):
            '''Enable deletion protection for RDS instance or cluster'''
            rds = boto3.client('rds', region_name=region)
            
            try:
                if resource_type == 'DBCluster':
                    response = rds.modify_db_cluster(
                        DBClusterIdentifier=resource_id,
                        DeletionProtection=True,
                        ApplyImmediately=True
                    )
                else:
                    response = rds.modify_db_instance(
                        DBInstanceIdentifier=resource_id,
                        DeletionProtection=True,
                        ApplyImmediately=True
                    )
                print(f"Successfully enabled deletion protection for {{resource_id}}")
                return True
            except ClientError as e:
                print(f"Error enabling deletion protection: {{e}}")
                return False
        
        if __name__ == "__main__":
            resource_id = "{resource_id}"
            region = "{region}"
            resource_type = "{resource_type}"
            
            print(f"Enabling deletion protection for {{resource_id}} in {{region}}")
            
            if enable_deletion_protection(resource_id, region, resource_type):
                print("\\nDeletion protection enabled successfully!")
                print("This database cannot be deleted until protection is explicitly disabled.")
            else:
                print("\\nFailed to enable deletion protection")
        """)
        
        return RemediationScript(
            finding_id=finding.finding_id,
            title=f"Enable deletion protection for {resource_id}",
            description=f"Prevent accidental deletion of RDS resource",
            script_type="python",
            script_content=script_content,
            risk_level="low",
            estimated_impact="No downtime - adds safety protection only"
        )
    
    def _generate_rds_auto_upgrade_script(self, finding: Finding) -> RemediationScript:
        """Generate script to enable auto minor version upgrade"""
        resource_id = finding.resource_id
        region = finding.region
        
        script_content = textwrap.dedent(f"""
        #!/usr/bin/env python3
        '''
        Remediation: Enable auto minor version upgrade for RDS instance
        Finding: {finding.title}
        Resource: {resource_id}
        '''
        
        import boto3
        from botocore.exceptions import ClientError
        
        def enable_auto_upgrade(db_identifier, region):
            '''Enable auto minor version upgrade for RDS instance'''
            rds = boto3.client('rds', region_name=region)
            
            try:
                response = rds.modify_db_instance(
                    DBInstanceIdentifier=db_identifier,
                    AutoMinorVersionUpgrade=True,
                    ApplyImmediately=True
                )
                print(f"Successfully enabled auto minor version upgrade for {{db_identifier}}")
                print("Minor version updates will be applied during maintenance windows")
                return True
            except ClientError as e:
                print(f"Error enabling auto upgrade: {{e}}")
                return False
        
        if __name__ == "__main__":
            db_identifier = "{resource_id}"
            region = "{region}"
            
            print(f"Enabling auto minor version upgrade for {{db_identifier}} in {{region}}")
            print("\\nThis will automatically apply minor version patches during maintenance windows")
            print("Minor versions typically include security patches and bug fixes")
            
            if enable_auto_upgrade(db_identifier, region):
                print("\\nAuto minor version upgrade enabled successfully!")
            else:
                print("\\nFailed to enable auto upgrade")
        """)
        
        return RemediationScript(
            finding_id=finding.finding_id,
            title=f"Enable auto upgrade for {resource_id}",
            description=f"Enable automatic minor version upgrades for security patches",
            script_type="python",
            script_content=script_content,
            risk_level="low",
            estimated_impact="Updates applied during maintenance window"
        )
    
    def _generate_rds_performance_insights_script(self, finding: Finding) -> RemediationScript:
        """Generate script to enable Performance Insights"""
        resource_id = finding.resource_id
        region = finding.region
        
        script_content = textwrap.dedent(f"""
        #!/usr/bin/env python3
        '''
        Remediation: Enable Performance Insights for RDS instance
        Finding: {finding.title}
        Resource: {resource_id}
        '''
        
        import boto3
        from botocore.exceptions import ClientError
        
        def enable_performance_insights(db_identifier, region):
            '''Enable Performance Insights for RDS instance'''
            rds = boto3.client('rds', region_name=region)
            
            try:
                response = rds.modify_db_instance(
                    DBInstanceIdentifier=db_identifier,
                    EnablePerformanceInsights=True,
                    PerformanceInsightsRetentionPeriod=7,  # Free tier: 7 days
                    ApplyImmediately=True
                )
                print(f"Successfully enabled Performance Insights for {{db_identifier}}")
                print("Retention period: 7 days (free tier)")
                return True
            except ClientError as e:
                print(f"Error enabling Performance Insights: {{e}}")
                if 'not supported' in str(e):
                    print("Performance Insights may not be supported for this instance type")
                return False
        
        if __name__ == "__main__":
            db_identifier = "{resource_id}"
            region = "{region}"
            
            print(f"Enabling Performance Insights for {{db_identifier}} in {{region}}")
            print("\\nPerformance Insights provides database performance monitoring")
            print("Free tier includes 7 days of retention")
            
            if enable_performance_insights(db_identifier, region):
                print("\\nPerformance Insights enabled successfully!")
                print("Access via RDS console to view performance metrics")
            else:
                print("\\nFailed to enable Performance Insights")
        """)
        
        return RemediationScript(
            finding_id=finding.finding_id,
            title=f"Enable Performance Insights for {resource_id}",
            description=f"Enable database performance monitoring",
            script_type="python",
            script_content=script_content,
            risk_level="low",
            estimated_impact="No downtime - adds monitoring capability only"
        )
    
    def _generate_rds_iam_auth_script(self, finding: Finding) -> RemediationScript:
        """Generate script to enable IAM database authentication"""
        resource_id = finding.resource_id
        region = finding.region
        
        script_content = textwrap.dedent(f"""
        #!/usr/bin/env python3
        '''
        Remediation: Enable IAM database authentication for RDS instance
        Finding: {finding.title}
        Resource: {resource_id}
        '''
        
        import boto3
        from botocore.exceptions import ClientError
        
        def enable_iam_auth(db_identifier, region):
            '''Enable IAM database authentication for RDS instance'''
            rds = boto3.client('rds', region_name=region)
            
            try:
                # Get current instance details
                response = rds.describe_db_instances(DBInstanceIdentifier=db_identifier)
                instance = response['DBInstances'][0]
                engine = instance['Engine']
                
                supported_engines = ['mysql', 'postgres', 'mariadb']
                if engine not in supported_engines:
                    print(f"IAM authentication not supported for engine: {{engine}}")
                    return False
                
                response = rds.modify_db_instance(
                    DBInstanceIdentifier=db_identifier,
                    EnableIAMDatabaseAuthentication=True,
                    ApplyImmediately=True
                )
                print(f"Successfully enabled IAM authentication for {{db_identifier}}")
                return True
            except ClientError as e:
                print(f"Error enabling IAM authentication: {{e}}")
                return False
        
        if __name__ == "__main__":
            db_identifier = "{resource_id}"
            region = "{region}"
            
            print(f"Enabling IAM database authentication for {{db_identifier}} in {{region}}")
            print("\\nNOTE: After enabling, you'll need to:")
            print("1. Create database users that match IAM user/role names")
            print("2. Grant rds_iam role to these database users")
            print("3. Generate auth tokens using AWS CLI/SDK for connections")
            
            confirm = input("\\nProceed with enabling IAM authentication? (yes/no): ")
            if confirm.lower() == 'yes':
                if enable_iam_auth(db_identifier, region):
                    print("\\nIAM authentication enabled successfully!")
                    print("\\nExample MySQL setup:")
                    print("CREATE USER 'iam_user' IDENTIFIED WITH AWSAuthenticationPlugin AS 'RDS';")
                    print("GRANT SELECT ON mydb.* TO 'iam_user'@'%';")
                else:
                    print("\\nFailed to enable IAM authentication")
            else:
                print("\\nOperation cancelled")
        """)
        
        return RemediationScript(
            finding_id=finding.finding_id,
            title=f"Enable IAM authentication for {resource_id}",
            description=f"Enable IAM-based database authentication",
            script_type="python",
            script_content=script_content,
            risk_level="low",
            estimated_impact="No downtime - adds authentication option only"
        )
    
    def _load_templates(self) -> Dict[str, str]:
        """Load remediation templates"""
        # This could be extended to load from files
        return {}