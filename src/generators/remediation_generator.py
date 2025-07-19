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
            "IAM User Without MFA": self._generate_enforce_mfa_script,
            "Inactive IAM User": self._generate_disable_inactive_user_script,
            "Unused IAM User": self._generate_disable_unused_user_script,
            "Weak Password Length Requirement": self._generate_password_policy_script,
            "No Password Policy Configured": self._generate_password_policy_script,
            "Password Expiration Not Configured": self._generate_password_policy_script,
            "Service Account with Console Access": self._generate_remove_console_access_script,
            "Old Access Key Needs Rotation": self._generate_access_key_rotation_reminder,
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
            action_prefix = "[DRY RUN] " if dry_run else "[APPLIED] "
            print(f"{action_prefix}{action}: {resource}")
        
        def confirm_action(prompt):
            if DRY_RUN:
                return True
            response = input(f"{prompt} (yes/no): ").lower()
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
    
    def _load_templates(self) -> Dict[str, str]:
        """Load remediation templates"""
        # This could be extended to load from files
        return {}