import json
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any, Optional
import boto3
from botocore.exceptions import ClientError
from .base import BaseScanner
from ..models import Finding, Severity, Category, ComplianceFramework


class IAMScanner(BaseScanner):
    """Scanner for IAM security issues"""
    
    @property
    def service_name(self) -> str:
        return "iam"
    
    def scan(self) -> List[Finding]:
        """Perform IAM security scan"""
        findings = []
        
        try:
            iam = self.session.client('iam')
            
            # Scan various IAM components
            findings.extend(self._check_root_account_usage(iam))
            findings.extend(self._check_users_without_mfa(iam))
            findings.extend(self._check_inactive_users(iam))
            findings.extend(self._check_access_key_rotation(iam))
            findings.extend(self._check_overprivileged_policies(iam))
            findings.extend(self._check_password_policy(iam))
            findings.extend(self._check_unused_credentials(iam))
            findings.extend(self._check_service_accounts_with_console_access(iam))
            
        except ClientError as e:
            self._handle_error(e, "IAM scan")
        
        return findings
    
    def _check_root_account_usage(self, iam_client) -> List[Finding]:
        """Check for root account usage"""
        findings = []
        
        try:
            # Get credential report
            report = self._get_credential_report(iam_client)
            
            for user in report:
                if user.get('user') == '<root_account>':
                    # Check last used
                    if user.get('password_last_used') and user['password_last_used'] != 'N/A':
                        last_used = datetime.fromisoformat(user['password_last_used'].replace('Z', '+00:00'))
                        if (datetime.now(timezone.utc) - last_used).days < 90:
                            findings.append(Finding(
                                severity=Severity.CRITICAL,
                                category=Category.IAM,
                                resource_type="AWS::IAM::RootAccount",
                                resource_id="root",
                                region="global",
                                account_id=self.account_id,
                                title="Root Account Recently Used",
                                description="The root account has been used within the last 90 days.",
                                impact="Root account usage poses significant security risks as it has unrestricted access to all AWS services.",
                                recommendation="Enable MFA on root account, create individual IAM users for daily tasks, and avoid using root account.",
                                compliance_frameworks=[ComplianceFramework.NIST, ComplianceFramework.CIS],
                                automated_remediation_available=False,
                                evidence={
                                    "last_used": user.get('password_last_used'),
                                    "days_since_use": (datetime.now(timezone.utc) - last_used).days
                                }
                            ))
                    
                    # Check for access keys
                    if user.get('access_key_1_active') == 'true' or user.get('access_key_2_active') == 'true':
                        findings.append(Finding(
                            severity=Severity.CRITICAL,
                            category=Category.IAM,
                            resource_type="AWS::IAM::RootAccount",
                            resource_id="root",
                            region="global",
                            account_id=self.account_id,
                            title="Root Account Has Active Access Keys",
                            description="The root account has active access keys.",
                            impact="Root access keys provide unrestricted access and cannot be restricted by IAM policies.",
                            recommendation="Delete all root account access keys immediately.",
                            compliance_frameworks=[ComplianceFramework.NIST, ComplianceFramework.CIS],
                            automated_remediation_available=False,
                            evidence={
                                "access_key_1_active": user.get('access_key_1_active'),
                                "access_key_2_active": user.get('access_key_2_active')
                            }
                        ))
                    
                    # Check for MFA
                    if user.get('mfa_active') != 'true':
                        findings.append(Finding(
                            severity=Severity.CRITICAL,
                            category=Category.IAM,
                            resource_type="AWS::IAM::RootAccount",
                            resource_id="root",
                            region="global",
                            account_id=self.account_id,
                            title="Root Account MFA Not Enabled",
                            description="Multi-Factor Authentication is not enabled for the root account.",
                            impact="Without MFA, the root account is vulnerable to credential compromise.",
                            recommendation="Enable MFA for the root account immediately.",
                            compliance_frameworks=[ComplianceFramework.NIST, ComplianceFramework.CIS],
                            automated_remediation_available=False,
                            evidence={
                                "mfa_active": user.get('mfa_active', 'false')
                            }
                        ))
        
        except ClientError as e:
            self._handle_error(e, "root account check")
        
        return findings
    
    def _check_users_without_mfa(self, iam_client) -> List[Finding]:
        """Check for users without MFA enabled"""
        findings = []
        
        try:
            # Get all users
            users = self._paginate(iam_client, 'list_users')
            
            for user in users:
                user_name = user['UserName']
                
                # Check if user has password (console access)
                try:
                    iam_client.get_login_profile(UserName=user_name)
                    has_password = True
                except ClientError as e:
                    if e.response['Error']['Code'] == 'NoSuchEntity':
                        has_password = False
                    else:
                        raise
                
                if has_password:
                    # Check MFA devices
                    mfa_devices = iam_client.list_mfa_devices(UserName=user_name)
                    
                    if not mfa_devices['MFADevices']:
                        findings.append(Finding(
                            severity=Severity.HIGH,
                            category=Category.IAM,
                            resource_type="AWS::IAM::User",
                            resource_id=user_name,
                            region="global",
                            account_id=self.account_id,
                            title="IAM User Without MFA",
                            description=f"IAM user '{user_name}' has console access but no MFA device configured.",
                            impact="User accounts without MFA are more vulnerable to credential compromise.",
                            recommendation="Enable MFA for all users with console access.",
                            compliance_frameworks=[ComplianceFramework.NIST, ComplianceFramework.CIS],
                            automated_remediation_available=False,
                            evidence={
                                "user_name": user_name,
                                "has_console_access": True,
                                "mfa_enabled": False
                            }
                        ))
        
        except ClientError as e:
            self._handle_error(e, "MFA check")
        
        return findings
    
    def _check_inactive_users(self, iam_client) -> List[Finding]:
        """Check for inactive users"""
        findings = []
        inactive_days = 90
        
        try:
            report = self._get_credential_report(iam_client)
            
            for user in report:
                if user.get('user') == '<root_account>':
                    continue
                
                user_name = user.get('user')
                last_activity = None
                
                # Check password last used
                if user.get('password_last_used') and user['password_last_used'] != 'N/A':
                    last_activity = datetime.fromisoformat(user['password_last_used'].replace('Z', '+00:00'))
                
                # Check access key last used
                for key_num in ['1', '2']:
                    key_last_used = user.get(f'access_key_{key_num}_last_used_date')
                    if key_last_used and key_last_used != 'N/A':
                        key_date = datetime.fromisoformat(key_last_used.replace('Z', '+00:00'))
                        if not last_activity or key_date > last_activity:
                            last_activity = key_date
                
                # If user has never been active but has credentials
                if not last_activity and (user.get('password_enabled') == 'true' or 
                                        user.get('access_key_1_active') == 'true' or 
                                        user.get('access_key_2_active') == 'true'):
                    findings.append(Finding(
                        severity=Severity.MEDIUM,
                        category=Category.IAM,
                        resource_type="AWS::IAM::User",
                        resource_id=user_name,
                        region="global",
                        account_id=self.account_id,
                        title="Unused IAM User",
                        description=f"IAM user '{user_name}' has never been used but has active credentials.",
                        impact="Unused accounts with active credentials increase the attack surface.",
                        recommendation="Remove unused IAM users or deactivate their credentials.",
                        compliance_frameworks=[ComplianceFramework.NIST],
                        automated_remediation_available=True,
                        evidence={
                            "user_name": user_name,
                            "has_password": user.get('password_enabled') == 'true',
                            "has_access_keys": user.get('access_key_1_active') == 'true' or user.get('access_key_2_active') == 'true'
                        }
                    ))
                elif last_activity and (datetime.now(timezone.utc) - last_activity).days > inactive_days:
                    findings.append(Finding(
                        severity=Severity.MEDIUM,
                        category=Category.IAM,
                        resource_type="AWS::IAM::User",
                        resource_id=user_name,
                        region="global",
                        account_id=self.account_id,
                        title="Inactive IAM User",
                        description=f"IAM user '{user_name}' has been inactive for more than {inactive_days} days.",
                        impact="Inactive accounts with active credentials increase the attack surface.",
                        recommendation="Review and remove inactive IAM users or deactivate their credentials.",
                        compliance_frameworks=[ComplianceFramework.NIST],
                        automated_remediation_available=True,
                        evidence={
                            "user_name": user_name,
                            "last_activity": last_activity.isoformat() if last_activity else None,
                            "days_inactive": (datetime.now(timezone.utc) - last_activity).days if last_activity else None
                        }
                    ))
        
        except ClientError as e:
            self._handle_error(e, "inactive users check")
        
        return findings
    
    def _check_access_key_rotation(self, iam_client) -> List[Finding]:
        """Check for old access keys that need rotation"""
        findings = []
        max_key_age_days = 90
        
        try:
            report = self._get_credential_report(iam_client)
            
            for user in report:
                if user.get('user') == '<root_account>':
                    continue
                
                user_name = user.get('user')
                
                # Check both access keys
                for key_num in ['1', '2']:
                    if user.get(f'access_key_{key_num}_active') == 'true':
                        key_created = user.get(f'access_key_{key_num}_last_rotated')
                        if key_created and key_created != 'N/A':
                            created_date = datetime.fromisoformat(key_created.replace('Z', '+00:00'))
                            key_age_days = (datetime.now(timezone.utc) - created_date).days
                            
                            if key_age_days > max_key_age_days:
                                findings.append(Finding(
                                    severity=Severity.HIGH,
                                    category=Category.IAM,
                                    resource_type="AWS::IAM::AccessKey",
                                    resource_id=f"{user_name}_key_{key_num}",
                                    region="global",
                                    account_id=self.account_id,
                                    title="Old Access Key Needs Rotation",
                                    description=f"Access key for user '{user_name}' is {key_age_days} days old.",
                                    impact="Old access keys increase the risk of credential compromise.",
                                    recommendation=f"Rotate access keys older than {max_key_age_days} days.",
                                    compliance_frameworks=[ComplianceFramework.NIST, ComplianceFramework.CIS],
                                    automated_remediation_available=False,
                                    evidence={
                                        "user_name": user_name,
                                        "key_number": key_num,
                                        "key_age_days": key_age_days,
                                        "created_date": created_date.isoformat()
                                    }
                                ))
        
        except ClientError as e:
            self._handle_error(e, "access key rotation check")
        
        return findings
    
    def _check_overprivileged_policies(self, iam_client) -> List[Finding]:
        """Check for overly permissive policies"""
        findings = []
        
        try:
            # Check inline and managed policies
            users = self._paginate(iam_client, 'list_users')
            
            for user in users:
                user_name = user['UserName']
                
                # Check inline policies
                inline_policies = iam_client.list_user_policies(UserName=user_name)
                for policy_name in inline_policies.get('PolicyNames', []):
                    policy_doc = iam_client.get_user_policy(
                        UserName=user_name,
                        PolicyName=policy_name
                    )
                    findings.extend(self._analyze_policy_document(
                        policy_doc['PolicyDocument'],
                        f"User:{user_name}",
                        policy_name,
                        "inline"
                    ))
                
                # Check attached policies
                attached_policies = iam_client.list_attached_user_policies(UserName=user_name)
                for policy in attached_policies.get('AttachedPolicies', []):
                    if policy['PolicyArn'].startswith('arn:aws:iam::aws:'):
                        # Check for dangerous AWS managed policies
                        if policy['PolicyName'] in ['AdministratorAccess', 'PowerUserAccess']:
                            findings.append(Finding(
                                severity=Severity.HIGH,
                                category=Category.IAM,
                                resource_type="AWS::IAM::User",
                                resource_id=user_name,
                                region="global",
                                account_id=self.account_id,
                                title="User with Administrative Privileges",
                                description=f"User '{user_name}' has '{policy['PolicyName']}' policy attached.",
                                impact="Administrative access should be limited to prevent unauthorized actions.",
                                recommendation="Apply principle of least privilege and use role-based access.",
                                compliance_frameworks=[ComplianceFramework.NIST],
                                automated_remediation_available=False,
                                evidence={
                                    "user_name": user_name,
                                    "policy_name": policy['PolicyName'],
                                    "policy_arn": policy['PolicyArn']
                                }
                            ))
            
            # Check roles
            roles = self._paginate(iam_client, 'list_roles')
            for role in roles:
                if role['RoleName'].startswith('aws-'):
                    continue  # Skip AWS service-linked roles
                
                # Check inline policies
                inline_policies = iam_client.list_role_policies(RoleName=role['RoleName'])
                for policy_name in inline_policies.get('PolicyNames', []):
                    policy_doc = iam_client.get_role_policy(
                        RoleName=role['RoleName'],
                        PolicyName=policy_name
                    )
                    findings.extend(self._analyze_policy_document(
                        policy_doc['PolicyDocument'],
                        f"Role:{role['RoleName']}",
                        policy_name,
                        "inline"
                    ))
        
        except ClientError as e:
            self._handle_error(e, "policy analysis")
        
        return findings
    
    def _check_password_policy(self, iam_client) -> List[Finding]:
        """Check password policy configuration"""
        findings = []
        
        try:
            policy = iam_client.get_account_password_policy()['PasswordPolicy']
            
            # Check minimum password length
            if policy.get('MinimumPasswordLength', 0) < 14:
                findings.append(Finding(
                    severity=Severity.MEDIUM,
                    category=Category.IAM,
                    resource_type="AWS::IAM::PasswordPolicy",
                    resource_id="account-password-policy",
                    region="global",
                    account_id=self.account_id,
                    title="Weak Password Length Requirement",
                    description=f"Password minimum length is {policy.get('MinimumPasswordLength', 'not set')} characters.",
                    impact="Short passwords are easier to crack.",
                    recommendation="Set minimum password length to at least 14 characters.",
                    compliance_frameworks=[ComplianceFramework.NIST, ComplianceFramework.CIS],
                    automated_remediation_available=True,
                    evidence={
                        "current_length": policy.get('MinimumPasswordLength', 0)
                    }
                ))
            
            # Check password expiration
            if not policy.get('MaxPasswordAge'):
                findings.append(Finding(
                    severity=Severity.MEDIUM,
                    category=Category.IAM,
                    resource_type="AWS::IAM::PasswordPolicy",
                    resource_id="account-password-policy",
                    region="global",
                    account_id=self.account_id,
                    title="Password Expiration Not Configured",
                    description="Password expiration is not configured.",
                    impact="Passwords that never expire increase security risk over time.",
                    recommendation="Configure password expiration (e.g., 90 days).",
                    compliance_frameworks=[ComplianceFramework.NIST],
                    automated_remediation_available=True,
                    evidence={
                        "password_expiration_enabled": False
                    }
                ))
            
            # Check password reuse prevention
            if policy.get('PasswordReusePrevention', 0) < 5:
                findings.append(Finding(
                    severity=Severity.LOW,
                    category=Category.IAM,
                    resource_type="AWS::IAM::PasswordPolicy",
                    resource_id="account-password-policy",
                    region="global",
                    account_id=self.account_id,
                    title="Insufficient Password Reuse Prevention",
                    description=f"Password reuse prevention is set to {policy.get('PasswordReusePrevention', 0)} passwords.",
                    impact="Allowing password reuse increases the risk of compromised credentials.",
                    recommendation="Prevent reuse of at least the last 5 passwords.",
                    compliance_frameworks=[ComplianceFramework.NIST],
                    automated_remediation_available=True,
                    evidence={
                        "reuse_prevention": policy.get('PasswordReusePrevention', 0)
                    }
                ))
        
        except ClientError as e:
            if e.response['Error']['Code'] == 'NoSuchEntity':
                findings.append(Finding(
                    severity=Severity.HIGH,
                    category=Category.IAM,
                    resource_type="AWS::IAM::PasswordPolicy",
                    resource_id="account-password-policy",
                    region="global",
                    account_id=self.account_id,
                    title="No Password Policy Configured",
                    description="No password policy is configured for the account.",
                    impact="Without a password policy, users may use weak passwords.",
                    recommendation="Configure a strong password policy.",
                    compliance_frameworks=[ComplianceFramework.NIST, ComplianceFramework.CIS],
                    automated_remediation_available=True,
                    evidence={}
                ))
            else:
                self._handle_error(e, "password policy check")
        
        return findings
    
    def _check_unused_credentials(self, iam_client) -> List[Finding]:
        """Check for unused credentials that should be removed"""
        findings = []
        
        try:
            report = self._get_credential_report(iam_client)
            
            for user in report:
                if user.get('user') == '<root_account>':
                    continue
                
                user_name = user.get('user')
                
                # Check for users with both console and programmatic access
                has_password = user.get('password_enabled') == 'true'
                has_access_keys = (user.get('access_key_1_active') == 'true' or 
                                 user.get('access_key_2_active') == 'true')
                
                if has_password and has_access_keys:
                    findings.append(Finding(
                        severity=Severity.MEDIUM,
                        category=Category.IAM,
                        resource_type="AWS::IAM::User",
                        resource_id=user_name,
                        region="global",
                        account_id=self.account_id,
                        title="User with Both Console and Programmatic Access",
                        description=f"User '{user_name}' has both console access and active access keys.",
                        impact="Users should typically have either console or programmatic access, not both.",
                        recommendation="Separate human users (console) from service accounts (programmatic).",
                        compliance_frameworks=[ComplianceFramework.NIST],
                        automated_remediation_available=False,
                        evidence={
                            "user_name": user_name,
                            "has_console_access": has_password,
                            "has_programmatic_access": has_access_keys
                        }
                    ))
                
                # Check for multiple active access keys
                if (user.get('access_key_1_active') == 'true' and 
                    user.get('access_key_2_active') == 'true'):
                    findings.append(Finding(
                        severity=Severity.LOW,
                        category=Category.IAM,
                        resource_type="AWS::IAM::User",
                        resource_id=user_name,
                        region="global",
                        account_id=self.account_id,
                        title="User with Multiple Active Access Keys",
                        description=f"User '{user_name}' has multiple active access keys.",
                        impact="Multiple active keys increase the risk of key compromise.",
                        recommendation="Maintain only one active access key per user.",
                        compliance_frameworks=[ComplianceFramework.NIST],
                        automated_remediation_available=False,
                        evidence={
                            "user_name": user_name,
                            "access_key_count": 2
                        }
                    ))
        
        except ClientError as e:
            self._handle_error(e, "unused credentials check")
        
        return findings
    
    def _check_service_accounts_with_console_access(self, iam_client) -> List[Finding]:
        """Check for service accounts that have console access"""
        findings = []
        
        # Common patterns for service account names
        service_patterns = ['svc', 'service', 'app', 'bot', 'system', 'automated']
        
        try:
            users = self._paginate(iam_client, 'list_users')
            
            for user in users:
                user_name = user['UserName'].lower()
                
                # Check if this looks like a service account
                is_service_account = any(pattern in user_name for pattern in service_patterns)
                
                if is_service_account:
                    # Check if it has console access
                    try:
                        iam_client.get_login_profile(UserName=user['UserName'])
                        findings.append(Finding(
                            severity=Severity.MEDIUM,
                            category=Category.IAM,
                            resource_type="AWS::IAM::User",
                            resource_id=user['UserName'],
                            region="global",
                            account_id=self.account_id,
                            title="Service Account with Console Access",
                            description=f"Suspected service account '{user['UserName']}' has console access enabled.",
                            impact="Service accounts should only have programmatic access.",
                            recommendation="Remove console access for service accounts.",
                            compliance_frameworks=[ComplianceFramework.NIST],
                            automated_remediation_available=True,
                            evidence={
                                "user_name": user['UserName'],
                                "has_console_access": True
                            }
                        ))
                    except ClientError as e:
                        if e.response['Error']['Code'] != 'NoSuchEntity':
                            raise
        
        except ClientError as e:
            self._handle_error(e, "service account check")
        
        return findings
    
    def _analyze_policy_document(self, policy_document: str, resource_id: str, 
                               policy_name: str, policy_type: str) -> List[Finding]:
        """Analyze a policy document for security issues"""
        findings = []
        
        try:
            if isinstance(policy_document, str):
                policy = json.loads(policy_document)
            else:
                policy = policy_document
            
            for statement in policy.get('Statement', []):
                if statement.get('Effect') != 'Allow':
                    continue
                
                actions = statement.get('Action', [])
                if isinstance(actions, str):
                    actions = [actions]
                
                resources = statement.get('Resource', [])
                if isinstance(resources, str):
                    resources = [resources]
                
                # Check for wildcard actions
                if '*' in actions or any('*' in action for action in actions):
                    findings.append(Finding(
                        severity=Severity.HIGH,
                        category=Category.IAM,
                        resource_type="AWS::IAM::Policy",
                        resource_id=f"{resource_id}/{policy_name}",
                        region="global",
                        account_id=self.account_id,
                        title="Policy with Wildcard Actions",
                        description=f"{policy_type.title()} policy '{policy_name}' contains wildcard actions.",
                        impact="Wildcard actions grant excessive permissions.",
                        recommendation="Use specific actions instead of wildcards.",
                        compliance_frameworks=[ComplianceFramework.NIST],
                        automated_remediation_available=False,
                        evidence={
                            "policy_name": policy_name,
                            "policy_type": policy_type,
                            "resource": resource_id,
                            "wildcard_actions": [a for a in actions if '*' in a]
                        }
                    ))
                
                # Check for wildcard resources with dangerous actions
                dangerous_actions = [
                    'iam:*', 'iam:Put*', 'iam:Create*', 'iam:Delete*',
                    's3:*', 's3:Delete*', 's3:Put*',
                    'ec2:*', 'ec2:Terminate*',
                    'rds:*', 'rds:Delete*',
                    'lambda:*', 'lambda:Delete*'
                ]
                
                if '*' in resources:
                    for action in actions:
                        if any(action.startswith(dangerous) or action == dangerous 
                              for dangerous in dangerous_actions):
                            findings.append(Finding(
                                severity=Severity.HIGH,
                                category=Category.IAM,
                                resource_type="AWS::IAM::Policy",
                                resource_id=f"{resource_id}/{policy_name}",
                                region="global",
                                account_id=self.account_id,
                                title="Dangerous Actions on All Resources",
                                description=f"Policy allows dangerous action '{action}' on all resources.",
                                impact="This grants excessive permissions that could be abused.",
                                recommendation="Restrict actions to specific resources.",
                                compliance_frameworks=[ComplianceFramework.NIST],
                                automated_remediation_available=False,
                                evidence={
                                    "policy_name": policy_name,
                                    "action": action,
                                    "resource": "*"
                                }
                            ))
        
        except json.JSONDecodeError:
            self.logger.error(f"Failed to parse policy document for {policy_name}")
        except Exception as e:
            self.logger.error(f"Error analyzing policy {policy_name}: {e}")
        
        return findings
    
    def _get_credential_report(self, iam_client) -> List[Dict[str, Any]]:
        """Get and parse the credential report"""
        import csv
        import io
        import base64
        import time
        
        # Generate credential report
        for _ in range(10):  # Try for up to 10 seconds
            try:
                response = iam_client.generate_credential_report()
                if response['State'] == 'COMPLETE':
                    break
                time.sleep(1)
            except ClientError as e:
                if e.response['Error']['Code'] != 'ReportInProgress':
                    raise
                time.sleep(1)
        
        # Get the report
        response = iam_client.get_credential_report()
        report_content = base64.b64decode(response['Content']).decode('utf-8')
        
        # Parse CSV
        report_lines = report_content.strip().split('\n')
        reader = csv.DictReader(io.StringIO(report_content))
        
        return list(reader)