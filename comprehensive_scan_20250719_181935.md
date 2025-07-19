# AWS Security Analysis Report

**Generated:** 2025-07-19 18:19:35 UTC
**Account ID:** 028358929215
**Regions:** 
**Services:** iam, s3, ec2

## Executive Summary

- **Total Findings:** 160
- **Critical:** 1
- **High:** 22
- **Medium:** 69
- **Low:** 68
- **Informational:** 0
- **Resources Scanned:** 160
- **Scan Duration:** 37 seconds

## Attack Surface Analysis

- **Total Attack Vectors:** 160
- **Critical Exposures:** 1
- **Categories Affected:** 6
- **Services Affected:** 3

### Top Security Risks

1. **Root Account Recently Used** (Risk Score: 100)
   - Resource: `root`
   - Impact: Root account usage poses significant security risks as it has unrestricted access to all AWS services.

2. **User with Administrative Privileges** (Risk Score: 80)
   - Resource: `Icculus373`
   - Impact: Administrative access should be limited to prevent unauthorized actions.

3. **Policy with Wildcard Actions** (Risk Score: 80)
   - Resource: `Role:cdk-hnb659fds-deploy-role-028358929215-us-east-1/default`
   - Impact: Wildcard actions grant excessive permissions.

4. **Policy with Wildcard Actions** (Risk Score: 80)
   - Resource: `Role:cdk-hnb659fds-deploy-role-028358929215-us-east-1/default`
   - Impact: Wildcard actions grant excessive permissions.

5. **Policy with Wildcard Actions** (Risk Score: 80)
   - Resource: `Role:cdk-hnb659fds-deploy-role-028358929215-us-east-1/default`
   - Impact: Wildcard actions grant excessive permissions.

## Quick Wins

These findings have automated remediation available and should be addressed first:

- **S3 Bucket Public Access Not Fully Blocked** (HIGH)
  - Resource: `bill-finance-ui-1750520483`
  - Risk Score: 70
- **S3 Bucket Public Access Not Fully Blocked** (HIGH)
  - Resource: `sapanalyzer4-frontend-028358929215-us-east-1`
  - Risk Score: 70
- **Unused IAM User** (MEDIUM)
  - Resource: `ses-smtp-user.20250716-211912`
  - Risk Score: 60
- **Weak Password Length Requirement** (MEDIUM)
  - Resource: `account-password-policy`
  - Risk Score: 60
- **S3 Bucket Versioning Not Enabled** (MEDIUM)
  - Resource: `amazon-connect-4217f28bf497`
  - Risk Score: 50

## Detailed Findings

### CRITICAL Severity (1 findings)

#### Root Account Recently Used

- **Resource Type:** AWS::IAM::RootAccount
- **Resource ID:** `root`
- **Region:** global
- **Risk Score:** 100

**Description:** The root account has been used within the last 90 days.

**Impact:** Root account usage poses significant security risks as it has unrestricted access to all AWS services.

**Recommendation:** Enable MFA on root account, create individual IAM users for daily tasks, and avoid using root account.

**Compliance Frameworks:** NIST, CIS

---

### HIGH Severity (22 findings)

#### User with Administrative Privileges

- **Resource Type:** AWS::IAM::User
- **Resource ID:** `Icculus373`
- **Region:** global
- **Risk Score:** 80

**Description:** User 'Icculus373' has 'AdministratorAccess' policy attached.

**Impact:** Administrative access should be limited to prevent unauthorized actions.

**Recommendation:** Apply principle of least privilege and use role-based access.

**Compliance Frameworks:** NIST

---

#### Policy with Wildcard Actions

- **Resource Type:** AWS::IAM::Policy
- **Resource ID:** `Role:cdk-hnb659fds-deploy-role-028358929215-us-east-1/default`
- **Region:** global
- **Risk Score:** 80

**Description:** Inline policy 'default' contains wildcard actions.

**Impact:** Wildcard actions grant excessive permissions.

**Recommendation:** Use specific actions instead of wildcards.

**Compliance Frameworks:** NIST

---

#### Policy with Wildcard Actions

- **Resource Type:** AWS::IAM::Policy
- **Resource ID:** `Role:cdk-hnb659fds-deploy-role-028358929215-us-east-1/default`
- **Region:** global
- **Risk Score:** 80

**Description:** Inline policy 'default' contains wildcard actions.

**Impact:** Wildcard actions grant excessive permissions.

**Recommendation:** Use specific actions instead of wildcards.

**Compliance Frameworks:** NIST

---

#### Policy with Wildcard Actions

- **Resource Type:** AWS::IAM::Policy
- **Resource ID:** `Role:cdk-hnb659fds-deploy-role-028358929215-us-east-1/default`
- **Region:** global
- **Risk Score:** 80

**Description:** Inline policy 'default' contains wildcard actions.

**Impact:** Wildcard actions grant excessive permissions.

**Recommendation:** Use specific actions instead of wildcards.

**Compliance Frameworks:** NIST

---

#### Policy with Wildcard Actions

- **Resource Type:** AWS::IAM::Policy
- **Resource ID:** `Role:cdk-hnb659fds-file-publishing-role-028358929215-us-east-1/cdk-hnb659fds-file-publishing-role-default-policy-028358929215-us-east-1`
- **Region:** global
- **Risk Score:** 80

**Description:** Inline policy 'cdk-hnb659fds-file-publishing-role-default-policy-028358929215-us-east-1' contains wildcard actions.

**Impact:** Wildcard actions grant excessive permissions.

**Recommendation:** Use specific actions instead of wildcards.

**Compliance Frameworks:** NIST

---

#### Policy with Wildcard Actions

- **Resource Type:** AWS::IAM::Policy
- **Resource ID:** `Role:cdk-hnb659fds-file-publishing-role-028358929215-us-east-1/cdk-hnb659fds-file-publishing-role-default-policy-028358929215-us-east-1`
- **Region:** global
- **Risk Score:** 80

**Description:** Inline policy 'cdk-hnb659fds-file-publishing-role-default-policy-028358929215-us-east-1' contains wildcard actions.

**Impact:** Wildcard actions grant excessive permissions.

**Recommendation:** Use specific actions instead of wildcards.

**Compliance Frameworks:** NIST

---

#### Policy with Wildcard Actions

- **Resource Type:** AWS::IAM::Policy
- **Resource ID:** `Role:SapAnalyzer4Stack-AnalyzeFunctionServiceRole2A2C257-SmNqyFG4V3Aa/AnalyzeFunctionServiceRoleDefaultPolicyC2F006BE`
- **Region:** global
- **Risk Score:** 80

**Description:** Inline policy 'AnalyzeFunctionServiceRoleDefaultPolicyC2F006BE' contains wildcard actions.

**Impact:** Wildcard actions grant excessive permissions.

**Recommendation:** Use specific actions instead of wildcards.

**Compliance Frameworks:** NIST

---

#### Policy with Wildcard Actions

- **Resource Type:** AWS::IAM::Policy
- **Resource ID:** `Role:SapAnalyzer4Stack-CustomCDKBucketDeployment8693BB64-Yb68O7HgOaxH/CustomCDKBucketDeployment8693BB64968944B69AAFB0CC9EB8756CServiceRoleDefaultPolicy88902FDF`
- **Region:** global
- **Risk Score:** 80

**Description:** Inline policy 'CustomCDKBucketDeployment8693BB64968944B69AAFB0CC9EB8756CServiceRoleDefaultPolicy88902FDF' contains wildcard actions.

**Impact:** Wildcard actions grant excessive permissions.

**Recommendation:** Use specific actions instead of wildcards.

**Compliance Frameworks:** NIST

---

#### Policy with Wildcard Actions

- **Resource Type:** AWS::IAM::Policy
- **Resource ID:** `Role:SapAnalyzer4Stack-CustomCDKBucketDeployment8693BB64-Yb68O7HgOaxH/CustomCDKBucketDeployment8693BB64968944B69AAFB0CC9EB8756CServiceRoleDefaultPolicy88902FDF`
- **Region:** global
- **Risk Score:** 80

**Description:** Inline policy 'CustomCDKBucketDeployment8693BB64968944B69AAFB0CC9EB8756CServiceRoleDefaultPolicy88902FDF' contains wildcard actions.

**Impact:** Wildcard actions grant excessive permissions.

**Recommendation:** Use specific actions instead of wildcards.

**Compliance Frameworks:** NIST

---

#### Policy with Wildcard Actions

- **Resource Type:** AWS::IAM::Policy
- **Resource ID:** `Role:SapAnalyzer4Stack-FilesFunctionServiceRoleAA8EECF9-PuZKkyRpXNyf/FilesFunctionServiceRoleDefaultPolicy5CB56C2C`
- **Region:** global
- **Risk Score:** 80

**Description:** Inline policy 'FilesFunctionServiceRoleDefaultPolicy5CB56C2C' contains wildcard actions.

**Impact:** Wildcard actions grant excessive permissions.

**Recommendation:** Use specific actions instead of wildcards.

**Compliance Frameworks:** NIST

---

*... and 12 more HIGH findings*

### MEDIUM Severity (69 findings)

#### Unused IAM User

- **Resource Type:** AWS::IAM::User
- **Resource ID:** `ses-smtp-user.20250716-211912`
- **Region:** global
- **Risk Score:** 60

**Description:** IAM user 'ses-smtp-user.20250716-211912' has never been used but has active credentials.

**Impact:** Unused accounts with active credentials increase the attack surface.

**Recommendation:** Remove unused IAM users or deactivate their credentials.

**Compliance Frameworks:** NIST

✅ **Automated remediation available**

---

#### Weak Password Length Requirement

- **Resource Type:** AWS::IAM::PasswordPolicy
- **Resource ID:** `account-password-policy`
- **Region:** global
- **Risk Score:** 60

**Description:** Password minimum length is 8 characters.

**Impact:** Short passwords are easier to crack.

**Recommendation:** Set minimum password length to at least 14 characters.

**Compliance Frameworks:** NIST, CIS

✅ **Automated remediation available**

---

#### User with Both Console and Programmatic Access

- **Resource Type:** AWS::IAM::User
- **Resource ID:** `Icculus373`
- **Region:** global
- **Risk Score:** 60

**Description:** User 'Icculus373' has both console access and active access keys.

**Impact:** Users should typically have either console or programmatic access, not both.

**Recommendation:** Separate human users (console) from service accounts (programmatic).

**Compliance Frameworks:** NIST

---

#### S3 Bucket Versioning Not Enabled

- **Resource Type:** AWS::S3::Bucket
- **Resource ID:** `amazon-connect-4217f28bf497`
- **Region:** us-east-1
- **Risk Score:** 50

**Description:** S3 bucket 'amazon-connect-4217f28bf497' does not have versioning enabled.

**Impact:** Cannot recover from accidental deletions or overwrites. No protection against ransomware.

**Recommendation:** Enable versioning to protect against accidental data loss and maintain data integrity.

**Compliance Frameworks:** NIST, SOX

✅ **Automated remediation available**

---

#### S3 Bucket Access Logging Not Enabled

- **Resource Type:** AWS::S3::Bucket
- **Resource ID:** `amazon-connect-4217f28bf497`
- **Region:** us-east-1
- **Risk Score:** 50

**Description:** S3 bucket 'amazon-connect-4217f28bf497' does not have access logging enabled.

**Impact:** Cannot audit access to bucket objects. Limited visibility for security investigations.

**Recommendation:** Enable S3 access logging to track requests made to the bucket.

**Compliance Frameworks:** NIST, CIS, SOX

✅ **Automated remediation available**

---

#### S3 Bucket Versioning Not Enabled

- **Resource Type:** AWS::S3::Bucket
- **Resource ID:** `bill-basic-dev-serverlessdeploymentbucket-uypet4cjt9ld`
- **Region:** us-east-1
- **Risk Score:** 50

**Description:** S3 bucket 'bill-basic-dev-serverlessdeploymentbucket-uypet4cjt9ld' does not have versioning enabled.

**Impact:** Cannot recover from accidental deletions or overwrites. No protection against ransomware.

**Recommendation:** Enable versioning to protect against accidental data loss and maintain data integrity.

**Compliance Frameworks:** NIST, SOX

✅ **Automated remediation available**

---

#### S3 Bucket Access Logging Not Enabled

- **Resource Type:** AWS::S3::Bucket
- **Resource ID:** `bill-basic-dev-serverlessdeploymentbucket-uypet4cjt9ld`
- **Region:** us-east-1
- **Risk Score:** 50

**Description:** S3 bucket 'bill-basic-dev-serverlessdeploymentbucket-uypet4cjt9ld' does not have access logging enabled.

**Impact:** Cannot audit access to bucket objects. Limited visibility for security investigations.

**Recommendation:** Enable S3 access logging to track requests made to the bucket.

**Compliance Frameworks:** NIST, CIS, SOX

✅ **Automated remediation available**

---

#### S3 Bucket Versioning Not Enabled

- **Resource Type:** AWS::S3::Bucket
- **Resource ID:** `bill-csv-uploads-1750517575`
- **Region:** us-east-1
- **Risk Score:** 50

**Description:** S3 bucket 'bill-csv-uploads-1750517575' does not have versioning enabled.

**Impact:** Cannot recover from accidental deletions or overwrites. No protection against ransomware.

**Recommendation:** Enable versioning to protect against accidental data loss and maintain data integrity.

**Compliance Frameworks:** NIST, SOX

✅ **Automated remediation available**

---

#### S3 Bucket Access Logging Not Enabled

- **Resource Type:** AWS::S3::Bucket
- **Resource ID:** `bill-csv-uploads-1750517575`
- **Region:** us-east-1
- **Risk Score:** 50

**Description:** S3 bucket 'bill-csv-uploads-1750517575' does not have access logging enabled.

**Impact:** Cannot audit access to bucket objects. Limited visibility for security investigations.

**Recommendation:** Enable S3 access logging to track requests made to the bucket.

**Compliance Frameworks:** NIST, CIS, SOX

✅ **Automated remediation available**

---

#### S3 Bucket Versioning Not Enabled

- **Resource Type:** AWS::S3::Bucket
- **Resource ID:** `bill-finance-minimal-dev-serverlessdeploymentbucke-ka5o2ewzdxid`
- **Region:** us-east-1
- **Risk Score:** 50

**Description:** S3 bucket 'bill-finance-minimal-dev-serverlessdeploymentbucke-ka5o2ewzdxid' does not have versioning enabled.

**Impact:** Cannot recover from accidental deletions or overwrites. No protection against ransomware.

**Recommendation:** Enable versioning to protect against accidental data loss and maintain data integrity.

**Compliance Frameworks:** NIST, SOX

✅ **Automated remediation available**

---

*... and 59 more MEDIUM findings*

### LOW Severity (68 findings)

#### Insufficient Password Reuse Prevention

- **Resource Type:** AWS::IAM::PasswordPolicy
- **Resource ID:** `account-password-policy`
- **Region:** global
- **Risk Score:** 40

**Description:** Password reuse prevention is set to 0 passwords.

**Impact:** Allowing password reuse increases the risk of compromised credentials.

**Recommendation:** Prevent reuse of at least the last 5 passwords.

**Compliance Frameworks:** NIST

✅ **Automated remediation available**

---

#### S3 Bucket Using SSE-S3 Instead of SSE-KMS

- **Resource Type:** AWS::S3::Bucket
- **Resource ID:** `amazon-connect-4217f28bf497`
- **Region:** us-east-1
- **Risk Score:** 30

**Description:** S3 bucket 'amazon-connect-4217f28bf497' uses SSE-S3 encryption instead of SSE-KMS.

**Impact:** SSE-S3 provides encryption but lacks the additional key management features and audit trail of KMS.

**Recommendation:** Consider using SSE-KMS for enhanced security and compliance requirements.

**Compliance Frameworks:** SOX

✅ **Automated remediation available**

---

#### S3 Bucket Without Lifecycle Policy

- **Resource Type:** AWS::S3::Bucket
- **Resource ID:** `amazon-connect-4217f28bf497`
- **Region:** us-east-1
- **Risk Score:** 30

**Description:** S3 bucket 'amazon-connect-4217f28bf497' does not have lifecycle policies configured.

**Impact:** May result in unnecessary storage costs and retention of outdated data.

**Recommendation:** Configure lifecycle policies to automatically transition or expire objects based on age.

**Compliance Frameworks:** NIST

---

#### S3 Bucket Using SSE-S3 Instead of SSE-KMS

- **Resource Type:** AWS::S3::Bucket
- **Resource ID:** `bill-basic-dev-serverlessdeploymentbucket-uypet4cjt9ld`
- **Region:** us-east-1
- **Risk Score:** 30

**Description:** S3 bucket 'bill-basic-dev-serverlessdeploymentbucket-uypet4cjt9ld' uses SSE-S3 encryption instead of SSE-KMS.

**Impact:** SSE-S3 provides encryption but lacks the additional key management features and audit trail of KMS.

**Recommendation:** Consider using SSE-KMS for enhanced security and compliance requirements.

**Compliance Frameworks:** SOX

✅ **Automated remediation available**

---

#### S3 Bucket Without Lifecycle Policy

- **Resource Type:** AWS::S3::Bucket
- **Resource ID:** `bill-basic-dev-serverlessdeploymentbucket-uypet4cjt9ld`
- **Region:** us-east-1
- **Risk Score:** 30

**Description:** S3 bucket 'bill-basic-dev-serverlessdeploymentbucket-uypet4cjt9ld' does not have lifecycle policies configured.

**Impact:** May result in unnecessary storage costs and retention of outdated data.

**Recommendation:** Configure lifecycle policies to automatically transition or expire objects based on age.

**Compliance Frameworks:** NIST

---

#### S3 Bucket Using SSE-S3 Instead of SSE-KMS

- **Resource Type:** AWS::S3::Bucket
- **Resource ID:** `bill-csv-uploads-1750517575`
- **Region:** us-east-1
- **Risk Score:** 30

**Description:** S3 bucket 'bill-csv-uploads-1750517575' uses SSE-S3 encryption instead of SSE-KMS.

**Impact:** SSE-S3 provides encryption but lacks the additional key management features and audit trail of KMS.

**Recommendation:** Consider using SSE-KMS for enhanced security and compliance requirements.

**Compliance Frameworks:** SOX

✅ **Automated remediation available**

---

#### S3 Bucket Without Lifecycle Policy

- **Resource Type:** AWS::S3::Bucket
- **Resource ID:** `bill-csv-uploads-1750517575`
- **Region:** us-east-1
- **Risk Score:** 30

**Description:** S3 bucket 'bill-csv-uploads-1750517575' does not have lifecycle policies configured.

**Impact:** May result in unnecessary storage costs and retention of outdated data.

**Recommendation:** Configure lifecycle policies to automatically transition or expire objects based on age.

**Compliance Frameworks:** NIST

---

#### S3 Bucket Using SSE-S3 Instead of SSE-KMS

- **Resource Type:** AWS::S3::Bucket
- **Resource ID:** `bill-finance-minimal-dev-serverlessdeploymentbucke-ka5o2ewzdxid`
- **Region:** us-east-1
- **Risk Score:** 30

**Description:** S3 bucket 'bill-finance-minimal-dev-serverlessdeploymentbucke-ka5o2ewzdxid' uses SSE-S3 encryption instead of SSE-KMS.

**Impact:** SSE-S3 provides encryption but lacks the additional key management features and audit trail of KMS.

**Recommendation:** Consider using SSE-KMS for enhanced security and compliance requirements.

**Compliance Frameworks:** SOX

✅ **Automated remediation available**

---

#### S3 Bucket Without Lifecycle Policy

- **Resource Type:** AWS::S3::Bucket
- **Resource ID:** `bill-finance-minimal-dev-serverlessdeploymentbucke-ka5o2ewzdxid`
- **Region:** us-east-1
- **Risk Score:** 30

**Description:** S3 bucket 'bill-finance-minimal-dev-serverlessdeploymentbucke-ka5o2ewzdxid' does not have lifecycle policies configured.

**Impact:** May result in unnecessary storage costs and retention of outdated data.

**Recommendation:** Configure lifecycle policies to automatically transition or expire objects based on age.

**Compliance Frameworks:** NIST

---

#### S3 Bucket Using SSE-S3 Instead of SSE-KMS

- **Resource Type:** AWS::S3::Bucket
- **Resource ID:** `bill-finance-system-dev-serverlessdeploymentbucket-kgisogxazjhy`
- **Region:** us-east-1
- **Risk Score:** 30

**Description:** S3 bucket 'bill-finance-system-dev-serverlessdeploymentbucket-kgisogxazjhy' uses SSE-S3 encryption instead of SSE-KMS.

**Impact:** SSE-S3 provides encryption but lacks the additional key management features and audit trail of KMS.

**Recommendation:** Consider using SSE-KMS for enhanced security and compliance requirements.

**Compliance Frameworks:** SOX

✅ **Automated remediation available**

---

*... and 58 more LOW findings*

## Compliance Framework Summary

### NIST
- Total Findings: 112
- CRITICAL: 1
- MEDIUM: 69
- HIGH: 21
- LOW: 21

### CIS
- Total Findings: 44
- CRITICAL: 1
- MEDIUM: 37
- HIGH: 6

### SOX
- Total Findings: 82
- LOW: 28
- MEDIUM: 53
- HIGH: 1

## Remediation Priority Matrix

### Critical Priority
- **Risk Score Range:** 90-100
- **Total Findings:** 1
- **Automated Remediation:** 0
- **Manual Remediation:** 1
- **Estimated Effort:** Low (< 1 day)

### High Priority
- **Risk Score Range:** 70-89
- **Total Findings:** 22
- **Automated Remediation:** 2
- **Manual Remediation:** 20
- **Estimated Effort:** High (1-2 weeks)

### Medium Priority
- **Risk Score Range:** 50-69
- **Total Findings:** 69
- **Automated Remediation:** 60
- **Manual Remediation:** 9
- **Estimated Effort:** Very High (> 2 weeks)

### Low Priority
- **Risk Score Range:** 30-49
- **Total Findings:** 68
- **Automated Remediation:** 29
- **Manual Remediation:** 39
- **Estimated Effort:** Very High (> 2 weeks)
