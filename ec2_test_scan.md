# AWS Security Analysis Report

**Generated:** 2025-07-19 18:04:31 UTC
**Account ID:** 028358929215
**Regions:** 
**Services:** ec2

## Executive Summary

- **Total Findings:** 2
- **Critical:** 0
- **High:** 1
- **Medium:** 0
- **Low:** 1
- **Informational:** 0
- **Resources Scanned:** 2
- **Scan Duration:** 29 seconds

## Attack Surface Analysis

- **Total Attack Vectors:** 2
- **Critical Exposures:** 0
- **Categories Affected:** 1
- **Services Affected:** 1

### Top Security Risks

1. **EBS Volume Not Encrypted** (Risk Score: 70)
   - Resource: `vol-0c549a258c55501e0`
   - Impact: Sensitive data stored on the volume is not encrypted at rest, risking exposure if physical storage is compromised or snapshots are shared

## Detailed Findings

### HIGH Severity (1 findings)

#### EBS Volume Not Encrypted

- **Resource Type:** AWS::EC2::Volume
- **Resource ID:** `vol-0c549a258c55501e0`
- **Region:** us-east-1
- **Risk Score:** 70

**Description:** EBS volume vol-0c549a258c55501e0 is not encrypted at rest.

**Impact:** Sensitive data stored on the volume is not encrypted at rest, risking exposure if physical storage is compromised or snapshots are shared

**Recommendation:** Enable EBS encryption for all volumes

**Compliance Frameworks:** NIST, SOX

---

### LOW Severity (1 findings)

#### EBS Volume Backup Status Unknown

- **Resource Type:** AWS::EC2::Volume
- **Resource ID:** `vol-0c549a258c55501e0`
- **Region:** us-east-1
- **Risk Score:** 30

**Description:** EBS volume vol-0c549a258c55501e0 backup status should be verified.

**Impact:** Without regular backups, data loss could occur due to volume failure, accidental deletion, or corruption, affecting business continuity

**Recommendation:** Ensure regular snapshots are taken for important volumes

---

## Compliance Framework Summary

### NIST
- Total Findings: 1
- HIGH: 1

### SOX
- Total Findings: 1
- HIGH: 1

## Remediation Priority Matrix

### High Priority
- **Risk Score Range:** 70-89
- **Total Findings:** 1
- **Automated Remediation:** 0
- **Manual Remediation:** 1
- **Estimated Effort:** Low (< 1 day)

### Low Priority
- **Risk Score Range:** 30-49
- **Total Findings:** 1
- **Automated Remediation:** 0
- **Manual Remediation:** 1
- **Estimated Effort:** Low (< 1 day)
