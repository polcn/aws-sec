# Configuration File Guide

The AWS Security Analysis Tool supports configuration files to customize scan behavior, manage service preferences, and control output formatting. This guide explains how to use configuration files effectively.

## Overview

Configuration files allow you to:
- Enable/disable specific AWS services
- Set custom regions per service
- Override finding severities
- Suppress specific findings
- Configure output preferences
- Filter resources by tags
- Set risk scoring weights

## Quick Start

1. Generate an example configuration file:
```bash
aws-security-tool generate-config
```

2. Use the configuration file:
```bash
aws-security-tool scan --config aws-security-config.example.yaml
```

## Configuration File Location

The tool looks for configuration files in the following order:
1. Path specified with `--config` option
2. `~/.aws-security-tool/config.yaml`
3. `./aws-security-config.yaml`
4. `./.aws-security.yaml`

## Configuration File Structure

### Services Configuration

Control which services to scan and their specific settings:

```yaml
services:
  iam:
    enabled: true
    regions: null  # IAM is global, regions ignored
    filters:
      exclude_users:
        - terraform-*
        - ci-*
  
  s3:
    enabled: true
    regions:
      - us-east-1
      - us-west-2
    filters:
      exclude_buckets:
        - '*-logs-*'
        - '*-backup-*'
  
  ec2:
    enabled: true
    exclude_regions:
      - ap-south-1
  
  vpc:
    enabled: true
  
  rds:
    enabled: true
```

### Risk Scoring Configuration

Customize risk scoring weights and override specific finding severities:

```yaml
risk_scoring:
  critical_weight: 100
  high_weight: 80
  medium_weight: 60
  low_weight: 40
  informational_weight: 20
  
  severity_overrides:
    "S3 Bucket Without Lifecycle Policy": LOW
    "Unused IAM User": HIGH
    "VPC Without Tags": LOW
```

### Output Configuration

Control report format and content:

```yaml
output:
  format: markdown  # Options: markdown, html, json, text
  file: security-report.md
  include_passed_checks: false
  suppress_findings:
    - "S3 Bucket Using SSE-S3 Instead of SSE-KMS"
    - "VPC Missing Recommended Endpoints"
  group_by: severity  # Options: severity, service, resource, compliance
```

### Compliance Configuration

Configure compliance framework mappings:

```yaml
compliance:
  frameworks:
    - NIST
    - CIS
    - SOX
  custom_mappings:
    "Custom Finding Type":
      - NIST
      - CIS
```

### Scan Metadata

Add metadata to your scans:

```yaml
scan_name: Production Security Scan
scan_tags:
  environment: production
  team: security
  scheduled: weekly
```

### Resource Tag Filtering

Filter resources based on their AWS tags:

```yaml
# Exclude resources with these tags
exclude_resource_tags:
  Environment:
    - development
    - test
  Ignore-Security-Scan:
    - 'true'

# Only include resources with these tags
include_resource_tags:
  Environment:
    - production
  Critical:
    - 'true'
```

### Advanced Settings

```yaml
# Maximum concurrent regions to scan (1-20)
max_concurrent_regions: 5

# API retry configuration
api_retry_attempts: 3
api_retry_delay: 1.0  # seconds
```

## CLI Options Override

CLI options take precedence over configuration file settings:

```bash
# Override services from config
aws-security-tool scan --config config.yaml --services iam,s3

# Override output format
aws-security-tool scan --config config.yaml --output-format json

# Override output file
aws-security-tool scan --config config.yaml --output-file custom-report.md
```

## Example Use Cases

### Production Scan Configuration

```yaml
scan_name: Production Weekly Scan
services:
  iam:
    enabled: true
  s3:
    enabled: true
    regions: [us-east-1, us-west-2]
  ec2:
    enabled: true
    regions: [us-east-1, us-west-2]
  vpc:
    enabled: true
    regions: [us-east-1, us-west-2]

risk_scoring:
  severity_overrides:
    "S3 Bucket Without Lifecycle Policy": LOW
    "Unused IAM User": CRITICAL

output:
  format: html
  file: prod-security-report.html
  suppress_findings:
    - "S3 Bucket Using SSE-S3 Instead of SSE-KMS"

include_resource_tags:
  Environment: [production]
```

### Development Environment Configuration

```yaml
scan_name: Dev Environment Quick Scan
services:
  iam:
    enabled: false  # Skip IAM in dev
  s3:
    enabled: true
    filters:
      exclude_buckets: ['*-test-*', '*-dev-*']
  ec2:
    enabled: true
  vpc:
    enabled: false

output:
  format: markdown
  file: dev-scan.md
  suppress_findings:
    - "S3 Bucket Versioning Not Enabled"
    - "EC2 Instance Using Instance Store"

exclude_resource_tags:
  Environment: [production]
```

### Compliance-Focused Configuration

```yaml
scan_name: SOX Compliance Scan
services:
  iam:
    enabled: true
  s3:
    enabled: true
  ec2:
    enabled: true
  vpc:
    enabled: true

compliance:
  frameworks: [SOX, NIST]

risk_scoring:
  severity_overrides:
    "S3 Bucket Access Logging Not Enabled": HIGH
    "VPC Flow Logs Not Enabled": HIGH

output:
  format: json
  file: sox-compliance-report.json
  group_by: compliance
```

## Best Practices

1. **Version Control**: Keep your configuration files in version control to track changes over time.

2. **Environment-Specific Configs**: Create separate configuration files for different environments (prod, staging, dev).

3. **Regular Updates**: Review and update severity overrides as your security posture evolves.

4. **Documentation**: Document why specific findings are suppressed or have overridden severities.

5. **Minimal Suppressions**: Only suppress findings that are truly not applicable to your environment.

## Troubleshooting

### Configuration Not Loading

If your configuration file isn't being loaded:
1. Check the file path is correct
2. Verify YAML syntax is valid
3. Ensure proper indentation (YAML is sensitive to spaces)
4. Run with explicit path: `--config /full/path/to/config.yaml`

### Invalid Configuration Values

The tool validates configuration values. Common errors:
- Invalid region names
- Invalid severity values (must be CRITICAL, HIGH, MEDIUM, LOW, or INFORMATIONAL)
- Invalid output format (must be markdown, html, json, or text)

### Finding Names for Suppression

To get the exact finding names for suppression:
1. Run a scan without suppression
2. Check the report for exact finding titles
3. Copy the titles exactly as they appear (case-sensitive)