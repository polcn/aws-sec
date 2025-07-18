# AWS Security Analysis Tool

A comprehensive, open-source AWS security analysis tool that performs automated security assessments based on the AWS Well-Architected Security Pillar framework.

## Features

- **Security Findings with Risk Prioritization**: Comprehensive scanning aligned with AWS Well-Architected Security Pillar
- **Automated Remediation Scripts**: Generate executable Python scripts to fix identified issues
- **IAM Security Analysis**: Deep analysis of IAM configurations and access patterns
- **Architecture Diagram Generation**: Auto-generate visual representation of AWS infrastructure
- **Compliance Framework Mapping**: Map findings to NIST, OWASP, and SOX frameworks
- **Multi-Format Reporting**: Generate reports in HTML, Markdown, and plain text formats

## Installation

```bash
pip install aws-security-tool
```

## Quick Start

```bash
# Run a security scan on your AWS account
aws-security-tool scan

# Generate remediation scripts
aws-security-tool scan --generate-remediation

# Scan specific services
aws-security-tool scan --services iam,s3,ec2

# Output in different formats
aws-security-tool scan --output-format html --output-file report.html
```

## Requirements

- Python 3.9+
- AWS credentials configured (via AWS CLI, environment variables, or IAM role)
- Appropriate AWS permissions to read resources

## Documentation

See the [docs](./docs) directory for detailed documentation.

## License

MIT License