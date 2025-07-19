# AWS Security Analysis Tool

A comprehensive, open-source AWS security analysis tool that performs automated security assessments based on the AWS Well-Architected Security Pillar framework.

## Features

- **Multi-Service Security Scanning**: Support for IAM and S3 with more services coming soon
- **Security Findings with Risk Prioritization**: Comprehensive scanning aligned with AWS Well-Architected Security Pillar
- **Automated Remediation Scripts**: Generate executable Python scripts to fix identified issues
- **IAM Security Analysis**: Deep analysis including MFA enforcement validation
- **S3 Security Analysis**: Comprehensive bucket security checks including encryption, public access, versioning, and more
- **Architecture Diagram Generation**: Auto-generate visual representation of AWS infrastructure
- **Compliance Framework Mapping**: Map findings to NIST, CIS, SOX, and OWASP frameworks
- **Multi-Format Reporting**: Generate reports in HTML, Markdown, JSON, and plain text formats

## Latest Scan Results

The tool has been successfully tested on AWS account 028358929215. Recent scan results:

### IAM + S3 Combined Scan
- **129 total security findings**
- 1 CRITICAL (Root account usage)
- 18 HIGH (Including admin privileges, wildcard policies, and public S3 buckets)
- 61 MEDIUM (Including unencrypted buckets, missing versioning, and weak password policy)
- 49 LOW (Including SSE-S3 instead of KMS encryption)

### S3-only Scan
- **110 total security findings**
- 4 HIGH (Public access issues)
- 58 MEDIUM (Missing encryption, versioning, and logging)
- 48 LOW (SSE-S3 encryption and lifecycle policies)

View the full reports:
- [Combined Scan Report](./combined_scan.md)
- [S3 Scan Report](./s3_test_scan.md)

## Installation

### From Source (Recommended)

Due to package structure issues, it's recommended to run from source:

```bash
# Clone the repository
git clone https://github.com/polcn/aws-sec.git
cd aws-sec

# Activate the virtual environment
source venv/bin/activate

# Run the tool
PYTHONPATH=/home/ec2-user/aws-sec python -m src.cli scan
```

### Using pip (Currently has issues)

```bash
pip install aws-security-tool  # Note: Has import issues, use source method
```

## Quick Start

```bash
# Activate virtual environment first
source venv/bin/activate

# Run a security scan on your AWS account (IAM + S3 by default)
PYTHONPATH=/home/ec2-user/aws-sec python -m src.cli scan

# Scan specific services
PYTHONPATH=/home/ec2-user/aws-sec python -m src.cli scan --services iam
PYTHONPATH=/home/ec2-user/aws-sec python -m src.cli scan --services s3
PYTHONPATH=/home/ec2-user/aws-sec python -m src.cli scan --services iam,s3

# Generate remediation scripts
PYTHONPATH=/home/ec2-user/aws-sec python -m src.cli scan --generate-remediation

# Output in different formats
PYTHONPATH=/home/ec2-user/aws-sec python -m src.cli scan --output-format html --output-file report.html
PYTHONPATH=/home/ec2-user/aws-sec python -m src.cli scan --output-format markdown --output-file report.md
PYTHONPATH=/home/ec2-user/aws-sec python -m src.cli scan --output-format json --output-file report.json

# List available services
PYTHONPATH=/home/ec2-user/aws-sec python -m src.cli list-services
```

## Requirements

- Python 3.9+
- AWS credentials configured (via AWS CLI, environment variables, or IAM role)
- Appropriate AWS permissions to read resources

## Known Issues

1. **Import Structure**: The package has relative import issues preventing the installed command from working properly. Use the source method with PYTHONPATH as shown above.
2. **Limited Scanner Coverage**: Currently only IAM and S3 scanning are implemented. Additional service scanners (EC2, RDS, VPC, etc.) are planned.

## Recent Updates (July 19, 2025)

- **Added S3 Security Scanner**: Comprehensive S3 bucket security analysis
- **Enhanced IAM Scanner**: Added MFA enforcement policy validation
- **Fixed Import Structure**: Added `__main__.py` for proper module execution
- **Fixed Remediation Generator**: Resolved variable scoping issues
- **Added S3 Remediation Scripts**: Automated fixes for S3 security findings
- Fixed base64 decoding issue in IAM credential report parsing
- Fixed Finding model to auto-calculate risk scores
- Updated documentation with correct usage instructions

## Documentation

- [Setup Guide](./README_SETUP.md) - Virtual environment setup and troubleshooting
- [AWS Security Tool PRD](./aws-security-tool-prd.md) - Product requirements document
- Additional docs in the [docs](./docs) directory

## License

MIT License