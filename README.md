# AWS Security Analysis Tool

A comprehensive, open-source AWS security analysis tool that performs automated security assessments based on the AWS Well-Architected Security Pillar framework.

## Features

- **Multi-Service Security Scanning**: Support for IAM, S3, EC2, VPC, and RDS with more services coming soon
- **Security Findings with Risk Prioritization**: Comprehensive scanning aligned with AWS Well-Architected Security Pillar
- **Automated Remediation Scripts**: Generate executable Python scripts to fix identified issues
- **Configuration File Support**: Customize scan behavior, suppress findings, and override severities
- **IAM Security Analysis**: Deep analysis including MFA enforcement validation
- **S3 Security Analysis**: Comprehensive bucket security checks including encryption, public access, versioning, and more
- **EC2 Security Analysis**: Instance security, security groups, EBS encryption, network ACLs, and more
- **VPC Security Analysis**: Flow logs, endpoints, peering, NAT gateways, route tables, and network configuration
- **RDS Security Analysis**: Database encryption, backups, public access, Multi-AZ, deletion protection, and parameter security
- **Architecture Diagram Generation**: Auto-generate visual representation of AWS infrastructure
- **Compliance Framework Mapping**: Map findings to NIST, CIS, SOX, and OWASP frameworks with percentage scoring
- **Multi-Format Reporting**: Generate reports in HTML, Markdown, JSON, CSV, and plain text formats
- **Compliance Percentage Scoring**: Calculate weighted compliance scores for each framework with risk assessments

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

# Run a security scan on your AWS account (IAM + S3 + EC2 + VPC + RDS by default)
PYTHONPATH=/home/ec2-user/aws-sec python -m src.cli scan

# Scan specific services
PYTHONPATH=/home/ec2-user/aws-sec python -m src.cli scan --services iam
PYTHONPATH=/home/ec2-user/aws-sec python -m src.cli scan --services s3
PYTHONPATH=/home/ec2-user/aws-sec python -m src.cli scan --services iam,s3,ec2,vpc,rds

# Use a configuration file
PYTHONPATH=/home/ec2-user/aws-sec python -m src.cli scan --config aws-security-config.yaml

# Generate an example configuration file
PYTHONPATH=/home/ec2-user/aws-sec python -m src.cli generate-config

# Generate remediation scripts
PYTHONPATH=/home/ec2-user/aws-sec python -m src.cli scan --generate-remediation

# Output in different formats
PYTHONPATH=/home/ec2-user/aws-sec python -m src.cli scan --output-format html --output-file report.html
PYTHONPATH=/home/ec2-user/aws-sec python -m src.cli scan --output-format markdown --output-file report.md
PYTHONPATH=/home/ec2-user/aws-sec python -m src.cli scan --output-format json --output-file report.json
PYTHONPATH=/home/ec2-user/aws-sec python -m src.cli scan --output-format csv --output-file report.csv

# List available services
PYTHONPATH=/home/ec2-user/aws-sec python -m src.cli list-services
```

## Requirements

- Python 3.9+
- AWS credentials configured (via AWS CLI, environment variables, or IAM role)
- Appropriate AWS permissions to read resources

## Known Issues

1. **Import Structure**: The package has relative import issues preventing the installed command from working properly. Use the source method with PYTHONPATH as shown above.
2. **Limited Scanner Coverage**: Currently IAM, S3, EC2, VPC, and RDS scanning are implemented. Additional service scanners (Lambda, CloudTrail, etc.) are planned.

## Recent Updates (July 19, 2025)

### Version 1.4.0
- **Added Configuration File Support**: YAML-based configuration for customizing scan behavior
- **Configuration Features**: 
  - Enable/disable specific services
  - Set custom regions per service
  - Override finding severities
  - Suppress specific findings
  - Configure output preferences
  - Filter resources by tags
- **CLI Enhancement**: Added `generate-config` command to create example configuration files
- **Enhanced Test Coverage**: Added unit tests for configuration (91% coverage)

### Version 1.3.0
- **Added VPC Security Scanner**: Comprehensive VPC security analysis including flow logs, endpoints, peering, and network configuration
- **VPC Remediation Scripts**: Automated fixes for flow logs, VPC endpoints, and NAT gateway configuration
- **Enhanced Test Coverage**: Added unit tests for VPC scanner (77% coverage)

### Version 1.2.0
- **Added EC2 Security Scanner**: Comprehensive EC2 security analysis including instances, security groups, EBS volumes, and network configuration
- **EC2 Remediation Scripts**: Automated fixes for IMDSv2, security groups, and EBS encryption
- **Enhanced Test Coverage**: Added unit tests for EC2 scanner (76% coverage)

### Version 1.1.1
- **Added S3 Security Scanner**: Comprehensive S3 bucket security analysis
- **Enhanced IAM Scanner**: Added MFA enforcement policy validation
- **Fixed Import Structure**: Added `__main__.py` for proper module execution
- **Fixed Remediation Generator**: Resolved variable scoping issues
- **Added S3 Remediation Scripts**: Automated fixes for S3 security findings
- Fixed base64 decoding issue in IAM credential report parsing
- Fixed Finding model to auto-calculate risk scores
- Updated documentation with correct usage instructions

## Documentation

- [Configuration Guide](./docs/configuration.md) - How to use configuration files
- [Setup Guide](./README_SETUP.md) - Virtual environment setup and troubleshooting
- [Changelog](./CHANGELOG.md) - Version history and updates
- [TODO List](./TODO.md) - Roadmap and planned features
- [AWS Security Audit Program](./AWS_SECURITY_AUDIT_PROGRAM.md) - Comprehensive audit methodology
- [AWS Security Tool PRD](./aws-security-tool-prd.md) - Product requirements document
- Additional docs in the [docs](./docs) directory

## Testing

The project includes comprehensive unit tests:

```bash
# Run all tests
source venv/bin/activate
PYTHONPATH=/home/ec2-user/aws-sec python -m pytest

# Run with coverage
PYTHONPATH=/home/ec2-user/aws-sec python -m pytest --cov=src --cov-report=term-missing
```

Current test coverage:
- S3 Scanner: 85% coverage with 23 unit tests
- EC2 Scanner: 76% coverage with 8 unit tests
- VPC Scanner: 77% coverage with 13 unit tests
- RDS Scanner: 18 unit tests
- Configuration: 91% coverage with 18 unit tests
- Overall: 80 total tests

See [tests/README.md](./tests/README.md) for detailed testing information.

## Contributing

We welcome contributions! Please check our [TODO list](./TODO.md) for areas where you can help. Some ways to contribute:

- Add new security scanners for AWS services
- Improve existing scanners with additional checks
- Add remediation scripts for more finding types
- Enhance reporting capabilities
- Write tests and improve code coverage
- Update documentation

## License

MIT License