# AWS Security Analysis Tool

A comprehensive, open-source AWS security analysis tool that performs automated security assessments based on the AWS Well-Architected Security Pillar framework.

## Features

- **Multi-Service Security Scanning**: Support for IAM, S3, EC2, VPC, RDS, Lambda, and Cost Explorer
- **Security Findings with Risk Prioritization**: Comprehensive scanning aligned with AWS Well-Architected Security Pillar
- **Cost Optimization Analysis**: Identify cost-saving opportunities, underutilized resources, and spending anomalies
- **Automated Remediation Scripts**: Generate executable Python scripts to fix identified issues
- **Configuration File Support**: Customize scan behavior, suppress findings, and override severities
- **IAM Security Analysis**: Deep analysis including MFA enforcement validation
- **S3 Security Analysis**: Comprehensive bucket security checks including encryption, public access, versioning, and more
- **EC2 Security Analysis**: Instance security, security groups, EBS encryption, network ACLs, and more
- **VPC Security Analysis**: Flow logs, endpoints, peering, NAT gateways, route tables, and network configuration
- **RDS Security Analysis**: Database encryption, backups, public access, Multi-AZ, deletion protection, and parameter security
- **Lambda Security Analysis**: Function security, environment variables, permissions, and configuration
- **Cost Monitoring**: Track AWS spending trends, Reserved Instance coverage, Savings Plans utilization, and resource optimization
- **Architecture Diagram Generation**: Auto-generate visual representation of AWS infrastructure
- **Compliance Framework Mapping**: Map findings to NIST, CIS, SOX, and OWASP frameworks with percentage scoring
- **Multi-Format Reporting**: Generate reports in HTML, Markdown, JSON, CSV, and plain text formats
- **Executive Dashboard**: Interactive HTML dashboard with security score, cost analysis, charts, and remediation priorities
- **Compliance Percentage Scoring**: Calculate weighted compliance scores for each framework with risk assessments

## Latest Scan Results

The tool has been successfully tested on AWS account 028358929215. Recent comprehensive scan results:

### Full Security & Cost Analysis (July 22, 2025)
- **390 total findings** across all services
- 1 CRITICAL (Root account usage)
- 47 HIGH (Including admin privileges, wildcard policies, public S3 buckets, underutilized resources)
- 97 MEDIUM (Including unencrypted resources, missing logging, cost growth anomalies)
- 216 LOW (Including SSE-S3 encryption, lifecycle policies, tagging issues)
- 29 INFORMATIONAL (Best practice recommendations)

### Key Findings:
- **Security**: Root account recently used, multiple IAM users with admin privileges, public S3 buckets
- **Cost Optimization**: Low Reserved Instance utilization, underutilized EC2/RDS instances, untagged resources
- **Compliance**: Multiple findings mapped to NIST, CIS, SOX frameworks
- **Services Scanned**: IAM, S3, EC2, VPC, RDS, Lambda, Cost Explorer

### Cost Analysis Highlights:
- Identified potential monthly savings opportunities
- Detected services with >50% month-over-month cost growth
- Found underutilized compute resources (EC2, RDS)
- Discovered unoptimized storage configurations

View the full reports:
- [Comprehensive Security & Cost Report](./combined_scan.md)
- [Interactive Dashboard](./dashboard.html)

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

# Run a security scan on your AWS account (IAM + S3 + EC2 + VPC + RDS + Lambda by default)
PYTHONPATH=/home/ec2-user/aws-sec python -m src.cli scan

# Scan specific services
PYTHONPATH=/home/ec2-user/aws-sec python -m src.cli scan --services iam
PYTHONPATH=/home/ec2-user/aws-sec python -m src.cli scan --services s3
PYTHONPATH=/home/ec2-user/aws-sec python -m src.cli scan --services iam,s3,ec2,vpc,rds,lambda

# Run cost analysis
PYTHONPATH=/home/ec2-user/aws-sec python -m src.cli scan --services cost
PYTHONPATH=/home/ec2-user/aws-sec python -m src.cli scan --services cost,ec2,s3 --output-format dashboard

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

# Generate executive dashboard
PYTHONPATH=/home/ec2-user/aws-sec python -m src.cli scan --generate-dashboard --output-file dashboard.html

# List available services
PYTHONPATH=/home/ec2-user/aws-sec python -m src.cli list-services
```

## Requirements

- Python 3.9+
- AWS credentials configured (via AWS CLI, environment variables, or IAM role)
- Appropriate AWS permissions to read resources

## Known Issues

1. **Import Structure**: The package has relative import issues preventing the installed command from working properly. Use the source method with PYTHONPATH as shown above.
2. **Limited Scanner Coverage**: Currently IAM, S3, EC2, VPC, RDS, Lambda, and Cost Explorer scanning are implemented. Additional service scanners (CloudTrail, etc.) are planned.

## Recent Updates (July 22, 2025)

### Version 1.9.0
- **Added Cost Monitoring and Optimization**: Comprehensive AWS cost analysis and savings recommendations
  - Cost Explorer API integration for spending trend analysis
  - Reserved Instance and Savings Plans coverage analysis
  - Resource utilization monitoring (EC2, RDS, EBS)
  - Cost anomaly detection
  - Untagged resource identification for cost allocation
  - Interactive cost dashboard with potential savings visualization
  - Added cost optimization findings to existing EC2 and S3 scanners
- **Enhanced Dashboard**: Added cost analysis section to executive dashboard
  - Total potential savings display
  - Cost findings by service breakdown
  - Top cost optimization opportunities
  - Visual charts for savings by service

### Version 1.8.0
- **Added Lambda Security Scanner**: Comprehensive serverless function security analysis
  - Function policy checks for public access
  - Environment variable secret detection
  - KMS encryption verification
  - Function URL authentication checks
  - VPC configuration analysis
  - Runtime deprecation detection
  - Dead letter queue configuration
  - X-Ray tracing enablement
- **Lambda Scanner Test Coverage**: Full test suite with 96% coverage
- **Default Service Update**: Lambda scanner now enabled by default

### Version 1.7.0
- **Added Executive Dashboard**: Interactive HTML dashboard with security visualization
  - Overall security score with A-F grading system
  - Visual charts for severity distribution, compliance, and service findings
  - Key metrics display with attack surface analysis
  - Remediation priority matrix
  - Responsive design for all devices
- **Dashboard CLI Integration**: New `--generate-dashboard` option for creating executive dashboards
- **Fixed Dashboard Generation**: Resolved Jinja2 template issues with built-in filters

### Version 1.6.0
- **Added CSV Export Format**: Export findings to spreadsheet-compatible CSV files
- **Compliance Percentage Scoring**: Calculate weighted compliance scores for each framework
  - Risk level assessments and estimated passed checks
  - Visual compliance indicators in HTML reports

### Version 1.5.0
- **Added RDS Security Scanner**: Comprehensive database security analysis
- **RDS Remediation Scripts**: Automated fixes for database security findings
- **New Security Categories**: Added OPERATIONAL and PATCHING categories

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
- Lambda Scanner: 96% coverage with 21 unit tests
- Configuration: 91% coverage with 18 unit tests
- Overall: 101 total tests

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