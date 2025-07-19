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
- **Compliance Framework Mapping**: Map findings to NIST, CIS, SOX, and OWASP frameworks
- **Multi-Format Reporting**: Generate reports in HTML, Markdown, JSON, and plain text formats

## Installation

### Using Virtual Environment (Recommended)

Due to potential conflicts with other Python projects on the same system, it's recommended to use a virtual environment:

```bash
# Clone the repository
cd /home/ec2-user/aws-sec

# Activate the virtual environment
source venv/bin/activate

# The tool is already installed in the virtual environment
```

### Running the Tool

Due to import structure in the codebase, use one of these methods:

```bash
# Method 1: Using the runner script
cd /home/ec2-user/aws-sec
source venv/bin/activate
python run_tool.py --help

# Method 2: From the source directory
cd /home/ec2-user/aws-sec
source venv/bin/activate
cd aws-security-tool/src
python -m cli --help
```

## Quick Start

```bash
# First activate the environment and navigate to the tool
cd /home/ec2-user/aws-sec
source venv/bin/activate

# Run a security scan on your AWS account (all services by default)
python run_tool.py scan

# Generate remediation scripts
python run_tool.py scan --generate-remediation

# Scan specific services
python run_tool.py scan --services iam,s3,ec2,vpc

# Use a configuration file
python run_tool.py scan --config aws-security-config.yaml

# Generate example configuration
python run_tool.py generate-config

# Output in different formats
python run_tool.py scan --output-format html --output-file report.html
```

## Requirements

- Python 3.9+
- AWS credentials configured (via AWS CLI, environment variables, or IAM role)
- Appropriate AWS permissions to read resources

## Documentation

See the [docs](./docs) directory for detailed documentation.

## License

MIT License