# AWS Security Analysis Tool

A comprehensive, open-source AWS security analysis tool that performs automated security assessments based on the AWS Well-Architected Security Pillar framework.

## Features

- **Security Findings with Risk Prioritization**: Comprehensive scanning aligned with AWS Well-Architected Security Pillar
- **Automated Remediation Scripts**: Generate executable Python scripts to fix identified issues
- **IAM Security Analysis**: Deep analysis of IAM configurations and access patterns
- **Architecture Diagram Generation**: Auto-generate visual representation of AWS infrastructure
- **Compliance Framework Mapping**: Map findings to NIST, OWASP, and SOX frameworks
- **Multi-Format Reporting**: Generate reports in HTML, Markdown, JSON, and plain text formats

## Latest Scan Results

The tool has been successfully tested on AWS account 028358929215. Recent scan found:
- **19 total security findings**
- 1 CRITICAL (Root account usage)
- 14 HIGH (Including admin privileges and wildcard policies)
- 3 MEDIUM (Unused IAM users, weak password policy)
- 1 LOW

View the full reports:
- [HTML Report](./scan_results_20250719_141513.html)
- [Markdown Report](./scan_results_20250719_141613.md)

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

# Run a security scan on your AWS account
PYTHONPATH=/home/ec2-user/aws-sec python -m src.cli scan

# Generate remediation scripts (currently has minor issues)
PYTHONPATH=/home/ec2-user/aws-sec python -m src.cli scan --generate-remediation

# Output in different formats
PYTHONPATH=/home/ec2-user/aws-sec python -m src.cli scan --output-format html --output-file report.html
PYTHONPATH=/home/ec2-user/aws-sec python -m src.cli scan --output-format markdown --output-file report.md
PYTHONPATH=/home/ec2-user/aws-sec python -m src.cli scan --output-format json --output-file report.json
```

## Requirements

- Python 3.9+
- AWS credentials configured (via AWS CLI, environment variables, or IAM role)
- Appropriate AWS permissions to read resources

## Known Issues

1. **Import Structure**: The package has relative import issues preventing the installed command from working properly. Use the source method with PYTHONPATH as shown above.
2. **Remediation Generator**: Minor issue with variable scoping in remediation script generation (being fixed).
3. **Limited Scanner Coverage**: Currently only IAM scanning is implemented. Additional service scanners (S3, EC2, etc.) are planned.

## Recent Updates (July 19, 2025)

- Fixed base64 decoding issue in IAM credential report parsing
- Fixed Finding model to auto-calculate risk scores
- Added comprehensive scan reports showing 19 security findings
- Updated documentation with correct usage instructions

## Documentation

- [Setup Guide](./README_SETUP.md) - Virtual environment setup and troubleshooting
- [AWS Security Tool PRD](./aws-security-tool-prd.md) - Product requirements document
- Additional docs in the [docs](./docs) directory

## License

MIT License