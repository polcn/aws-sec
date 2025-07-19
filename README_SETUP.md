# AWS Security Tool Setup Guide

## Virtual Environment Setup

A Python virtual environment has been created for this project to avoid conflicts with other projects on the server.

### Activation

To activate the virtual environment:

```bash
cd /home/ec2-user/aws-sec
source venv/bin/activate
```

Or use the provided activation script:
```bash
source /home/ec2-user/aws-sec/activate.sh
```

### Running the Tool

Due to import structure issues in the codebase, the tool cannot be run directly via the installed command. Use this method:

**Recommended Method:**
```bash
cd /home/ec2-user/aws-sec
source venv/bin/activate
PYTHONPATH=/home/ec2-user/aws-sec python -m src.cli scan
```

**Example Commands:**
```bash
# Basic scan
PYTHONPATH=/home/ec2-user/aws-sec python -m src.cli scan

# Generate HTML report
PYTHONPATH=/home/ec2-user/aws-sec python -m src.cli scan --output-format html --output-file report.html

# Generate markdown report
PYTHONPATH=/home/ec2-user/aws-sec python -m src.cli scan --output-format markdown --output-file report.md

# With remediation scripts (has minor issues)
PYTHONPATH=/home/ec2-user/aws-sec python -m src.cli scan --generate-remediation
```

### Dependencies

The following packages are installed in the virtual environment:
- boto3>=1.34.0 (AWS SDK)
- botocore>=1.34.0
- jinja2>=3.1.2
- python-dateutil>=2.8.2
- typing-extensions>=4.8.0
- pydantic>=2.5.0
- rich>=13.7.0
- click>=8.1.7
- PyYAML>=6.0.1
- cryptography>=41.0.7
- markdown>=3.5.1

### Python Version

This project requires Python 3.9 or higher. The virtual environment uses Python 3.9.23.

### Known Issues

1. The package has relative import issues that prevent the installed `aws-security-tool` command from working properly
2. The tool needs to be run with PYTHONPATH set as shown above
3. Remediation script generation has a minor variable scoping issue (being fixed)

### Recent Successful Scan

The tool has been successfully tested on AWS account 028358929215 on July 19, 2025:
- Successfully scanned IAM configurations
- Found 19 security issues (1 CRITICAL, 14 HIGH, 3 MEDIUM, 1 LOW)
- Generated both HTML and Markdown reports
- Fixed several bugs during initial run (base64 decoding, risk score calculation)

### Deactivation

To deactivate the virtual environment:
```bash
deactivate
```