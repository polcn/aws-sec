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

# With remediation scripts
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

### Running Tests

To run the unit tests:
```bash
# Basic test run
PYTHONPATH=/home/ec2-user/aws-sec python -m pytest

# With coverage report
PYTHONPATH=/home/ec2-user/aws-sec python -m pytest --cov=src --cov-report=term-missing

# Run specific test file
PYTHONPATH=/home/ec2-user/aws-sec python -m pytest tests/test_s3_scanner.py -v
```

Current test coverage (78 total tests):
- S3 Scanner: 85% coverage with 23 unit tests
- EC2 Scanner: 76% coverage with 8 unit tests
- VPC Scanner: 77% coverage with 13 unit tests
- RDS Scanner: 16 unit tests
- Configuration: 91% coverage with 18 unit tests

### Recent Successful Scan

The tool has been successfully tested on AWS account 028358929215 on July 19, 2025:
- Successfully scanned IAM, S3, EC2, and VPC configurations
- Comprehensive scan found 148 security issues across all services
- S3-only scan found 110 findings (4 HIGH, 58 MEDIUM, 48 LOW)
- VPC-only scan found 84 findings (17 HIGH, 67 LOW)
- Configuration file support allows customization of scan behavior
- Generated remediation scripts for all automated fixes
- Generated reports in HTML, Markdown, JSON, and Text formats

### Deactivation

To deactivate the virtual environment:
```bash
deactivate
```