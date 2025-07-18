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

Due to import structure issues in the codebase, the tool cannot be run directly via the installed command. Instead, use one of these methods:

1. **From the src directory:**
```bash
cd /home/ec2-user/aws-sec
source venv/bin/activate
cd aws-security-tool/src
python -m cli --help
```

2. **Using the runner script:**
```bash
cd /home/ec2-user/aws-sec
source venv/bin/activate
python run_tool.py --help
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
2. The tool needs to be run from the source directory or using the runner script as a workaround

### Deactivation

To deactivate the virtual environment:
```bash
deactivate
```