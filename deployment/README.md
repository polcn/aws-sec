# AWS Security Tool Deployment Guide

## Local Installation

### Prerequisites
- Python 3.9 or higher
- AWS CLI configured with appropriate credentials
- pip package manager

### Installation Steps

1. Clone the repository:
```bash
git clone https://github.com/yourusername/aws-security-tool.git
cd aws-security-tool
```

2. Install the tool:
```bash
pip install -e .
```

3. Verify installation:
```bash
aws-security-tool --version
```

## Usage

### Basic Scan
Run a security scan on your AWS account:
```bash
aws-security-tool scan
```

### Scan Specific Services
```bash
aws-security-tool scan --services iam,s3,ec2,vpc,rds
```

### Use Configuration File
```bash
# Generate example configuration
aws-security-tool generate-config

# Use configuration file
aws-security-tool scan --config aws-security-config.yaml
```

### Generate Different Report Formats
```bash
# HTML report (default)
aws-security-tool scan --output-format html --output-file report.html

# Markdown report
aws-security-tool scan --output-format markdown --output-file report.md

# JSON report (for programmatic access)
aws-security-tool scan --output-format json --output-file report.json
```

### Generate Remediation Scripts
```bash
aws-security-tool scan --generate-remediation
```

### Use Specific AWS Profile
```bash
aws-security-tool scan --profile production
```

### Filter by Severity
```bash
aws-security-tool scan --severity-filter HIGH
```

## Lambda Deployment

### Deploy with CloudFormation

1. Deploy the CloudFormation stack:
```bash
aws cloudformation create-stack \
  --stack-name aws-security-tool \
  --template-body file://deployment/cloudformation-template.yaml \
  --capabilities CAPABILITY_NAMED_IAM \
  --parameters \
    ParameterKey=S3BucketName,ParameterValue=my-security-reports \
    ParameterKey=EmailNotification,ParameterValue=security@example.com
```

2. Wait for stack creation:
```bash
aws cloudformation wait stack-create-complete \
  --stack-name aws-security-tool
```

3. Get stack outputs:
```bash
aws cloudformation describe-stacks \
  --stack-name aws-security-tool \
  --query 'Stacks[0].Outputs'
```

### Package Lambda Function

To deploy the actual security tool code to Lambda:

1. Create deployment package:
```bash
cd aws-security-tool
zip -r ../deployment-package.zip src/ -x "*.pyc" "__pycache__/*"
cd ..
pip install -r aws-security-tool/requirements.txt -t lambda-layer/python/
cd lambda-layer
zip -r ../lambda-layer.zip python/
```

2. Update Lambda function code:
```bash
aws lambda update-function-code \
  --function-name AWSSecurityScanFunction \
  --zip-file fileb://deployment-package.zip
```

## IAM Permissions

### Minimum Required Permissions

For running the security tool, the IAM user/role needs the following permissions:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "iam:Get*",
        "iam:List*",
        "iam:GenerateCredentialReport",
        "ec2:Describe*",
        "s3:Get*",
        "s3:List*",
        "vpc:Describe*",
        "rds:Describe*",
        "logs:DescribeLogGroups",
        "logs:DescribeLogStreams",
        "sts:GetCallerIdentity"
      ],
      "Resource": "*"
    }
  ]
}
```

## Scheduled Scans

The CloudFormation template sets up daily scans at 2 AM UTC. To modify the schedule:

```bash
aws cloudformation update-stack \
  --stack-name aws-security-tool \
  --template-body file://deployment/cloudformation-template.yaml \
  --capabilities CAPABILITY_NAMED_IAM \
  --parameters \
    ParameterKey=ScanSchedule,ParameterValue="cron(0 8 * * ? *)"
```

## Monitoring

### CloudWatch Dashboard
Access the dashboard URL from the CloudFormation outputs to monitor:
- Lambda invocations
- Errors
- Execution duration
- Recent scan logs

### Logs
View Lambda logs:
```bash
aws logs tail /aws/lambda/AWSSecurityScanFunction --follow
```

## Troubleshooting

### Common Issues

1. **Permission Denied Errors**
   - Ensure the IAM role/user has all required permissions
   - Check CloudTrail logs for specific access denied events

2. **Lambda Timeout**
   - Increase Lambda timeout in CloudFormation template
   - Consider splitting large accounts into regional scans

3. **Report Generation Fails**
   - Check S3 bucket permissions
   - Ensure Lambda has sufficient memory

### Debug Mode
Run with debug logging:
```bash
export AWS_SECURITY_TOOL_DEBUG=1
aws-security-tool scan
```

## Security Considerations

1. **Data Protection**
   - All reports are encrypted at rest in S3
   - No data leaves your AWS account
   - Sensitive findings are masked in reports

2. **Access Control**
   - Use IAM roles with least privilege
   - Enable MFA for users running the tool
   - Rotate access keys regularly

3. **Audit Trail**
   - All tool actions are logged to CloudTrail
   - Lambda invocations are tracked
   - S3 access logging is enabled

## Support

For issues or questions:
- Create an issue on GitHub
- Check the documentation
- Review CloudWatch logs for errors