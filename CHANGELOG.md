# Changelog

All notable changes to the AWS Security Analysis Tool will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.1] - 2025-07-19

### Added
- **Comprehensive Unit Tests for S3 Scanner**: 23 unit tests with 85% code coverage
- **Testing Infrastructure**: pytest configuration with coverage reporting
- **Test Documentation**: Added tests/README.md with testing guidelines

### Changed
- Updated requirements.txt to include testing dependencies
- Updated main README with testing section

## [1.1.0] - 2025-07-19

### Added
- **S3 Security Scanner**: Comprehensive S3 bucket security analysis
  - Encryption validation (SSE-S3, SSE-KMS)
  - Public access block configuration
  - Bucket ACL analysis
  - Bucket policy security checks
  - SSL/TLS enforcement detection
  - Versioning status
  - Access logging configuration
  - Lifecycle policy detection
  - Object Lock for compliance buckets
- **Enhanced IAM Scanner**: MFA enforcement policy validation
  - Checks user, group, and attached policies for MFA enforcement
  - Identifies users without MFA enforcement policies
- **S3 Remediation Scripts**: 8 types of automated fixes
  - Enable bucket encryption (SSE-S3 and SSE-KMS)
  - Block public access
  - Enable versioning
  - Enable access logging
  - Enforce SSL in bucket policies
  - Remove public ACL grants
- **Module Execution Support**: Added `__main__.py` for proper module execution
- **New Security Categories**: DATA_PROTECTION, ACCESS_CONTROL, COST_OPTIMIZATION
- **AWS Security Audit Program**: Comprehensive audit program documentation

### Changed
- Default services now include both IAM and S3
- Improved remediation script generation with proper string handling
- Updated CLI to support multi-service scanning

### Fixed
- Remediation generator variable scoping issue
- Package import structure for proper CLI installation
- F-string interpolation in remediation templates

### Testing
- S3-only scan: 110 findings (4 HIGH, 58 MEDIUM, 48 LOW)
- Combined IAM+S3 scan: 129 findings total
- All remediation scripts generate successfully

## [1.0.0] - 2025-07-18

### Initial Release
- IAM Security Scanner with comprehensive checks
- Multi-format reporting (HTML, Markdown, JSON, Text)
- Automated remediation script generation
- Risk prioritization and scoring
- Compliance framework mapping (NIST, CIS, SOX, OWASP)
- Virtual environment setup

### Known Issues at Release
- Package import structure issues
- Limited to IAM scanning only

## Roadmap

### Planned Features
- **EC2 Security Scanner**: Instance security, security groups, EBS encryption
- **VPC Security Scanner**: Network ACLs, security groups, flow logs
- **RDS Security Scanner**: Database encryption, backups, public access
- **Lambda Security Scanner**: Function policies, environment variables
- **CloudTrail Scanner**: Logging configuration, event analysis
- **Scheduled Scanning**: Automated periodic scans
- **Dashboard UI**: Web-based interface for reports
- **Integration**: CI/CD pipeline support, SIEM integration