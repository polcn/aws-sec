# Changelog

All notable changes to the AWS Security Analysis Tool will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.6.0] - 2025-07-19

### Added
- **CSV Export Format**: Export security findings to CSV for spreadsheet analysis
  - Full finding details with all metadata
  - Summary statistics section
  - Proper handling of special characters and newlines
  - Compatible with Excel, Google Sheets, and other spreadsheet tools
- **Compliance Percentage Scoring**: Calculate compliance scores for each framework
  - Weighted scoring based on finding severity
  - Risk level assessment (Low/Medium/High/Critical)
  - Estimated passed checks calculation
  - Severity breakdown per framework
  - Visual compliance indicators in HTML reports
  - Compliance data in all report formats (HTML, Markdown, JSON, CSV)
- **Unit Tests**: Added comprehensive tests for report generator and compliance scoring

### Changed
- Updated configuration to support CSV format option
- Enhanced CLI to include CSV in output format choices
- Report generators now include compliance percentage scores
- HTML reports show visual compliance indicators with color coding

## [1.5.0] - 2025-07-19

### Added
- **RDS Security Scanner**: Comprehensive RDS security analysis
  - Database encryption at rest validation
  - Automated backup configuration checks
  - Public accessibility detection
  - Multi-AZ deployment validation
  - Deletion protection checks
  - Auto minor version upgrade status
  - Performance Insights configuration
  - IAM database authentication checks
  - Database snapshot encryption validation
  - Parameter group security analysis
- **RDS Remediation Scripts**: Automated fixes for RDS findings
  - Backup retention configuration
  - Disable public access
  - Enable Multi-AZ deployment
  - Enable deletion protection
  - Enable auto minor version upgrades
  - Enable Performance Insights
  - Enable IAM authentication
  - Encryption migration guidance
- **Unit Tests for RDS Scanner**: 18 comprehensive tests
- **New Security Categories**: Added OPERATIONAL and PATCHING categories

### Changed
- Default services now include IAM, S3, EC2, VPC, and RDS
- Updated CLI to support RDS scanning

## [1.4.0] - 2025-07-19

### Added
- **Configuration File Support**: YAML-based configuration for customizing scan behavior
  - Enable/disable specific AWS services
  - Set custom regions per service  
  - Override finding severities
  - Suppress specific findings
  - Configure output preferences
  - Filter resources by AWS tags
  - Set custom risk scoring weights
- **New CLI Commands**:
  - `generate-config`: Generate example configuration file
  - `--config` option: Specify configuration file path
- **Configuration Features**:
  - Default configuration paths supported
  - CLI options override configuration settings
  - Service-specific region configuration
  - Resource tag inclusion/exclusion filters
  - API retry configuration
  - Scan metadata and tagging
- **Unit Tests for Configuration**: 18 tests with 91% code coverage
- **Documentation**: Comprehensive configuration guide

### Changed
- Default services now include IAM, S3, EC2, and VPC
- CLI scan command now supports configuration files
- Improved error handling for configuration loading

### Fixed
- Pydantic validator compatibility for default service configuration

## [1.3.0] - 2025-07-19

### Added
- **VPC Security Scanner**: Comprehensive VPC security analysis
  - VPC tagging and DNS configuration checks
  - VPC Flow Logs monitoring validation
  - Internet Gateway and NAT Gateway configuration
  - VPC Peering connection security analysis
  - VPC endpoint recommendations for cost and security
  - Route table configuration checks
  - DHCP options security review
  - VPN connection configuration analysis
- **VPC Remediation Scripts**: Automated fixes for VPC findings
  - Enable VPC Flow Logs with CloudWatch integration
  - Create missing VPC endpoints (S3, DynamoDB, EC2, etc.)
  - Fix NAT Gateway configuration issues
- **Unit Tests for VPC Scanner**: 13 comprehensive tests with 77% code coverage

### Changed
- Default services list now includes VPC scanner
- Updated CLI to support VPC scanning

## [1.2.0] - 2025-07-19

### Added
- **EC2 Security Scanner**: Comprehensive EC2 security analysis
  - Instance security checks (IMDSv2 enforcement, public IPs, IAM roles)
  - Security group analysis for overly permissive rules
  - EBS volume encryption validation
  - VPC endpoint recommendations
  - Network ACL security checks
  - Elastic IP cost optimization
- **EC2 Remediation Scripts**: Automated fixes for EC2 findings
  - Enable IMDSv2 enforcement
  - Restrict security group rules
  - Enable EBS encryption
- **Unit Tests for EC2 Scanner**: 8 comprehensive tests with 76% code coverage

### Changed
- Default scan now includes EC2 along with IAM and S3
- Updated CLI to support EC2 scanning

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
- **RDS Security Scanner**: Database encryption, backups, public access
- **Lambda Security Scanner**: Function policies, environment variables
- **CloudTrail Scanner**: Logging configuration, event analysis
- **Scheduled Scanning**: Automated periodic scans
- **Dashboard UI**: Web-based interface for reports
- **Integration**: CI/CD pipeline support, SIEM integration
- **Container Security**: ECS/EKS security analysis
- **Cost Optimization**: Security-related cost recommendations