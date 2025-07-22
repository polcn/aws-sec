"""Configuration management for AWS Security Analysis Tool."""

from typing import Dict, List, Optional, Any
from pathlib import Path
import yaml
from pydantic import BaseModel, Field, validator
import os


class ServiceConfig(BaseModel):
    """Configuration for individual AWS service scanners."""
    
    enabled: bool = True
    regions: Optional[List[str]] = None
    exclude_regions: Optional[List[str]] = None
    filters: Optional[Dict[str, Any]] = Field(default_factory=dict)
    
    @validator('regions', 'exclude_regions')
    def validate_regions(cls, v):
        """Validate AWS region names."""
        if v is None:
            return v
        valid_regions = {
            'us-east-1', 'us-east-2', 'us-west-1', 'us-west-2',
            'eu-west-1', 'eu-west-2', 'eu-west-3', 'eu-central-1', 'eu-north-1',
            'ap-northeast-1', 'ap-northeast-2', 'ap-northeast-3',
            'ap-southeast-1', 'ap-southeast-2', 'ap-south-1',
            'ca-central-1', 'sa-east-1'
        }
        invalid = set(v) - valid_regions
        if invalid:
            raise ValueError(f"Invalid regions: {invalid}")
        return v


class RiskScoringConfig(BaseModel):
    """Configuration for risk scoring weights."""
    
    critical_weight: float = Field(default=100.0, ge=0, le=100)
    high_weight: float = Field(default=80.0, ge=0, le=100)
    medium_weight: float = Field(default=60.0, ge=0, le=100)
    low_weight: float = Field(default=40.0, ge=0, le=100)
    informational_weight: float = Field(default=20.0, ge=0, le=100)
    
    severity_overrides: Optional[Dict[str, str]] = Field(default_factory=dict)
    

class OutputConfig(BaseModel):
    """Configuration for output formatting and reporting."""
    
    format: str = Field(default="markdown", pattern="^(markdown|html|json|text|csv)$")
    file: Optional[str] = None
    include_passed_checks: bool = False
    suppress_findings: Optional[List[str]] = Field(default_factory=list)
    group_by: str = Field(default="severity", pattern="^(severity|service|resource|compliance)$")
    

class NotificationConfig(BaseModel):
    """Configuration for notifications (future enhancement)."""
    
    enabled: bool = False
    slack_webhook: Optional[str] = None
    email_recipients: Optional[List[str]] = Field(default_factory=list)
    min_severity: str = Field(default="HIGH", pattern="^(CRITICAL|HIGH|MEDIUM|LOW|INFORMATIONAL)$")


class ComplianceConfig(BaseModel):
    """Configuration for compliance framework mapping."""
    
    frameworks: List[str] = Field(default_factory=lambda: ["NIST", "CIS"])
    custom_mappings: Optional[Dict[str, List[str]]] = Field(default_factory=dict)
    

class ScanConfig(BaseModel):
    """Main configuration for AWS Security Analysis Tool."""
    
    services: Dict[str, ServiceConfig] = Field(default_factory=dict)
    risk_scoring: RiskScoringConfig = Field(default_factory=RiskScoringConfig)
    output: OutputConfig = Field(default_factory=OutputConfig)
    notifications: NotificationConfig = Field(default_factory=NotificationConfig)
    compliance: ComplianceConfig = Field(default_factory=ComplianceConfig)
    
    scan_name: Optional[str] = None
    scan_tags: Optional[Dict[str, str]] = Field(default_factory=dict)
    max_concurrent_regions: int = Field(default=5, ge=1, le=20)
    api_retry_attempts: int = Field(default=3, ge=1, le=10)
    api_retry_delay: float = Field(default=1.0, ge=0.1, le=60.0)
    
    exclude_resource_tags: Optional[Dict[str, List[str]]] = Field(default_factory=dict)
    include_resource_tags: Optional[Dict[str, List[str]]] = Field(default_factory=dict)
    
    @validator('services', pre=True, always=True)
    def set_default_services(cls, v):
        """Set default service configurations if not specified."""
        if v is None:
            v = {}
            
        defaults = {
            'iam': {'enabled': True},
            's3': {'enabled': True},
            'ec2': {'enabled': True},
            'vpc': {'enabled': True},
            'rds': {'enabled': True},
            'lambda': {'enabled': True},
            'cloudtrail': {'enabled': False},
            'cost': {'enabled': False},
        }
        
        # Merge with defaults
        result = {}
        for service, default_config in defaults.items():
            if service in v:
                # Merge user config with defaults
                result[service] = {**default_config, **v[service]}
            else:
                result[service] = default_config
                
        # Add any extra services from user config
        for service, config in v.items():
            if service not in result:
                result[service] = config
                
        return result


class ConfigManager:
    """Manages configuration loading and validation."""
    
    DEFAULT_CONFIG_PATHS = [
        Path.home() / ".aws-security-tool" / "config.yaml",
        Path.cwd() / "aws-security-config.yaml",
        Path.cwd() / ".aws-security.yaml",
    ]
    
    def __init__(self, config_path: Optional[str] = None):
        """Initialize configuration manager.
        
        Args:
            config_path: Optional path to configuration file
        """
        self.config_path = config_path
        self.config: Optional[ScanConfig] = None
        
    def load_config(self) -> ScanConfig:
        """Load configuration from file or use defaults.
        
        Returns:
            Loaded configuration object
        """
        if self.config:
            return self.config
            
        config_data = {}
        
        # Try to load from specified path first
        if self.config_path:
            config_data = self._load_yaml_file(Path(self.config_path))
        else:
            # Try default paths
            for path in self.DEFAULT_CONFIG_PATHS:
                if path.exists():
                    config_data = self._load_yaml_file(path)
                    break
                    
        # Create config object with loaded data or defaults
        self.config = ScanConfig(**config_data)
        return self.config
        
    def _load_yaml_file(self, path: Path) -> dict:
        """Load YAML configuration file.
        
        Args:
            path: Path to YAML file
            
        Returns:
            Loaded configuration data
            
        Raises:
            Exception: If file cannot be loaded or parsed
        """
        try:
            with open(path, 'r') as f:
                data = yaml.safe_load(f) or {}
            print(f"Loaded configuration from {path}")
            return data
        except yaml.YAMLError as e:
            raise Exception(f"Error parsing YAML configuration: {e}")
        except Exception as e:
            raise Exception(f"Error loading configuration file: {e}")
            
    def save_example_config(self, path: Optional[str] = None) -> str:
        """Save an example configuration file.
        
        Args:
            path: Optional path to save file
            
        Returns:
            Path where file was saved
        """
        if not path:
            path = "aws-security-config.example.yaml"
            
        example_config = {
            "services": {
                "iam": {
                    "enabled": True,
                    "filters": {
                        "exclude_users": ["terraform-*", "ci-*"]
                    }
                },
                "s3": {
                    "enabled": True,
                    "regions": ["us-east-1", "us-west-2"],
                    "filters": {
                        "exclude_buckets": ["*-logs-*", "*-backup-*"]
                    }
                },
                "ec2": {
                    "enabled": True,
                    "exclude_regions": ["ap-south-1"]
                },
                "vpc": {
                    "enabled": True
                },
                "rds": {
                    "enabled": False
                }
            },
            "risk_scoring": {
                "critical_weight": 100,
                "high_weight": 80,
                "medium_weight": 60,
                "low_weight": 40,
                "severity_overrides": {
                    "S3 Bucket Without Lifecycle Policy": "LOW",
                    "Unused IAM User": "HIGH"
                }
            },
            "output": {
                "format": "markdown",
                "file": "security-report.md",
                "include_passed_checks": False,
                "suppress_findings": [
                    "S3 Bucket Using SSE-S3 Instead of SSE-KMS"
                ],
                "group_by": "severity"
            },
            "compliance": {
                "frameworks": ["NIST", "CIS", "SOX"],
                "custom_mappings": {
                    "Custom Finding Type": ["NIST", "CIS"]
                }
            },
            "scan_name": "Production Security Scan",
            "scan_tags": {
                "environment": "production",
                "team": "security"
            },
            "max_concurrent_regions": 5,
            "api_retry_attempts": 3,
            "exclude_resource_tags": {
                "Environment": ["development", "test"],
                "Ignore-Security-Scan": ["true"]
            },
            "include_resource_tags": {
                "Environment": ["production"],
                "Critical": ["true"]
            }
        }
        
        with open(path, 'w') as f:
            yaml.dump(example_config, f, default_flow_style=False, sort_keys=False)
            
        return path
        
    def merge_cli_options(self, **kwargs) -> None:
        """Merge CLI options with loaded configuration.
        
        Args:
            **kwargs: CLI options to merge
        """
        if not self.config:
            self.load_config()
            
        # Map CLI options to config fields
        if 'services' in kwargs and kwargs['services']:
            # Enable only specified services
            for service in self.config.services:
                self.config.services[service].enabled = service in kwargs['services']
                
        if 'output_format' in kwargs and kwargs['output_format']:
            self.config.output.format = kwargs['output_format']
            
        if 'output_file' in kwargs and kwargs['output_file']:
            self.config.output.file = kwargs['output_file']
            
        if 'regions' in kwargs and kwargs['regions']:
            # Apply regions to all enabled services
            for service, config in self.config.services.items():
                if config.enabled:
                    config.regions = kwargs['regions']