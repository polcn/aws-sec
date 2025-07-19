"""Tests for configuration management."""

import pytest
import tempfile
import yaml
from pathlib import Path
from unittest.mock import patch, MagicMock

from src.config import ConfigManager, ScanConfig, ServiceConfig, RiskScoringConfig, OutputConfig
from src.models.finding import Severity


class TestConfigManager:
    """Test ConfigManager functionality."""
    
    def test_default_config_creation(self):
        """Test creating default configuration."""
        config_manager = ConfigManager()
        config = config_manager.load_config()
        
        assert isinstance(config, ScanConfig)
        assert config.services['iam'].enabled is True
        assert config.services['s3'].enabled is True
        assert config.services['ec2'].enabled is True
        assert config.services['vpc'].enabled is True
        assert config.services['rds'].enabled is False
        
    def test_load_config_from_file(self):
        """Test loading configuration from YAML file."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            config_data = {
                'services': {
                    'iam': {'enabled': False},
                    's3': {
                        'enabled': True,
                        'regions': ['us-east-1', 'us-west-2']
                    }
                },
                'scan_name': 'Test Scan',
                'risk_scoring': {
                    'critical_weight': 95,
                    'severity_overrides': {
                        'Test Finding': 'HIGH'
                    }
                }
            }
            yaml.dump(config_data, f)
            f.flush()
            
        try:
            config_manager = ConfigManager(f.name)
            config = config_manager.load_config()
            
            assert config.services['iam'].enabled is False
            assert config.services['s3'].enabled is True
            assert config.services['s3'].regions == ['us-east-1', 'us-west-2']
            assert config.scan_name == 'Test Scan'
            assert config.risk_scoring.critical_weight == 95
            assert config.risk_scoring.severity_overrides['Test Finding'] == 'HIGH'
        finally:
            Path(f.name).unlink()
            
    def test_invalid_yaml_file(self):
        """Test handling of invalid YAML file."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write("invalid: yaml: content: [")
            f.flush()
            
        try:
            config_manager = ConfigManager(f.name)
            with pytest.raises(Exception) as exc_info:
                config_manager.load_config()
            assert "Error parsing YAML" in str(exc_info.value)
        finally:
            Path(f.name).unlink()
            
    def test_merge_cli_options(self):
        """Test merging CLI options with configuration."""
        config_manager = ConfigManager()
        config_manager.load_config()
        
        # Test service override
        config_manager.merge_cli_options(services=['iam', 's3'])
        assert config_manager.config.services['iam'].enabled is True
        assert config_manager.config.services['s3'].enabled is True
        assert config_manager.config.services['ec2'].enabled is False
        assert config_manager.config.services['vpc'].enabled is False
        
        # Test output format override
        config_manager.merge_cli_options(output_format='json')
        assert config_manager.config.output.format == 'json'
        
        # Test output file override
        config_manager.merge_cli_options(output_file='test-report.json')
        assert config_manager.config.output.file == 'test-report.json'
        
        # Test regions override
        config_manager.merge_cli_options(regions=['us-east-1', 'eu-west-1'])
        assert config_manager.config.services['iam'].regions == ['us-east-1', 'eu-west-1']
        assert config_manager.config.services['s3'].regions == ['us-east-1', 'eu-west-1']
        
    def test_save_example_config(self):
        """Test saving example configuration file."""
        config_manager = ConfigManager()
        
        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / 'example.yaml'
            saved_path = config_manager.save_example_config(str(output_path))
            
            assert Path(saved_path).exists()
            
            # Load and validate the saved config
            with open(saved_path, 'r') as f:
                config_data = yaml.safe_load(f)
                
            assert 'services' in config_data
            assert 'iam' in config_data['services']
            assert 'risk_scoring' in config_data
            assert 'output' in config_data
            assert config_data['scan_name'] == 'Production Security Scan'
            

class TestServiceConfig:
    """Test ServiceConfig model."""
    
    def test_valid_regions(self):
        """Test valid region configuration."""
        config = ServiceConfig(regions=['us-east-1', 'eu-west-1'])
        assert config.regions == ['us-east-1', 'eu-west-1']
        
    def test_invalid_regions(self):
        """Test invalid region validation."""
        with pytest.raises(ValueError) as exc_info:
            ServiceConfig(regions=['us-east-1', 'invalid-region'])
        assert "Invalid regions" in str(exc_info.value)
        
    def test_filters(self):
        """Test service filters configuration."""
        config = ServiceConfig(
            filters={
                'exclude_buckets': ['test-*', '*-logs'],
                'max_age_days': 30
            }
        )
        assert config.filters['exclude_buckets'] == ['test-*', '*-logs']
        assert config.filters['max_age_days'] == 30
        

class TestRiskScoringConfig:
    """Test RiskScoringConfig model."""
    
    def test_default_weights(self):
        """Test default risk scoring weights."""
        config = RiskScoringConfig()
        assert config.critical_weight == 100.0
        assert config.high_weight == 80.0
        assert config.medium_weight == 60.0
        assert config.low_weight == 40.0
        assert config.informational_weight == 20.0
        
    def test_custom_weights(self):
        """Test custom risk scoring weights."""
        config = RiskScoringConfig(
            critical_weight=95,
            high_weight=75,
            medium_weight=55
        )
        assert config.critical_weight == 95
        assert config.high_weight == 75
        assert config.medium_weight == 55
        
    def test_severity_overrides(self):
        """Test severity override configuration."""
        config = RiskScoringConfig(
            severity_overrides={
                'Test Finding 1': 'HIGH',
                'Test Finding 2': 'LOW'
            }
        )
        assert config.severity_overrides['Test Finding 1'] == 'HIGH'
        assert config.severity_overrides['Test Finding 2'] == 'LOW'
        

class TestOutputConfig:
    """Test OutputConfig model."""
    
    def test_default_format(self):
        """Test default output format."""
        config = OutputConfig()
        assert config.format == 'markdown'
        
    def test_format_validation(self):
        """Test output format validation."""
        config = OutputConfig(format='json')
        assert config.format == 'json'
        
        with pytest.raises(ValueError):
            OutputConfig(format='invalid')
            
    def test_suppress_findings(self):
        """Test suppress findings configuration."""
        config = OutputConfig(
            suppress_findings=['Finding 1', 'Finding 2']
        )
        assert 'Finding 1' in config.suppress_findings
        assert 'Finding 2' in config.suppress_findings
        

class TestScanConfig:
    """Test main ScanConfig model."""
    
    def test_default_services(self):
        """Test default service configuration."""
        config = ScanConfig()
        assert 'iam' in config.services
        assert 's3' in config.services
        assert 'ec2' in config.services
        assert 'vpc' in config.services
        assert config.services['iam'].enabled is True
        assert config.services['rds'].enabled is False
        
    def test_scan_metadata(self):
        """Test scan metadata configuration."""
        config = ScanConfig(
            scan_name='Production Scan',
            scan_tags={
                'environment': 'prod',
                'team': 'security'
            }
        )
        assert config.scan_name == 'Production Scan'
        assert config.scan_tags['environment'] == 'prod'
        assert config.scan_tags['team'] == 'security'
        
    def test_resource_tag_filters(self):
        """Test resource tag filtering configuration."""
        config = ScanConfig(
            exclude_resource_tags={
                'Environment': ['dev', 'test'],
                'Ignore': ['true']
            },
            include_resource_tags={
                'Environment': ['prod'],
                'Critical': ['true']
            }
        )
        assert 'dev' in config.exclude_resource_tags['Environment']
        assert 'prod' in config.include_resource_tags['Environment']
        
    def test_api_retry_configuration(self):
        """Test API retry configuration."""
        config = ScanConfig(
            api_retry_attempts=5,
            api_retry_delay=2.5
        )
        assert config.api_retry_attempts == 5
        assert config.api_retry_delay == 2.5
        
        # Test validation limits
        with pytest.raises(ValueError):
            ScanConfig(api_retry_attempts=0)
            
        with pytest.raises(ValueError):
            ScanConfig(api_retry_attempts=25)