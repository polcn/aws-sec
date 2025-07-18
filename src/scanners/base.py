from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional
import boto3
from botocore.exceptions import ClientError
from ..models import Finding, ScanResult
import logging


class BaseScanner(ABC):
    """Base class for all service scanners"""
    
    def __init__(self, session: boto3.Session, regions: Optional[List[str]] = None):
        self.session = session
        self.regions = regions or self._get_enabled_regions()
        self.logger = logging.getLogger(self.__class__.__name__)
        self.account_id = self._get_account_id()
    
    @property
    @abstractmethod
    def service_name(self) -> str:
        """Return the AWS service name this scanner handles"""
        pass
    
    @abstractmethod
    def scan(self) -> List[Finding]:
        """Perform the security scan and return findings"""
        pass
    
    def _get_account_id(self) -> str:
        """Get the AWS account ID"""
        try:
            sts = self.session.client('sts')
            return sts.get_caller_identity()['Account']
        except ClientError as e:
            self.logger.error(f"Failed to get account ID: {e}")
            return "unknown"
    
    def _get_enabled_regions(self) -> List[str]:
        """Get list of enabled regions for the account"""
        try:
            ec2 = self.session.client('ec2', region_name='us-east-1')
            regions = ec2.describe_regions(
                Filters=[{'Name': 'opt-in-status', 'Values': ['opt-in-not-required', 'opted-in']}]
            )
            return [r['RegionName'] for r in regions['Regions']]
        except ClientError as e:
            self.logger.error(f"Failed to get regions: {e}")
            # Return default regions
            return ['us-east-1', 'us-west-2', 'eu-west-1', 'eu-central-1']
    
    def _paginate(self, client, operation: str, **kwargs) -> List[Dict[str, Any]]:
        """Helper method to handle pagination"""
        paginator = client.get_paginator(operation)
        results = []
        try:
            for page in paginator.paginate(**kwargs):
                results.extend(page.get(self._get_result_key(operation), []))
        except ClientError as e:
            self.logger.error(f"Error during pagination for {operation}: {e}")
        return results
    
    def _get_result_key(self, operation: str) -> str:
        """Get the result key for paginated operations"""
        # This is a simplified mapping - extend as needed
        operation_keys = {
            'list_users': 'Users',
            'list_roles': 'Roles',
            'list_policies': 'Policies',
            'list_access_keys': 'AccessKeyMetadata',
            'describe_instances': 'Reservations',
            'list_buckets': 'Buckets',
        }
        return operation_keys.get(operation, 'Results')
    
    def _handle_error(self, error: ClientError, context: str) -> None:
        """Handle AWS API errors gracefully"""
        error_code = error.response.get('Error', {}).get('Code', 'Unknown')
        if error_code == 'AccessDenied':
            self.logger.warning(f"Access denied for {context}. Skipping...")
        elif error_code == 'UnauthorizedOperation':
            self.logger.warning(f"Unauthorized operation for {context}. Skipping...")
        else:
            self.logger.error(f"Error in {context}: {error}")
    
    def _get_tag_value(self, tags: List[Dict[str, str]], key: str) -> Optional[str]:
        """Extract tag value from tag list"""
        for tag in tags:
            if tag.get('Key') == key:
                return tag.get('Value')
        return None