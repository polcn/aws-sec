"""AWS Lambda Security Scanner

This module provides security scanning for AWS Lambda functions.
"""

import json
import logging
import re
from typing import Dict, List, Any, Optional

import boto3
from botocore.exceptions import ClientError

from src.models import Finding, Severity, Category
from src.scanners.base import BaseScanner

logger = logging.getLogger(__name__)


class LambdaScanner(BaseScanner):
    """Scanner for AWS Lambda security configurations"""
    
    @property
    def service_name(self) -> str:
        return "lambda"
    
    def scan(self) -> List[Finding]:
        """Perform security scan across all regions"""
        findings = []
        
        for region in self.regions:
            logger.info(f"Scanning Lambda functions in {region}")
            
            try:
                lambda_client = self.session.client('lambda', region_name=region)
                
                try:
                    functions = self._get_all_functions(lambda_client)
                    logger.info(f"Found {len(functions)} Lambda functions in {region}")
                    
                    for function in functions:
                        function_name = function['FunctionName']
                        function_arn = function['FunctionArn']
                        
                        findings.extend(self._check_function_policy(lambda_client, function, region))
                        findings.extend(self._check_environment_secrets(function, region))
                        findings.extend(self._check_encryption(function, region))
                        findings.extend(self._check_function_url(lambda_client, function, region))
                        findings.extend(self._check_vpc_config(function, region))
                        findings.extend(self._check_runtime(function, region))
                        findings.extend(self._check_dead_letter_queue(function, region))
                        findings.extend(self._check_tracing(function, region))
                except ClientError as e:
                    if e.response['Error']['Code'] == 'UnauthorizedOperation':
                        findings.append(self._create_access_finding(region, 'Lambda'))
                    else:
                        logger.error(f"Error listing Lambda functions in {region}: {e}")
                    
            except ClientError as e:
                logger.error(f"Error connecting to Lambda in {region}: {e}")
                    
        return findings
    
    def _get_all_functions(self, client) -> List[Dict[str, Any]]:
        """Get all Lambda functions with pagination"""
        functions = []
        
        try:
            paginator = client.get_paginator('list_functions')
            for page in paginator.paginate():
                functions.extend(page.get('Functions', []))
        except ClientError as e:
            logger.error(f"Error listing Lambda functions: {e}")
            # Re-raise to be handled by the caller
            raise
            
        return functions
    
    def _check_function_policy(self, client, function: Dict[str, Any], region: str) -> List[Finding]:
        """Check Lambda function resource policy for security issues"""
        findings = []
        function_name = function['FunctionName']
        
        try:
            response = client.get_policy(FunctionName=function_name)
            policy = json.loads(response['Policy'])
            
            for statement in policy.get('Statement', []):
                if statement.get('Effect') == 'Allow':
                    principal = statement.get('Principal', {})
                    
                    if isinstance(principal, str) and principal == '*':
                        findings.append(Finding(
                            region=region,
                            service='Lambda',
                            resource_type='Function',
                            resource_id=function_name,
                            severity=Severity.HIGH,
                            category=Category.ACCESS_CONTROL,
                            title='Lambda Function Allows Public Access',
                            description=f'Lambda function {function_name} has a resource policy that allows public access',
                            impact='The function can be invoked by anyone on the internet, potentially leading to data exposure or unauthorized execution',
                            recommendation='Review and restrict the function policy to specific AWS accounts or services',
                            evidence={
                                'function_arn': function['FunctionArn'],
                                'statement_id': statement.get('Sid', 'N/A')
                            }
                        ))
                    elif isinstance(principal, dict) and principal.get('AWS') == '*':
                        findings.append(Finding(
                            region=region,
                            service='Lambda',
                            resource_type='Function',
                            resource_id=function_name,
                            severity=Severity.HIGH,
                            category=Category.ACCESS_CONTROL,
                            title='Lambda Function Allows Access from Any AWS Account',
                            description=f'Lambda function {function_name} allows access from any AWS account',
                            impact='Any AWS account can invoke this function, potentially leading to unauthorized access or abuse',
                            recommendation='Restrict access to specific AWS accounts or principals',
                            evidence={
                                'function_arn': function['FunctionArn'],
                                'statement_id': statement.get('Sid', 'N/A')
                            }
                        ))
                        
        except ClientError as e:
            if e.response['Error']['Code'] != 'ResourceNotFoundException':
                logger.error(f"Error checking policy for {function_name}: {e}")
                
        return findings
    
    def _check_environment_secrets(self, function: Dict[str, Any], region: str) -> List[Finding]:
        """Check for potential secrets in environment variables"""
        findings = []
        function_name = function['FunctionName']
        
        env_vars = function.get('Environment', {}).get('Variables', {})
        
        secret_patterns = [
            r'password',
            r'passwd',
            r'pwd',
            r'secret',
            r'key',
            r'token',
            r'api_key',
            r'apikey',
            r'access_key',
            r'private_key',
            r'credential'
        ]
        
        for key, value in env_vars.items():
            for pattern in secret_patterns:
                if re.search(pattern, key, re.IGNORECASE):
                    if not value.startswith('arn:aws:secretsmanager:') and not value.startswith('arn:aws:ssm:'):
                        findings.append(Finding(
                            region=region,
                            service='Lambda',
                            resource_type='Function',
                            resource_id=function_name,
                            severity=Severity.HIGH,
                            category=Category.DATA_PROTECTION,
                            title='Potential Secret in Environment Variables',
                            description=f'Lambda function {function_name} has potential secret in environment variable: {key}',
                            impact='Secrets stored in plain text environment variables can be exposed to anyone with read access to the function',
                            recommendation='Use AWS Secrets Manager or Systems Manager Parameter Store to store secrets',
                            evidence={
                                'function_arn': function['FunctionArn'],
                                'environment_variable': key
                            }
                        ))
                        break  # Only report once per environment variable
                        
        return findings
    
    def _check_encryption(self, function: Dict[str, Any], region: str) -> List[Finding]:
        """Check if Lambda function uses encryption at rest"""
        findings = []
        function_name = function['FunctionName']
        
        kms_key = function.get('KMSKeyArn')
        
        if not kms_key:
            findings.append(Finding(
                region=region,
                service='Lambda',
                resource_type='Function',
                resource_id=function_name,
                severity=Severity.MEDIUM,
                category=Category.ENCRYPTION,
                title='Lambda Function Not Using Customer-Managed KMS Key',
                description=f'Lambda function {function_name} is not encrypted with a customer-managed KMS key',
                impact='Function code and environment variables are encrypted with AWS-managed keys instead of customer-managed keys',
                recommendation='Enable encryption with a customer-managed KMS key for sensitive functions',
                evidence={
                    'function_arn': function['FunctionArn']
                }
            ))
            
        return findings
    
    def _check_function_url(self, client, function: Dict[str, Any], region: str) -> List[Finding]:
        """Check if Lambda function has a public URL"""
        findings = []
        function_name = function['FunctionName']
        
        try:
            response = client.get_function_url_config(FunctionName=function_name)
            
            if response.get('AuthType') == 'NONE':
                findings.append(Finding(
                    region=region,
                    service='Lambda',
                    resource_type='Function',
                    resource_id=function_name,
                    severity=Severity.HIGH,
                    category=Category.ACCESS_CONTROL,
                    title='Lambda Function URL Without Authentication',
                    description=f'Lambda function {function_name} has a public URL without authentication',
                    impact='The function can be invoked by anyone on the internet via its URL without any authentication',
                    recommendation='Enable IAM authentication for the function URL or remove it if not needed',
                    evidence={
                        'function_arn': function['FunctionArn'],
                        'function_url': response.get('FunctionUrl', 'N/A')
                    }
                ))
                
        except ClientError as e:
            if e.response['Error']['Code'] != 'ResourceNotFoundException':
                logger.error(f"Error checking function URL for {function_name}: {e}")
                
        return findings
    
    def _check_vpc_config(self, function: Dict[str, Any], region: str) -> List[Finding]:
        """Check VPC configuration for Lambda function"""
        findings = []
        function_name = function['FunctionName']
        
        vpc_config = function.get('VpcConfig', {})
        
        if not vpc_config or not vpc_config.get('SubnetIds'):
            findings.append(Finding(
                region=region,
                service='Lambda',
                resource_type='Function',
                resource_id=function_name,
                severity=Severity.LOW,
                category=Category.NETWORK,
                title='Lambda Function Not in VPC',
                description=f'Lambda function {function_name} is not configured to run in a VPC',
                impact='Function cannot access private VPC resources and is not isolated from the internet',
                recommendation='Consider running the function in a VPC if it needs to access private resources',
                evidence={
                    'function_arn': function['FunctionArn']
                }
            ))
            
        return findings
    
    def _check_runtime(self, function: Dict[str, Any], region: str) -> List[Finding]:
        """Check if Lambda runtime is supported"""
        findings = []
        function_name = function['FunctionName']
        runtime = function.get('Runtime', '')
        
        deprecated_runtimes = [
            'nodejs',
            'nodejs4.3',
            'nodejs6.10',
            'nodejs8.10',
            'nodejs10.x',
            'nodejs12.x',
            'python2.7',
            'python3.6',
            'python3.7',
            'dotnetcore1.0',
            'dotnetcore2.0',
            'dotnetcore2.1',
            'ruby2.5'
        ]
        
        if runtime in deprecated_runtimes:
            findings.append(Finding(
                region=region,
                service='Lambda',
                resource_type='Function',
                resource_id=function_name,
                severity=Severity.HIGH,
                category=Category.CONFIGURATION,
                title='Lambda Function Using Deprecated Runtime',
                description=f'Lambda function {function_name} is using deprecated runtime: {runtime}',
                impact='Deprecated runtimes no longer receive security updates and may have unpatched vulnerabilities',
                recommendation='Update to a supported runtime version',
                evidence={
                    'function_arn': function['FunctionArn'],
                    'current_runtime': runtime
                }
            ))
            
        return findings
    
    def _check_dead_letter_queue(self, function: Dict[str, Any], region: str) -> List[Finding]:
        """Check if Lambda function has dead letter queue configured"""
        findings = []
        function_name = function['FunctionName']
        
        dlq_config = function.get('DeadLetterConfig', {})
        
        if not dlq_config.get('TargetArn'):
            findings.append(Finding(
                region=region,
                service='Lambda',
                resource_type='Function',
                resource_id=function_name,
                severity=Severity.LOW,
                category=Category.OPERATIONAL,
                title='Lambda Function Without Dead Letter Queue',
                description=f'Lambda function {function_name} does not have a dead letter queue configured',
                impact='Failed invocations are not captured, making it difficult to debug and retry failed executions',
                recommendation='Configure a dead letter queue to handle failed invocations',
                evidence={
                    'function_arn': function['FunctionArn']
                }
            ))
            
        return findings
    
    def _check_tracing(self, function: Dict[str, Any], region: str) -> List[Finding]:
        """Check if Lambda function has tracing enabled"""
        findings = []
        function_name = function['FunctionName']
        
        tracing_config = function.get('TracingConfig', {})
        
        if tracing_config.get('Mode') != 'Active':
            findings.append(Finding(
                region=region,
                service='Lambda',
                resource_type='Function',
                resource_id=function_name,
                severity=Severity.LOW,
                category=Category.LOGGING,
                title='Lambda Function Without Active Tracing',
                description=f'Lambda function {function_name} does not have X-Ray tracing enabled',
                impact='Limited visibility into function performance and execution flow, making debugging and optimization difficult',
                recommendation='Enable X-Ray tracing for better observability and debugging',
                evidence={
                    'function_arn': function['FunctionArn'],
                    'current_mode': tracing_config.get('Mode', 'PassThrough')
                }
            ))
            
        return findings
    
    def _create_access_finding(self, region: str, service: str) -> Finding:
        """Create a finding for insufficient permissions"""
        return Finding(
            region=region,
            service=service,
            resource_type='Account',
            resource_id=self.account_id,
            severity=Severity.HIGH,
            category=Category.ACCESS_CONTROL,
            title=f'Insufficient Permissions to Scan {service}',
            description=f'The scanner does not have sufficient permissions to scan {service} resources in {region}',
            impact='Security vulnerabilities in this service may go undetected',
            recommendation=f'Grant the necessary IAM permissions to scan {service} resources',
            evidence={
                'error_type': 'UnauthorizedOperation',
                'required_permissions': [f'{service.lower()}:List*', f'{service.lower()}:Describe*', f'{service.lower()}:Get*']
            }
        )