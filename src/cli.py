#!/usr/bin/env python3
"""
AWS Security Tool CLI
Main entry point for the security analysis tool
"""

import click
import boto3
import json
import sys
import os
from datetime import datetime
from pathlib import Path
from typing import List, Optional
import logging
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich import print as rprint

from .models import ScanResult, Finding
from .scanners import IAMScanner, S3Scanner, EC2Scanner, VPCScanner, RDSScanner
from .analyzers import FindingAnalyzer
from .generators import RemediationGenerator, ReportGenerator, DashboardGenerator
from .config import ConfigManager, ScanConfig


console = Console()
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@click.group()
@click.version_option(version='1.0.0')
def cli():
    """AWS Security Analysis Tool - Comprehensive security scanning for AWS accounts"""
    pass


@cli.command()
@click.option('--config', '-c', type=click.Path(exists=True), help='Configuration file path')
@click.option('--services', '-s', help='Comma-separated list of services to scan (overrides config)')
@click.option('--regions', '-r', help='Comma-separated list of regions to scan (overrides config)')
@click.option('--output-format', '-f', type=click.Choice(['html', 'markdown', 'json', 'text', 'csv', 'dashboard']), help='Output format for the report')
@click.option('--output-file', '-o', help='Output file path')
@click.option('--generate-remediation', '-g', is_flag=True, help='Generate remediation scripts')
@click.option('--remediation-dir', default='remediation-scripts', help='Directory to save remediation scripts')
@click.option('--profile', '-p', help='AWS profile to use')
@click.option('--no-progress', is_flag=True, help='Disable progress indicators')
@click.option('--severity-filter', help='Filter findings by minimum severity (CRITICAL,HIGH,MEDIUM,LOW,INFO)')
def scan(config, services, regions, output_format, output_file, generate_remediation, remediation_dir, profile, no_progress, severity_filter):
    """Perform a security scan of your AWS account"""
    
    # Load configuration
    config_manager = ConfigManager(config)
    try:
        scan_config = config_manager.load_config()
    except Exception as e:
        console.print(f"[yellow]Warning: Failed to load config file: {e}[/yellow]")
        scan_config = ScanConfig()  # Use defaults
    
    # Merge CLI options with config
    cli_options = {
        'services': [s.strip() for s in services.split(',')] if services else None,
        'regions': [r.strip() for r in regions.split(',')] if regions else None,
        'output_format': output_format,
        'output_file': output_file,
    }
    config_manager.merge_cli_options(**cli_options)
    
    # Setup AWS session
    try:
        session = boto3.Session(profile_name=profile) if profile else boto3.Session()
        account_id = session.client('sts').get_caller_identity()['Account']
    except Exception as e:
        console.print(f"[red]Error: Failed to establish AWS session: {e}[/red]")
        sys.exit(1)
    
    # Get enabled services and their configurations
    enabled_services = [
        service_name for service_name, service_config in scan_config.services.items()
        if service_config.enabled
    ]
    
    # Use first service's regions if specified, otherwise use all enabled regions
    region_list = None
    for service_name, service_config in scan_config.services.items():
        if service_config.enabled and service_config.regions:
            region_list = service_config.regions
            break
    
    # Initialize scan result with config metadata
    scan_result = ScanResult(
        scan_id=scan_config.scan_name or f"scan-{datetime.utcnow().strftime('%Y%m%d-%H%M%S')}",
        account_id=account_id,
        regions=region_list or [],
        services_scanned=enabled_services,
        start_time=datetime.utcnow()
    )
    
    # Add scan tags if configured
    if scan_config.scan_tags:
        scan_result.metadata = scan_config.scan_tags
    
    console.print(f"\n[bold blue]AWS Security Analysis Tool[/bold blue]")
    if scan_config.scan_name:
        console.print(f"Scan Name: [cyan]{scan_config.scan_name}[/cyan]")
    console.print(f"Account: [yellow]{account_id}[/yellow]")
    console.print(f"Services: [green]{', '.join(enabled_services)}[/green]")
    if region_list:
        console.print(f"Regions: [green]{', '.join(region_list)}[/green]")
    if config:
        console.print(f"Config: [blue]{config}[/blue]")
    console.print()
    
    # Perform scans
    all_findings = []
    scanners = []
    
    # Initialize scanners based on enabled services
    if 'iam' in enabled_services:
        service_config = scan_config.services['iam']
        scanners.append(IAMScanner(session, service_config.regions or region_list))
    
    if 's3' in enabled_services:
        service_config = scan_config.services['s3']
        scanners.append(S3Scanner(session, service_config.regions or region_list))
    
    if 'ec2' in enabled_services:
        service_config = scan_config.services['ec2']
        scanners.append(EC2Scanner(session, service_config.regions or region_list))
    
    if 'vpc' in enabled_services:
        service_config = scan_config.services['vpc']
        scanners.append(VPCScanner(session, service_config.regions or region_list))
    
    if 'rds' in enabled_services:
        service_config = scan_config.services['rds']
        scanners.append(RDSScanner(session, service_config.regions or region_list))
    
    if not scanners:
        console.print("[red]Error: No valid scanners found for the specified services[/red]")
        sys.exit(1)
    
    # Run scans
    if no_progress:
        for scanner in scanners:
            console.print(f"Scanning {scanner.service_name}...")
            findings = scanner.scan()
            all_findings.extend(findings)
            scan_result.total_resources_scanned += len(findings)
    else:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:
            for scanner in scanners:
                task = progress.add_task(f"Scanning {scanner.service_name}...", total=None)
                findings = scanner.scan()
                all_findings.extend(findings)
                scan_result.total_resources_scanned += len(findings)
                progress.update(task, completed=True)
    
    # Add findings to scan result
    for finding in all_findings:
        # Apply severity overrides from config
        if scan_config.risk_scoring.severity_overrides:
            if finding.title in scan_config.risk_scoring.severity_overrides:
                from .models import Severity
                new_severity = scan_config.risk_scoring.severity_overrides[finding.title]
                finding.severity = Severity[new_severity.upper()]
                # Recalculate risk score based on new severity
                severity_scores = {
                    Severity.CRITICAL: scan_config.risk_scoring.critical_weight,
                    Severity.HIGH: scan_config.risk_scoring.high_weight,
                    Severity.MEDIUM: scan_config.risk_scoring.medium_weight,
                    Severity.LOW: scan_config.risk_scoring.low_weight,
                    Severity.INFO: scan_config.risk_scoring.informational_weight
                }
                finding.risk_score = int(severity_scores.get(finding.severity, 50))
        
        # Check if finding should be suppressed
        if finding.title not in scan_config.output.suppress_findings:
            scan_result.add_finding(finding)
    
    # Apply severity filter if specified (CLI or config)
    min_severity_str = severity_filter or (scan_config.notifications.min_severity if scan_config.notifications.enabled else None)
    if min_severity_str:
        from .models import Severity
        min_severity = Severity[min_severity_str.upper()]
        severity_order = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
        min_index = severity_order.index(min_severity)
        
        filtered_findings = [
            f for f in scan_result.findings 
            if severity_order.index(f.severity) >= min_index
        ]
        scan_result.findings = filtered_findings
    
    scan_result.end_time = datetime.utcnow()
    
    # Display summary
    display_scan_summary(scan_result)
    
    # Generate report
    console.print("\n[bold]Generating report...[/bold]")
    
    # Determine output file name and format from config or CLI
    output_format = output_format or scan_config.output.format
    output_file = output_file or scan_config.output.file
    
    if not output_file:
        timestamp = datetime.utcnow().strftime('%Y%m%d-%H%M%S')
        output_file = f"aws-security-report-{timestamp}.{output_format}"
    
    # Generate report in requested format
    try:
        if output_format == 'dashboard':
            dashboard_generator = DashboardGenerator(scan_result)
            report_content = dashboard_generator.generate_dashboard()
        else:
            report_generator = ReportGenerator(scan_result)
            if output_format == 'html':
                report_content = report_generator.generate_html_report()
            elif output_format == 'markdown':
                report_content = report_generator.generate_markdown_report()
            elif output_format == 'json':
                report_content = report_generator.generate_json_report()
            elif output_format == 'csv':
                report_content = report_generator.generate_csv_report()
            else:  # text
                report_content = report_generator.generate_text_report()
        
        # Write report to file
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(report_content)
        
        console.print(f"[green]✓[/green] Report saved to: [blue]{output_file}[/blue]")
    except Exception as e:
        import traceback
        console.print(f"[red]Error generating report: {e}[/red]")
        console.print(f"[red]{traceback.format_exc()}[/red]")
        sys.exit(1)
    
    # Generate remediation scripts if requested
    if generate_remediation:
        generate_remediation_scripts(scan_result, remediation_dir)
    
    # Exit with appropriate code
    stats = scan_result.get_statistics()
    if stats['severity_distribution']['CRITICAL'] > 0:
        sys.exit(2)  # Critical findings
    elif stats['severity_distribution']['HIGH'] > 0:
        sys.exit(1)  # High findings
    else:
        sys.exit(0)  # Success


@cli.command()
@click.argument('report_file', type=click.Path(exists=True))
@click.option('--output-dir', '-o', default='remediation-scripts', help='Directory to save remediation scripts')
def generate_remediation(report_file, output_dir):
    """Generate remediation scripts from an existing report"""
    
    console.print(f"\n[bold]Loading report from {report_file}...[/bold]")
    
    try:
        with open(report_file, 'r') as f:
            if report_file.endswith('.json'):
                report_data = json.load(f)
                # Reconstruct findings from JSON
                from .models import Finding, Severity, Category
                findings = []
                for f_data in report_data['findings']:
                    finding = Finding(
                        finding_id=f_data['finding_id'],
                        severity=Severity[f_data['severity']],
                        category=Category[f_data['category']],
                        resource_type=f_data['resource_type'],
                        resource_id=f_data['resource_id'],
                        region=f_data['region'],
                        title=f_data['title'],
                        description=f_data['description'],
                        impact=f_data['impact'],
                        recommendation=f_data['recommendation'],
                        risk_score=f_data['risk_score'],
                        automated_remediation_available=f_data['automated_remediation_available'],
                        evidence=f_data['evidence']
                    )
                    findings.append(finding)
                
                # Create a minimal scan result
                scan_result = ScanResult(
                    scan_id=report_data['scan_info']['scan_id'],
                    account_id=report_data['scan_info']['account_id'],
                    regions=report_data['scan_info']['regions'],
                    services_scanned=report_data['scan_info']['services_scanned'],
                    start_time=datetime.fromisoformat(report_data['scan_info']['start_time']),
                    findings=findings
                )
                
                generate_remediation_scripts(scan_result, output_dir)
            else:
                console.print("[red]Error: Only JSON reports are supported for remediation generation[/red]")
                sys.exit(1)
    except Exception as e:
        console.print(f"[red]Error loading report: {e}[/red]")
        sys.exit(1)


@cli.command()
def list_services():
    """List all available services for scanning"""
    
    table = Table(title="Available Services")
    table.add_column("Service", style="cyan")
    table.add_column("Description", style="white")
    table.add_column("Status", style="green")
    
    services = [
        ("iam", "Identity and Access Management", "Available"),
        ("s3", "Simple Storage Service", "Available"),
        ("ec2", "Elastic Compute Cloud", "Available"),
        ("vpc", "Virtual Private Cloud", "Available"),
        ("rds", "Relational Database Service", "Coming Soon"),
        ("lambda", "Lambda Functions", "Coming Soon"),
        ("cloudtrail", "CloudTrail Logging", "Coming Soon"),
    ]
    
    for service, description, status in services:
        table.add_row(service, description, status)
    
    console.print(table)


@cli.command()
@click.option('--output', '-o', default='aws-security-config.example.yaml', help='Output file path')
def generate_config(output):
    """Generate an example configuration file"""
    
    console.print(f"\n[bold]Generating example configuration file...[/bold]")
    
    config_manager = ConfigManager()
    saved_path = config_manager.save_example_config(output)
    
    console.print(f"[green]✓[/green] Example configuration saved to: [blue]{saved_path}[/blue]")
    console.print("\nYou can use this configuration file with:")
    console.print(f"  [cyan]aws-security-tool scan --config {saved_path}[/cyan]")
    console.print("\nCustomize the file to:")
    console.print("  • Enable/disable specific services")
    console.print("  • Set custom regions per service")
    console.print("  • Override finding severities")
    console.print("  • Suppress specific findings")
    console.print("  • Configure output preferences")
    console.print("  • Filter resources by tags")


def display_scan_summary(scan_result: ScanResult):
    """Display a summary of scan results"""
    
    stats = scan_result.get_statistics()
    
    # Create summary table
    table = Table(title="Scan Summary", show_header=False)
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="white")
    
    table.add_row("Total Findings", str(stats['total_findings']))
    table.add_row("Critical", f"[red]{stats['severity_distribution']['CRITICAL']}[/red]")
    table.add_row("High", f"[orange1]{stats['severity_distribution']['HIGH']}[/orange1]")
    table.add_row("Medium", f"[yellow]{stats['severity_distribution']['MEDIUM']}[/yellow]")
    table.add_row("Low", f"[green]{stats['severity_distribution']['LOW']}[/green]")
    table.add_row("Informational", f"[blue]{stats['severity_distribution']['INFO']}[/blue]")
    
    if stats['scan_duration']:
        table.add_row("Scan Duration", f"{int(stats['scan_duration'])} seconds")
    
    console.print(table)
    
    # Show top findings
    analyzer = FindingAnalyzer(scan_result)
    priority_findings = analyzer.get_priority_findings(5)
    
    if priority_findings:
        console.print("\n[bold]Top Priority Findings:[/bold]")
        for i, finding in enumerate(priority_findings, 1):
            severity_color = {
                'CRITICAL': 'red',
                'HIGH': 'orange1',
                'MEDIUM': 'yellow',
                'LOW': 'green',
                'INFO': 'blue'
            }.get(finding.severity.value, 'white')
            
            console.print(f"{i}. [{severity_color}]{finding.severity.value}[/{severity_color}] {finding.title}")
            console.print(f"   Resource: {finding.resource_id}")
            console.print(f"   Risk Score: {finding.risk_score}")


def generate_remediation_scripts(scan_result: ScanResult, output_dir: str):
    """Generate remediation scripts for findings"""
    
    console.print(f"\n[bold]Generating remediation scripts...[/bold]")
    
    # Create output directory
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    
    # Initialize remediation generator
    remediation_generator = RemediationGenerator()
    
    # Generate scripts for findings with automated remediation
    remediation_count = 0
    for finding in scan_result.findings:
        if finding.automated_remediation_available:
            script = remediation_generator.generate_remediation_script(finding)
            if script:
                script_path = os.path.join(output_dir, script.script_name)
                with open(script_path, 'w') as f:
                    f.write(script.script_content)
                os.chmod(script_path, 0o755)  # Make executable
                remediation_count += 1
    
    # Generate batch remediation script
    if remediation_count > 0:
        batch_script = remediation_generator.generate_batch_remediation_script(
            [f for f in scan_result.findings if f.automated_remediation_available]
        )
        batch_path = os.path.join(output_dir, 'batch_remediation.py')
        with open(batch_path, 'w') as f:
            f.write(batch_script)
        os.chmod(batch_path, 0o755)
        
        console.print(f"[green]✓[/green] Generated {remediation_count} remediation scripts in: [blue]{output_dir}/[/blue]")
        console.print(f"[green]✓[/green] Batch remediation script: [blue]{batch_path}[/blue]")
    else:
        console.print("[yellow]No findings with automated remediation available[/yellow]")


def main():
    """Main entry point"""
    try:
        cli()
    except KeyboardInterrupt:
        console.print("\n[red]Interrupted by user[/red]")
        sys.exit(1)
    except Exception as e:
        console.print(f"\n[red]Unexpected error: {e}[/red]")
        logger.exception("Unexpected error")
        sys.exit(1)


if __name__ == '__main__':
    main()