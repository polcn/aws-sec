# AWS Cost Analysis Guide

## Overview

The AWS Security Tool includes comprehensive cost analysis capabilities that help identify optimization opportunities, reduce waste, and forecast future spending. This guide covers all cost analysis features and how to use them effectively.

## Features

### Core Cost Analysis

#### 1. **Cost Trends and Anomalies**
- Analyzes last 3 months of spending data
- Detects month-over-month cost growth (alerts on >20% increase)
- Service-level cost spike detection (>50% growth triggers)
- Integrates with AWS Cost Anomaly Detection service

#### 2. **Reserved Instance & Savings Plans**
- Monitors RI coverage (alerts when <70%)
- Tracks RI utilization (alerts when <80%)
- Savings Plans coverage monitoring (alerts when <60%)
- Provides specific purchase recommendations

#### 3. **Cost Forecasting**
- Predicts next month's costs using AWS Cost Explorer API
- Compares forecast with historical spending
- Alerts on projected cost increases >20%
- Helps with budget planning and control

### Resource Optimization

#### 1. **EC2 Instance Analysis**
- CPU utilization monitoring (flags <10% as underutilized)
- Identifies overutilized instances (>90% CPU)
- Spot instance opportunity identification
- Right-sizing recommendations

#### 2. **RDS Database Optimization**
- Database CPU and connection monitoring
- Multi-AZ analysis for non-production environments
- Identifies idle or underutilized databases
- Suggests downsizing opportunities

#### 3. **Lambda Function Optimization**
- Memory allocation analysis
- Duration vs timeout comparison
- Identifies overprovisioned functions
- Cost-per-invocation optimization

#### 4. **EBS Volume Analysis**
- Detects unattached volumes
- IOPS utilization for provisioned volumes
- Storage type optimization recommendations
- Snapshot management suggestions

### Network Cost Optimization

#### 1. **NAT Gateway Analysis**
- Monthly cost tracking
- Alternative solutions (NAT instances, VPC endpoints)
- Traffic pattern analysis
- Regional optimization

#### 2. **Data Transfer Costs**
- Cross-AZ transfer monitoring
- Inter-region transfer analysis
- VPC endpoint opportunities
- CloudFront optimization suggestions

#### 3. **Elastic IP Management**
- Unattached EIP detection
- Cost impact calculation
- Automated cleanup recommendations

### Storage Optimization

#### 1. **S3 Request Analysis**
- High request pattern detection
- CloudFront caching opportunities
- Batch operation recommendations
- Storage class optimization

#### 2. **CloudWatch Logs**
- Retention policy analysis
- Log groups without retention
- Excessive retention detection
- Archive to S3 recommendations

### Container Services

#### 1. **ECS/Fargate**
- Fargate Spot opportunities (70% savings)
- Task definition right-sizing
- Savings Plans recommendations

#### 2. **EKS**
- Control plane cost analysis
- Cluster consolidation opportunities
- Namespace isolation strategies

### Service-Specific Analysis

#### 1. **DynamoDB**
- On-demand vs provisioned capacity analysis
- Auto-scaling recommendations
- Backup optimization

#### 2. **ElastiCache**
- Reserved node coverage
- Cluster utilization analysis
- Node type optimization

#### 3. **Redshift**
- Pause/resume opportunities for non-production
- Reserved node recommendations
- Compression analysis

#### 4. **SageMaker**
- Idle notebook detection
- Instance type optimization
- Lifecycle configuration recommendations

## Usage

### Basic Cost Scan
```bash
# Run cost analysis only
PYTHONPATH=/home/ec2-user/aws-sec python -m src.cli scan --services cost

# Combine with other services
PYTHONPATH=/home/ec2-user/aws-sec python -m src.cli scan --services cost,ec2,s3
```

### Generate Enhanced Dashboard
```bash
# Create interactive cost dashboard
PYTHONPATH=/home/ec2-user/aws-sec python -m src.cli scan --services cost --output-format html --output-file cost-dashboard.html
```

### Test Cost Features
```bash
# Run comprehensive cost scanner tests
PYTHONPATH=/home/ec2-user/aws-sec python test_enhanced_cost_scanner.py
```

### Configuration Options

Add to your `aws-security-config.yaml`:

```yaml
services:
  cost:
    enabled: true
    # Cost thresholds
    cost_increase_threshold: 20  # Alert on >20% month-over-month increase
    service_spike_threshold: 50  # Alert on >50% service cost increase
    
    # Coverage thresholds
    ri_coverage_threshold: 70    # Alert when RI coverage <70%
    ri_utilization_threshold: 80 # Alert when RI utilization <80%
    sp_coverage_threshold: 60    # Alert when Savings Plans coverage <60%
    
    # Resource thresholds
    ec2_cpu_low_threshold: 10    # Flag as underutilized when CPU <10%
    ec2_cpu_high_threshold: 90   # Flag as overutilized when CPU >90%
    rds_cpu_threshold: 20        # RDS underutilization threshold
    
    # Cost thresholds
    nat_gateway_cost_threshold: 100  # Alert when NAT Gateway costs >$100/month
    transfer_cost_threshold: 50      # Alert on high data transfer costs
```

## Understanding Findings

### Severity Levels
- **CRITICAL**: Immediate action required (e.g., massive cost spike)
- **HIGH**: Significant savings opportunity (>$100/month)
- **MEDIUM**: Moderate savings opportunity ($10-100/month)
- **LOW**: Minor optimization available (<$10/month)
- **INFO**: Best practice recommendations

### Quick Wins
Look for findings marked as "Quick Wins" - these are easy to implement with immediate savings:
- Unattached EBS volumes
- Idle SageMaker notebooks
- Unattached Elastic IPs
- CloudWatch Logs without retention

### Long-term Optimizations
Some findings require planning but offer substantial savings:
- Reserved Instance purchases
- Spot instance migrations
- Architecture changes for data transfer
- Service consolidation

## Cost Dashboard Features

### Overview Tab
- Monthly spend trends
- Cost distribution by service
- Top optimization opportunities
- Quick wins identification

### Compute Optimization Tab
- EC2 utilization distribution
- Spot instance opportunities
- Lambda optimization insights
- Container service analysis

### Storage & Transfer Tab
- Storage cost breakdown
- Data transfer patterns
- NAT Gateway analysis
- Network optimization opportunities

### Service-Specific Tab
- Database service costs
- Container service analysis
- ML/AI service optimization
- Analytics service recommendations

### Forecast & Trends Tab
- Cost predictions
- Budget vs actual tracking
- Anomaly detection results
- Historical trend analysis

## Best Practices

1. **Regular Scanning**: Run cost analysis weekly to catch issues early
2. **Act on Quick Wins**: Implement easy fixes immediately for instant savings
3. **Plan Major Changes**: Architecture changes need careful planning
4. **Monitor Trends**: Watch for gradual cost increases
5. **Set Budgets**: Use AWS Budgets with actions for automated control
6. **Tag Resources**: Proper tagging enables better cost allocation
7. **Review Regularly**: Cost optimization is an ongoing process

## Troubleshooting

### Common Issues

1. **No Cost Data**: Ensure Cost Explorer is enabled in your account
2. **Permission Errors**: Add required IAM permissions:
   ```json
   {
     "Version": "2012-10-17",
     "Statement": [
       {
         "Effect": "Allow",
         "Action": [
           "ce:GetCostAndUsage",
           "ce:GetCostForecast",
           "ce:GetReservationCoverage",
           "ce:GetReservationUtilization",
           "ce:GetSavingsPlansCoverage",
           "ce:GetAnomalies",
           "cloudwatch:GetMetricStatistics"
         ],
         "Resource": "*"
       }
     ]
   }
   ```

3. **Incomplete Data**: Some metrics require CloudWatch agent for memory/disk data
4. **Forecast Errors**: Forecasting requires at least 14 days of historical data

## Integration with CI/CD

Include cost analysis in your pipeline:

```yaml
# Example GitHub Action
- name: Run AWS Cost Analysis
  run: |
    python -m src.cli scan --services cost --output-format json --output-file cost-report.json
    
- name: Check Cost Threshold
  run: |
    potential_savings=$(jq '.summary.potential_savings' cost-report.json)
    if (( $(echo "$potential_savings > 1000" | bc -l) )); then
      echo "⚠️ High cost optimization potential: $${potential_savings}"
      exit 1
    fi
```

## Conclusion

The enhanced cost analysis features provide comprehensive insights into your AWS spending, helping you:
- Reduce waste and optimize resources
- Plan budgets with accurate forecasting
- Identify quick wins for immediate savings
- Make informed decisions about architecture changes
- Track and control costs proactively

Regular use of these tools can lead to significant cost reductions while maintaining or improving performance and reliability.