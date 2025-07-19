from datetime import datetime
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field
from .finding import Finding, Severity


class ScanResult(BaseModel):
    scan_id: str
    account_id: str
    regions: List[str]
    services_scanned: List[str]
    start_time: datetime
    end_time: Optional[datetime] = None
    findings: List[Finding] = Field(default_factory=list)
    total_resources_scanned: int = 0
    scan_errors: List[Dict[str, Any]] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)
    
    def add_finding(self, finding: Finding):
        """Add a finding to the scan results"""
        self.findings.append(finding)
    
    def get_findings_by_severity(self, severity: Severity) -> List[Finding]:
        """Get all findings of a specific severity"""
        return [f for f in self.findings if f.severity == severity]
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get statistics about the scan"""
        severity_counts = {
            Severity.CRITICAL: 0,
            Severity.HIGH: 0,
            Severity.MEDIUM: 0,
            Severity.LOW: 0,
            Severity.INFO: 0
        }
        
        category_counts = {}
        
        for finding in self.findings:
            severity_counts[finding.severity] += 1
            if finding.category not in category_counts:
                category_counts[finding.category] = 0
            category_counts[finding.category] += 1
        
        return {
            "total_findings": len(self.findings),
            "severity_distribution": severity_counts,
            "category_distribution": category_counts,
            "resources_scanned": self.total_resources_scanned,
            "scan_duration": (self.end_time - self.start_time).total_seconds() if self.end_time else None,
            "errors": len(self.scan_errors)
        }