from datetime import datetime
from enum import Enum
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field
import uuid


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class Category(str, Enum):
    IAM = "IAM"
    DATA = "DATA"
    NETWORK = "NETWORK"
    LOGGING = "LOGGING"
    INCIDENT_RESPONSE = "INCIDENT_RESPONSE"
    CONFIGURATION = "CONFIGURATION"
    ENCRYPTION = "ENCRYPTION"
    DATA_PROTECTION = "DATA_PROTECTION"
    ACCESS_CONTROL = "ACCESS_CONTROL"
    COST_OPTIMIZATION = "COST_OPTIMIZATION"
    OPERATIONAL = "OPERATIONAL"
    PATCHING = "PATCHING"


class ComplianceFramework(str, Enum):
    NIST = "NIST"
    OWASP = "OWASP"
    SOX = "SOX"
    CIS = "CIS"
    AWS_WELL_ARCHITECTED = "AWS_WELL_ARCHITECTED"


class Finding(BaseModel):
    finding_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    severity: Severity
    category: Category
    resource_type: str
    resource_id: str
    region: str
    account_id: Optional[str] = None
    title: str
    description: str
    impact: str
    recommendation: str
    compliance_frameworks: List[ComplianceFramework] = Field(default_factory=list)
    automated_remediation_available: bool = False
    remediation_script_id: Optional[str] = None
    detected_at: datetime = Field(default_factory=datetime.utcnow)
    evidence: Dict[str, Any] = Field(default_factory=dict)
    risk_score: int = Field(ge=0, le=100)
    
    def calculate_risk_score(self) -> int:
        """Calculate risk score based on severity and other factors"""
        base_scores = {
            Severity.CRITICAL: 90,
            Severity.HIGH: 70,
            Severity.MEDIUM: 50,
            Severity.LOW: 30,
            Severity.INFO: 10
        }
        
        score = base_scores[self.severity]
        
        # Adjust based on category
        if self.category == Category.IAM:
            score += 10
        elif self.category == Category.DATA:
            score += 5
        
        # Cap at 100
        return min(score, 100)
    
    def __init__(self, **data):
        # Calculate risk score if not provided
        if 'risk_score' not in data:
            # Create a temporary instance to calculate risk score
            temp_data = data.copy()
            temp_data['risk_score'] = 0  # Temporary value
            super().__init__(**temp_data)
            self.risk_score = self.calculate_risk_score()
        else:
            super().__init__(**data)