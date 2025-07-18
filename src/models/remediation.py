from datetime import datetime
from typing import Optional, Dict, Any
from pydantic import BaseModel, Field
import uuid


class RemediationScript(BaseModel):
    script_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    finding_id: str
    script_name: str
    description: str
    script_content: str
    language: str = "python"
    prerequisites: str
    rollback_instructions: Optional[str] = None
    estimated_impact: str
    requires_confirmation: bool = True
    created_at: datetime = Field(default_factory=datetime.utcnow)
    metadata: Dict[str, Any] = Field(default_factory=dict)