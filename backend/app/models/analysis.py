import uuid
from datetime import datetime, timezone
from pydantic import BaseModel, Field
from typing import Optional
from app.models.header import EmailHeader
from app.models.risk import RiskScore

def generate_investigation_id() -> str:
    """Generates a unique Investigation ID, e.g., INV-A1B2C3D4"""
    return f"INV-{uuid.uuid4().hex[:8].upper()}"

def get_current_timestamp() -> str:
    """Returns ISO 8601 UTC timestamp string."""
    return datetime.now(timezone.utc).isoformat()

class AnalysisResult(BaseModel):
    """The final payload returned to the frontend representing the complete investigation."""
    investigation_id: str = Field(default_factory=generate_investigation_id)
    analysis_time: str = Field(default_factory=get_current_timestamp)
    header_data: EmailHeader
    risk_assessment: RiskScore
    ai_explanation: Optional[str] = None
