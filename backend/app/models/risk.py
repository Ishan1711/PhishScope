from pydantic import BaseModel, Field
from typing import List

class Indicator(BaseModel):
    """Represents a specific phishing indicator found in the analysis."""
    name: str          # e.g., "Reply-To Mismatch"
    description: str   # e.g., "The Reply-To address does not match the From address."
    severity: str      # Expected: HIGH, MEDIUM, LOW

class RiskScore(BaseModel):
    """Represents the final calculated risk of the email."""
    threat_score: int = 0         # Scale: 0 to 100
    threat_level: str = "SAFE"    # Expected: SAFE, SUSPICIOUS, HIGHLY SUSPICIOUS
    confidence_score: int = 100   # Scale: 0 to 100 (how confident the analyzer is)
    indicators: List[Indicator] = Field(default_factory=list)
