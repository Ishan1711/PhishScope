from pydantic import BaseModel, Field
from typing import List, Optional


class Indicator(BaseModel):
    """Represents a specific phishing indicator found in the analysis."""
    name: str          # e.g., "Reply-To Mismatch"
    description: str   # e.g., "The Reply-To address does not match the From address."
    severity: str      # Expected: HIGH, MEDIUM, LOW
    score_contribution: int = 0  # How many points this added to the threat score
    category: str = "General"   # e.g., "Authentication", "Header", "Domain", "URL"


class ScoreItem(BaseModel):
    """A single line item in the threat score breakdown."""
    reason: str        # e.g., "SPF Failed"
    points: int        # e.g., 30
    category: str      # e.g., "Authentication"
    severity: str = "HIGH"  # HIGH, MEDIUM, LOW


class UrlIndicator(BaseModel):
    """Threat assessment for a specific URL found in the email."""
    url: str
    domain: str = ""
    protocol: str = "https"
    risk_level: str = "SAFE"   # SAFE, SUSPICIOUS, HIGH
    reasons: List[str] = Field(default_factory=list)
    is_shortened: bool = False
    is_ip_based: bool = False
    is_encoded: bool = False
    is_homograph: bool = False
    suspicious_tld: bool = False


class IocSummary(BaseModel):
    """High-level summary of all detected Indicators of Compromise."""
    total: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    url_threats: int = 0
    auth_failures: int = 0
    spoofing_detected: bool = False
    domain_suspicious: bool = False


class MitreTechnique(BaseModel):
    """MITRE ATT&CK technique mapping."""
    technique_id: str    # e.g., "T1566.001"
    technique_name: str  # e.g., "Spearphishing Attachment"
    tactic: str          # e.g., "Initial Access"
    description: str = ""
    url: str = ""


class RiskScore(BaseModel):
    """Represents the final calculated risk of the email."""
    threat_score: int = 0         # Scale: 0 to 100
    threat_level: str = "SAFE"    # Expected: SAFE, SUSPICIOUS, HIGHLY SUSPICIOUS
    confidence_score: int = 100   # Scale: 0 to 100 (how confident the analyzer is)
    indicators: List[Indicator] = Field(default_factory=list)
    score_breakdown: List[ScoreItem] = Field(default_factory=list)
    url_indicators: List[UrlIndicator] = Field(default_factory=list)
    ioc_summary: IocSummary = Field(default_factory=IocSummary)
    mitre_techniques: List[MitreTechnique] = Field(default_factory=list)
