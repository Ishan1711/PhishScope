from pydantic import BaseModel, Field
from typing import List, Dict, Any, Optional


class Hop(BaseModel):
    """Represents a single 'Received' hop in the email routing path."""
    hop_number: int
    from_server: str = "Unknown"
    by_server: str = "Unknown"
    with_protocol: str = "Unknown"
    timestamp: str = ""
    delay: str = "0s"
    ip_address: str = ""
    is_suspicious: bool = False


class AuthenticationResults(BaseModel):
    """Structured representation of SPF, DKIM, and DMARC results."""
    spf: str = "UNKNOWN"   # Expected: PASS, FAIL, SOFTFAIL, NEUTRAL, NONE, UNKNOWN
    dkim: str = "UNKNOWN"  # Expected: PASS, FAIL, NONE, UNKNOWN
    dmarc: str = "UNKNOWN" # Expected: PASS, FAIL, NONE, UNKNOWN
    raw_details: str = ""
    spf_domain: str = ""
    dkim_domain: str = ""
    dkim_selector: str = ""
    dmarc_policy: str = ""


class EmailHeader(BaseModel):
    """Core domain model representing the extracted fields of an email header."""
    subject: str = "No Subject"
    from_address: str = ""
    display_name: str = ""          # Extracted display name from From header
    from_domain: str = ""           # Extracted sender domain
    to_address: str = ""
    cc_address: str = ""
    date: str = ""
    reply_to: str = ""
    reply_to_domain: str = ""
    return_path: str = ""
    return_path_domain: str = ""
    message_id: str = ""
    mime_version: str = ""
    content_type: str = ""
    user_agent: str = ""            # X-Mailer or User-Agent
    x_mailer: str = ""
    x_spam_status: str = ""
    x_spam_score: str = ""
    originating_ip: str = ""
    ip_is_hidden: bool = False      # True if Gmail/Outlook hides the original IP
    ip_provider: str = ""           # e.g., "Gmail", "Outlook"
    hops: List[Hop] = Field(default_factory=list)
    auth_results: AuthenticationResults = Field(default_factory=AuthenticationResults)
    raw_headers: Dict[str, Any] = Field(default_factory=dict)
    urls_found: List[str] = Field(default_factory=list)   # All URLs found in header values
    header_count: int = 0           # Total number of header fields
    duplicate_headers: List[str] = Field(default_factory=list)  # Headers that appear more than once
