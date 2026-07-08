from pydantic import BaseModel, Field
from typing import List, Dict, Any

class Hop(BaseModel):
    """Represents a single 'Received' hop in the email routing path."""
    hop_number: int
    from_server: str = "Unknown"
    by_server: str = "Unknown"
    with_protocol: str = "Unknown"
    timestamp: str = ""
    delay: str = "0s"

class AuthenticationResults(BaseModel):
    """Structured representation of SPF, DKIM, and DMARC results."""
    spf: str = "UNKNOWN"   # Expected: PASS, FAIL, SOFTFAIL, NEUTRAL, NONE, UNKNOWN
    dkim: str = "UNKNOWN"  # Expected: PASS, FAIL, NONE, UNKNOWN
    dmarc: str = "UNKNOWN" # Expected: PASS, FAIL, NONE, UNKNOWN
    raw_details: str = ""

class EmailHeader(BaseModel):
    """Core domain model representing the extracted fields of an email header."""
    subject: str = "No Subject"
    from_address: str = ""
    to_address: str = ""
    date: str = ""
    reply_to: str = ""
    return_path: str = ""
    message_id: str = ""
    mime_version: str = ""
    content_type: str = ""
    user_agent: str = ""
    originating_ip: str = ""
    hops: List[Hop] = Field(default_factory=list)
    auth_results: AuthenticationResults = Field(default_factory=AuthenticationResults)
    raw_headers: Dict[str, Any] = Field(default_factory=dict)
