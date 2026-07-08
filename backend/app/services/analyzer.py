import re
from app.models.header import EmailHeader
from app.models.risk import RiskScore, Indicator

class HeaderAnalyzer:
    """Service to analyze EmailHeader and calculate a Threat Score (0-100)."""
    
    @staticmethod
    def analyze(header: EmailHeader) -> RiskScore:
        score = 0
        indicators = []
        confidence = 100
        
        # 1. Authentication Analysis (SPF, DKIM, DMARC)
        auth = header.auth_results
        
        # SPF
        if auth.spf == "FAIL":
            score += 30
            indicators.append(Indicator(name="SPF Failure", description="The sender IP is not authorized to send emails on behalf of this domain.", severity="HIGH"))
        elif auth.spf == "SOFTFAIL":
            score += 15
            indicators.append(Indicator(name="SPF Softfail", description="The sender IP is likely not authorized to send emails.", severity="MEDIUM"))
        elif auth.spf in ["NONE", "UNKNOWN"] and auth.raw_details:
            score += 10
            indicators.append(Indicator(name="Missing SPF", description="No SPF record found for the sender domain.", severity="MEDIUM"))

        # DKIM
        if auth.dkim == "FAIL":
            score += 30
            indicators.append(Indicator(name="DKIM Failure", description="The cryptographic signature is invalid or missing, implying tampering.", severity="HIGH"))
        elif auth.dkim in ["NONE", "UNKNOWN"] and auth.raw_details:
            score += 15
            indicators.append(Indicator(name="Missing DKIM", description="The email is not cryptographically signed.", severity="MEDIUM"))

        # DMARC
        if auth.dmarc == "FAIL":
            score += 40
            indicators.append(Indicator(name="DMARC Failure", description="The email failed DMARC policy evaluation.", severity="HIGH"))
        elif auth.dmarc in ["NONE", "UNKNOWN"] and auth.raw_details:
            score += 10
            indicators.append(Indicator(name="Missing DMARC", description="No DMARC policy found for the sender domain.", severity="LOW"))

        # 2. Mismatches
        from_domain = HeaderAnalyzer._extract_domain(header.from_address)
        
        if header.reply_to:
            reply_to_domain = HeaderAnalyzer._extract_domain(header.reply_to)
            if reply_to_domain and from_domain and reply_to_domain != from_domain:
                score += 25
                indicators.append(Indicator(name="Reply-To Mismatch", description=f"Replies are routed to {reply_to_domain} instead of {from_domain}.", severity="HIGH"))

        if header.return_path:
            return_path_domain = HeaderAnalyzer._extract_domain(header.return_path)
            if return_path_domain and from_domain and return_path_domain != from_domain:
                score += 25
                indicators.append(Indicator(name="Return-Path Mismatch", description=f"Bounces are routed to {return_path_domain} instead of {from_domain}.", severity="HIGH"))

        # 3. Relay Servers (Hops)
        if len(header.hops) > 4:
            score += 15
            indicators.append(Indicator(name="Too Many Relays", description=f"The email passed through {len(header.hops)} servers, which is unusually high.", severity="MEDIUM"))

        # 4. Message-ID Anomalies
        if not header.message_id:
            score += 20
            indicators.append(Indicator(name="Missing Message-ID", description="The email lacks a Message-ID, a common indicator of spam scripts.", severity="HIGH"))
        elif from_domain and from_domain not in header.message_id:
            score += 10
            indicators.append(Indicator(name="Message-ID Anomaly", description="The Message-ID domain does not match the sender domain.", severity="LOW"))

        # 5. Missing Auth Results Entirely
        if not auth.raw_details:
            score += 20
            indicators.append(Indicator(name="Missing Authentication", description="No Authentication-Results header found. The email bypassed modern security checks.", severity="HIGH"))
            confidence -= 20

        # Calculate final threat level
        threat_score = min(score, 100) # Cap at 100
        
        threat_level = "SAFE"
        if threat_score >= 60:
            threat_level = "HIGHLY SUSPICIOUS"
        elif threat_score >= 30:
            threat_level = "SUSPICIOUS"

        return RiskScore(
            threat_score=threat_score,
            threat_level=threat_level,
            confidence_score=max(confidence, 0),
            indicators=indicators
        )

    @staticmethod
    def _extract_domain(email_str: str) -> str:
        """Extracts the domain part from a string like 'Name <user@domain.com>' or 'user@domain.com'"""
        if not email_str:
            return ""
        # Search for email address between < > or just standalone
        match = re.search(r'[\w\.-]+@([\w\.-]+\.\w+)', email_str)
        if match:
            return match.group(1).lower()
        return ""
