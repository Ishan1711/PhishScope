import re
import unicodedata
from app.models.header import EmailHeader
from app.models.risk import RiskScore, Indicator, ScoreItem, UrlIndicator, IocSummary, MitreTechnique

# URL shortener domains
URL_SHORTENERS = {
    'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd', 'buff.ly',
    'adf.ly', 'tiny.cc', 'lnkd.in', 'db.tt', 'qr.ae', 'po.st', 'bc.vc',
    'u.to', 'j.mp', 'buzurl.com', 'cutt.us', 'u.bb', 'yourls.org',
    'x.co', 'prettylinkpro.com', 'viralurl.com', 'clk.im', 'vzturl.com',
    'short.io', 'rebrand.ly', 'cli.gs', 'ff.im', 'tr.im', 'twit.ac',
    'su.pr', 'mcaf.ee', 'click.ly'
}

# Suspicious TLDs
SUSPICIOUS_TLDS = {
    '.xyz', '.top', '.tk', '.site', '.icu', '.pw', '.cc', '.ga',
    '.ml', '.cf', '.gq', '.click', '.link', '.win', '.loan', '.racing',
    '.download', '.review', '.science', '.party', '.bid', '.trade',
    '.accountant', '.stream', '.webcam', '.faith', '.date', '.men'
}

# Brands commonly spoofed (display name check)
SPOOFABLE_BRANDS = {
    'paypal': 'paypal.com',
    'microsoft': 'microsoft.com',
    'apple': 'apple.com',
    'amazon': 'amazon.com',
    'google': 'google.com',
    'facebook': 'facebook.com',
    'instagram': 'instagram.com',
    'netflix': 'netflix.com',
    'bank': None,  # Many banks — just flag
    'chase': 'chase.com',
    'wellsfargo': 'wellsfargo.com',
    'citibank': 'citibank.com',
    'barclays': 'barclays.com',
    'hsbc': 'hsbc.com',
    'linkedin': 'linkedin.com',
    'twitter': 'twitter.com',
    'dropbox': 'dropbox.com',
    'docusign': 'docusign.com',
    'fedex': 'fedex.com',
    'ups': 'ups.com',
    'dhl': 'dhl.com',
    'irs': 'irs.gov',
    'gov': None,
}

# MITRE ATT&CK mappings for email-based techniques
MITRE_PHISHING = MitreTechnique(
    technique_id="T1566.001",
    technique_name="Spearphishing Attachment",
    tactic="Initial Access",
    description="Adversaries may send spearphishing emails with a malicious attachment.",
    url="https://attack.mitre.org/techniques/T1566/001/"
)
MITRE_LINK_PHISHING = MitreTechnique(
    technique_id="T1566.002",
    technique_name="Spearphishing Link",
    tactic="Initial Access",
    description="Adversaries may send spearphishing emails with a malicious link.",
    url="https://attack.mitre.org/techniques/T1566/002/"
)
MITRE_SPOOFING = MitreTechnique(
    technique_id="T1036.005",
    technique_name="Match Legitimate Name or Location",
    tactic="Defense Evasion",
    description="Adversaries may match or approximate the name or location of legitimate email senders.",
    url="https://attack.mitre.org/techniques/T1036/005/"
)
MITRE_MASQUERADING = MitreTechnique(
    technique_id="T1036",
    technique_name="Masquerading",
    tactic="Defense Evasion",
    description="Adversaries may attempt to manipulate features of their artifacts to make them appear legitimate.",
    url="https://attack.mitre.org/techniques/T1036/"
)
MITRE_HIDE_INFRA = MitreTechnique(
    technique_id="T1665",
    technique_name="Hide Infrastructure",
    tactic="Command and Control",
    description="Adversaries may manipulate network infrastructure to hide the true origin.",
    url="https://attack.mitre.org/techniques/T1665/"
)


class HeaderAnalyzer:
    """Service to analyze EmailHeader and calculate a Threat Score (0-100)."""

    @staticmethod
    def analyze(header: EmailHeader) -> RiskScore:
        score = 0
        indicators: list[Indicator] = []
        score_breakdown: list[ScoreItem] = []
        url_indicators: list[UrlIndicator] = []
        mitre_techniques: list[MitreTechnique] = []
        confidence = 100

        auth = header.auth_results
        from_domain = header.from_domain or HeaderAnalyzer._extract_domain(header.from_address)

        # ==============================================================
        # 1. AUTHENTICATION ANALYSIS (SPF, DKIM, DMARC)
        # ==============================================================

        # SPF
        if auth.spf == "FAIL":
            pts = 30
            score += pts
            indicators.append(Indicator(
                name="SPF Failure",
                description="The sender IP is not authorized to send emails on behalf of this domain. This is a strong indicator of spoofing.",
                severity="HIGH", score_contribution=pts, category="Authentication"
            ))
            score_breakdown.append(ScoreItem(reason="SPF Failure — sender IP not authorized", points=pts, category="Authentication", severity="HIGH"))
            if MITRE_SPOOFING not in mitre_techniques:
                mitre_techniques.append(MITRE_SPOOFING)
        elif auth.spf == "SOFTFAIL":
            pts = 15
            score += pts
            indicators.append(Indicator(
                name="SPF Softfail",
                description="The sender IP is likely not authorized. The domain owner suspects the message may be spam but is not certain.",
                severity="MEDIUM", score_contribution=pts, category="Authentication"
            ))
            score_breakdown.append(ScoreItem(reason="SPF Softfail — probable unauthorized sender", points=pts, category="Authentication", severity="MEDIUM"))
        elif auth.spf in ["NONE", "UNKNOWN"] and auth.raw_details:
            pts = 10
            score += pts
            indicators.append(Indicator(
                name="Missing SPF Record",
                description="No SPF record found for the sender domain, making it impossible to verify the sender's legitimacy.",
                severity="MEDIUM", score_contribution=pts, category="Authentication"
            ))
            score_breakdown.append(ScoreItem(reason="No SPF record found for sender domain", points=pts, category="Authentication", severity="MEDIUM"))

        # DKIM
        if auth.dkim == "FAIL":
            pts = 30
            score += pts
            indicators.append(Indicator(
                name="DKIM Signature Failure",
                description="The cryptographic email signature is invalid or was tampered with in transit. This indicates the email may have been altered.",
                severity="HIGH", score_contribution=pts, category="Authentication"
            ))
            score_breakdown.append(ScoreItem(reason="DKIM invalid/tampered signature", points=pts, category="Authentication", severity="HIGH"))
        elif auth.dkim in ["NONE", "UNKNOWN"] and auth.raw_details:
            pts = 15
            score += pts
            indicators.append(Indicator(
                name="Missing DKIM Signature",
                description="The email is not cryptographically signed. Legitimate senders typically sign their emails.",
                severity="MEDIUM", score_contribution=pts, category="Authentication"
            ))
            score_breakdown.append(ScoreItem(reason="Email lacks DKIM cryptographic signature", points=pts, category="Authentication", severity="MEDIUM"))

        # DMARC
        if auth.dmarc == "FAIL":
            pts = 40
            score += pts
            indicators.append(Indicator(
                name="DMARC Policy Failure",
                description="The email failed the domain's DMARC policy evaluation. This is the strongest authentication signal of impersonation.",
                severity="HIGH", score_contribution=pts, category="Authentication"
            ))
            score_breakdown.append(ScoreItem(reason="DMARC policy evaluation failed", points=pts, category="Authentication", severity="HIGH"))
            if MITRE_SPOOFING not in mitre_techniques:
                mitre_techniques.append(MITRE_SPOOFING)
        elif auth.dmarc in ["NONE", "UNKNOWN"] and auth.raw_details:
            pts = 10
            score += pts
            indicators.append(Indicator(
                name="No DMARC Policy",
                description="The sender domain has no DMARC policy, offering no protection against spoofing of this domain.",
                severity="LOW", score_contribution=pts, category="Authentication"
            ))
            score_breakdown.append(ScoreItem(reason="Sender domain has no DMARC policy", points=pts, category="Authentication", severity="LOW"))

        # Missing Authentication Results entirely
        if not auth.raw_details:
            pts = 20
            score += pts
            indicators.append(Indicator(
                name="No Authentication Headers",
                description="No Authentication-Results header found. The email bypassed modern email security checks entirely.",
                severity="HIGH", score_contribution=pts, category="Authentication"
            ))
            score_breakdown.append(ScoreItem(reason="No authentication results header present", points=pts, category="Authentication", severity="HIGH"))
            confidence -= 20

        # ==============================================================
        # 2. HEADER MISMATCH ANALYSIS
        # ==============================================================

        # Reply-To mismatch
        reply_to_domain = header.reply_to_domain or HeaderAnalyzer._extract_domain(header.reply_to)
        if header.reply_to and reply_to_domain and from_domain and reply_to_domain != from_domain:
            pts = 25
            score += pts
            indicators.append(Indicator(
                name="Reply-To Domain Mismatch",
                description=f"Replies are redirected to '{reply_to_domain}' instead of '{from_domain}'. This is a classic phishing tactic to intercept responses.",
                severity="HIGH", score_contribution=pts, category="Header"
            ))
            score_breakdown.append(ScoreItem(reason=f"Reply-To routes to {reply_to_domain} (≠ {from_domain})", points=pts, category="Header", severity="HIGH"))
            mitre_techniques.append(MITRE_MASQUERADING)

        # Return-Path mismatch
        return_path_domain = header.return_path_domain or HeaderAnalyzer._extract_domain(header.return_path)
        if header.return_path and return_path_domain and from_domain and return_path_domain != from_domain:
            pts = 20
            score += pts
            indicators.append(Indicator(
                name="Return-Path Domain Mismatch",
                description=f"Bounce messages are routed to '{return_path_domain}' instead of '{from_domain}'. This suggests the sending infrastructure is separate from the claimed domain.",
                severity="HIGH", score_contribution=pts, category="Header"
            ))
            score_breakdown.append(ScoreItem(reason=f"Return-Path routes to {return_path_domain} (≠ {from_domain})", points=pts, category="Header", severity="HIGH"))

        # ==============================================================
        # 3. DISPLAY NAME SPOOFING
        # ==============================================================

        display_name_lower = header.display_name.lower() if header.display_name else ""
        from_lower = header.from_address.lower() if header.from_address else ""

        if from_domain:
            for brand, expected_domain in SPOOFABLE_BRANDS.items():
                brand_in_name = brand in display_name_lower or brand in from_lower
                if brand_in_name:
                    domain_ok = (expected_domain is None) or (expected_domain in from_domain)
                    if not domain_ok:
                        pts = 35
                        score += pts
                        indicators.append(Indicator(
                            name="Display Name Spoofing",
                            description=f"The sender claims to be '{header.display_name or brand.title()}' but sends from '{from_domain}', which is not the legitimate {brand.title()} domain.",
                            severity="HIGH", score_contribution=pts, category="Spoofing"
                        ))
                        score_breakdown.append(ScoreItem(reason=f"Display name '{brand.title()}' spoofed from {from_domain}", points=pts, category="Spoofing", severity="HIGH"))
                        mitre_techniques.append(MITRE_SPOOFING)
                        if MITRE_MASQUERADING not in mitre_techniques:
                            mitre_techniques.append(MITRE_MASQUERADING)
                        break

        # ==============================================================
        # 4. DOMAIN ANALYSIS
        # ==============================================================

        if from_domain:
            # Punycode / Homograph Attack
            if from_domain.startswith("xn--"):
                pts = 30
                score += pts
                indicators.append(Indicator(
                    name="Punycode / Homograph Domain",
                    description=f"The sender domain '{from_domain}' uses Punycode encoding, a technique used in homograph attacks to impersonate legitimate domains with lookalike characters.",
                    severity="HIGH", score_contribution=pts, category="Domain"
                ))
                score_breakdown.append(ScoreItem(reason="Punycode/homograph domain detected", points=pts, category="Domain", severity="HIGH"))

            # Unicode characters in domain
            try:
                decoded_domain = from_domain.encode('ascii').decode('ascii')
            except (UnicodeEncodeError, UnicodeDecodeError):
                pts = 25
                score += pts
                indicators.append(Indicator(
                    name="Unicode Domain Attack",
                    description="The sender domain contains non-ASCII Unicode characters, which can be used to create visually identical lookalike domains.",
                    severity="HIGH", score_contribution=pts, category="Domain"
                ))
                score_breakdown.append(ScoreItem(reason="Unicode characters found in sender domain", points=pts, category="Domain", severity="HIGH"))

            # Suspicious TLD
            if any(from_domain.endswith(tld) for tld in SUSPICIOUS_TLDS):
                pts = 15
                score += pts
                matched_tld = next(tld for tld in SUSPICIOUS_TLDS if from_domain.endswith(tld))
                indicators.append(Indicator(
                    name="Suspicious Top-Level Domain",
                    description=f"The sender domain uses the '{matched_tld}' TLD, which is frequently associated with spam, phishing, and malicious campaigns.",
                    severity="MEDIUM", score_contribution=pts, category="Domain"
                ))
                score_breakdown.append(ScoreItem(reason=f"Suspicious TLD ({matched_tld}) on sender domain", points=pts, category="Domain", severity="MEDIUM"))

            # Look-alike domain detection (common substitutions)
            lookalike_patterns = [
                (r'paypa1\.', 'paypal'), (r'rn(?:icrosoft|ail)', 'microsoft'),
                (r'g[0o]0?gle', 'google'), (r'arnazon', 'amazon'),
                (r'rnicros[o0]ft', 'microsoft'), (r'app1e', 'apple'),
                (r'netf1ix', 'netflix'), (r'fac[e3]b[o0]{2}k', 'facebook'),
            ]
            for pattern, brand in lookalike_patterns:
                if re.search(pattern, from_domain, re.IGNORECASE):
                    pts = 40
                    score += pts
                    indicators.append(Indicator(
                        name="Look-alike Domain Detected",
                        description=f"The sender domain '{from_domain}' appears to be a typosquatted version of '{brand}.com', designed to deceive recipients.",
                        severity="HIGH", score_contribution=pts, category="Domain"
                    ))
                    score_breakdown.append(ScoreItem(reason=f"Lookalike/typosquatted domain of {brand}", points=pts, category="Domain", severity="HIGH"))
                    break

        # ==============================================================
        # 5. MESSAGE-ID ANOMALIES
        # ==============================================================

        if not header.message_id:
            pts = 20
            score += pts
            indicators.append(Indicator(
                name="Missing Message-ID",
                description="The email has no Message-ID header. Legitimate mail servers always generate this unique identifier.",
                severity="HIGH", score_contribution=pts, category="Header"
            ))
            score_breakdown.append(ScoreItem(reason="Missing Message-ID header", points=pts, category="Header", severity="HIGH"))
        elif from_domain and from_domain not in header.message_id.lower():
            pts = 10
            score += pts
            indicators.append(Indicator(
                name="Message-ID Domain Mismatch",
                description=f"The Message-ID domain does not match the sender domain '{from_domain}', suggesting it was generated by a different mail infrastructure.",
                severity="LOW", score_contribution=pts, category="Header"
            ))
            score_breakdown.append(ScoreItem(reason="Message-ID domain differs from sender domain", points=pts, category="Header", severity="LOW"))

        # ==============================================================
        # 6. ROUTING & HOP ANALYSIS
        # ==============================================================

        if len(header.hops) > 5:
            pts = 15
            score += pts
            indicators.append(Indicator(
                name="Excessive Email Hops",
                description=f"The email passed through {len(header.hops)} mail servers, which is unusually high and may indicate deliberate routing through anonymizing infrastructure.",
                severity="MEDIUM", score_contribution=pts, category="Routing"
            ))
            score_breakdown.append(ScoreItem(reason=f"Email routed through {len(header.hops)} hops (excessive)", points=pts, category="Routing", severity="MEDIUM"))

        # Suspicious HELO/EHLO — from server is an IP address directly
        for hop in header.hops:
            if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', hop.from_server):
                pts = 15
                score += pts
                indicators.append(Indicator(
                    name="Suspicious HELO/EHLO (IP Address)",
                    description=f"A mail server introduced itself using a raw IP address ({hop.from_server}) in the HELO/EHLO command instead of a hostname, which is atypical of legitimate servers.",
                    severity="MEDIUM", score_contribution=pts, category="Routing"
                ))
                score_breakdown.append(ScoreItem(reason=f"Server HELO'd with IP ({hop.from_server}) instead of hostname", points=pts, category="Routing", severity="MEDIUM"))
                break

        # ==============================================================
        # 7. HEADER STRUCTURAL ANOMALIES
        # ==============================================================

        # Duplicate headers
        if header.duplicate_headers:
            pts = 20
            score += pts
            dup_list = ', '.join(header.duplicate_headers[:5])
            indicators.append(Indicator(
                name="Duplicate Email Headers",
                description=f"The following headers appear more than once: [{dup_list}]. Duplicate headers are a sign of header injection attacks or malformed emails.",
                severity="HIGH", score_contribution=pts, category="Header"
            ))
            score_breakdown.append(ScoreItem(reason=f"Duplicate headers found: {dup_list}", points=pts, category="Header", severity="HIGH"))

        # Missing subject
        if not header.subject or header.subject == 'No Subject':
            pts = 10
            score += pts
            indicators.append(Indicator(
                name="Missing Subject Line",
                description="The email has no subject line. Legitimate business emails almost always include a subject.",
                severity="LOW", score_contribution=pts, category="Header"
            ))
            score_breakdown.append(ScoreItem(reason="Missing or empty subject line", points=pts, category="Header", severity="LOW"))

        # Suspicious MIME content type
        suspicious_mime = ['application/x-msdownload', 'application/x-executable', 'application/x-dosexec']
        ct_lower = header.content_type.lower() if header.content_type else ""
        if any(m in ct_lower for m in suspicious_mime):
            pts = 25
            score += pts
            indicators.append(Indicator(
                name="Suspicious MIME Type",
                description=f"The email Content-Type ({header.content_type[:80]}) indicates executable content, which is extremely high risk.",
                severity="HIGH", score_contribution=pts, category="Header"
            ))
            score_breakdown.append(ScoreItem(reason="Executable MIME type in email headers", points=pts, category="Header", severity="HIGH"))

        # Header injection check (newlines in field values)
        suspicious_fields = {
            'From': header.from_address,
            'Subject': header.subject,
            'Reply-To': header.reply_to,
        }
        for field_name, field_val in suspicious_fields.items():
            if field_val and ('\n' in field_val or '\r' in field_val or '%0a' in field_val.lower() or '%0d' in field_val.lower()):
                pts = 30
                score += pts
                indicators.append(Indicator(
                    name="Header Injection Detected",
                    description=f"The '{field_name}' header contains newline characters, a technique used in header injection attacks to forge additional headers.",
                    severity="HIGH", score_contribution=pts, category="Header"
                ))
                score_breakdown.append(ScoreItem(reason=f"Header injection in {field_name} field", points=pts, category="Header", severity="HIGH"))
                break

        # ==============================================================
        # 8. URL ANALYSIS
        # ==============================================================

        for url in header.urls_found[:20]:  # Analyze up to 20 URLs
            ui = HeaderAnalyzer._analyze_url(url)
            url_indicators.append(ui)
            if ui.risk_level in ("SUSPICIOUS", "HIGH") and len(indicators) < 20:
                pts = 10 if ui.risk_level == "SUSPICIOUS" else 15
                score += pts
                reasons_str = "; ".join(ui.reasons[:2])
                indicators.append(Indicator(
                    name=f"Suspicious URL: {ui.domain or url[:40]}",
                    description=f"URL risk detected: {reasons_str}.",
                    severity="MEDIUM" if ui.risk_level == "SUSPICIOUS" else "HIGH",
                    score_contribution=pts,
                    category="URL"
                ))
                score_breakdown.append(ScoreItem(
                    reason=f"Suspicious URL: {reasons_str[:60]}",
                    points=pts,
                    category="URL",
                    severity="MEDIUM" if ui.risk_level == "SUSPICIOUS" else "HIGH"
                ))
                if MITRE_LINK_PHISHING not in mitre_techniques:
                    mitre_techniques.append(MITRE_LINK_PHISHING)

        # Add phishing MITRE if score is high
        if score >= 50 and MITRE_PHISHING not in mitre_techniques:
            mitre_techniques.append(MITRE_PHISHING)

        # ==============================================================
        # 9. CALCULATE FINAL RISK
        # ==============================================================

        threat_score = min(score, 100)

        threat_level = "SAFE"
        if threat_score >= 60:
            threat_level = "HIGHLY SUSPICIOUS"
        elif threat_score >= 30:
            threat_level = "SUSPICIOUS"

        # Reduce confidence if we lack auth data
        if not auth.raw_details:
            confidence = max(confidence - 20, 40)

        # Build IOC Summary
        high_count = sum(1 for i in indicators if i.severity == "HIGH")
        medium_count = sum(1 for i in indicators if i.severity == "MEDIUM")
        low_count = sum(1 for i in indicators if i.severity == "LOW")
        url_threats = sum(1 for u in url_indicators if u.risk_level in ("SUSPICIOUS", "HIGH"))
        auth_failures = sum(1 for i in indicators if i.category == "Authentication" and i.severity == "HIGH")
        spoofing = any(i.category == "Spoofing" for i in indicators)
        domain_suspicious = any(i.category == "Domain" and i.severity in ("HIGH", "MEDIUM") for i in indicators)

        ioc_summary = IocSummary(
            total=len(indicators),
            high_count=high_count,
            medium_count=medium_count,
            low_count=low_count,
            url_threats=url_threats,
            auth_failures=auth_failures,
            spoofing_detected=spoofing,
            domain_suspicious=domain_suspicious,
        )

        return RiskScore(
            threat_score=threat_score,
            threat_level=threat_level,
            confidence_score=max(confidence, 0),
            indicators=indicators,
            score_breakdown=score_breakdown,
            url_indicators=url_indicators,
            ioc_summary=ioc_summary,
            mitre_techniques=mitre_techniques,
        )

    @staticmethod
    def _analyze_url(url: str) -> UrlIndicator:
        """Analyzes a single URL for threat indicators."""
        reasons = []
        risk_level = "SAFE"
        is_shortened = False
        is_ip_based = False
        is_encoded = False
        is_homograph = False
        suspicious_tld = False

        # Extract domain
        domain_match = re.match(r'https?://([^/\?#:]+)', url, re.IGNORECASE)
        domain = domain_match.group(1).lower() if domain_match else ""
        protocol = "https" if url.lower().startswith("https") else "http"

        # Remove port
        domain_clean = domain.split(':')[0]

        # 1. URL shortener
        if any(domain_clean == s or domain_clean.endswith('.' + s) for s in URL_SHORTENERS):
            is_shortened = True
            reasons.append("URL shortener service detected")
            risk_level = "SUSPICIOUS"

        # 2. IP-based URL
        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', domain_clean):
            is_ip_based = True
            reasons.append("URL uses raw IP address instead of domain")
            risk_level = "HIGH"

        # 3. URL encoding / obfuscation
        if '%' in url and re.search(r'%[0-9a-fA-F]{2}', url):
            encoded_count = len(re.findall(r'%[0-9a-fA-F]{2}', url))
            if encoded_count > 3:
                is_encoded = True
                reasons.append(f"URL heavily encoded ({encoded_count} encoded characters)")
                risk_level = "SUSPICIOUS"

        # 4. Punycode / homograph domain
        if domain_clean.startswith('xn--'):
            is_homograph = True
            reasons.append("Punycode/homograph domain in URL")
            risk_level = "HIGH"

        # 5. Suspicious TLD in URL
        if any(domain_clean.endswith(tld) for tld in SUSPICIOUS_TLDS):
            suspicious_tld = True
            matched_tld = next(tld for tld in SUSPICIOUS_TLDS if domain_clean.endswith(tld))
            reasons.append(f"Suspicious TLD ({matched_tld}) in URL")
            if risk_level == "SAFE":
                risk_level = "SUSPICIOUS"

        # 6. Excessive subdomains
        parts = domain_clean.split('.')
        if len(parts) > 4:
            reasons.append(f"Excessive subdomains ({len(parts)-2} levels)")
            if risk_level == "SAFE":
                risk_level = "SUSPICIOUS"

        # 7. Non-HTTPS
        if protocol == "http":
            reasons.append("URL uses insecure HTTP protocol")
            if risk_level == "SAFE":
                risk_level = "SUSPICIOUS"

        return UrlIndicator(
            url=url[:200],
            domain=domain_clean,
            protocol=protocol,
            risk_level=risk_level,
            reasons=reasons,
            is_shortened=is_shortened,
            is_ip_based=is_ip_based,
            is_encoded=is_encoded,
            is_homograph=is_homograph,
            suspicious_tld=suspicious_tld,
        )

    @staticmethod
    def _extract_domain(email_str: str) -> str:
        """Extracts the domain part from a string like 'Name <user@domain.com>' or 'user@domain.com'"""
        if not email_str:
            return ""
        match = re.search(r'[\w\.-]+@([\w\.-]+\.\w+)', email_str)
        if match:
            return match.group(1).lower()
        return ""
