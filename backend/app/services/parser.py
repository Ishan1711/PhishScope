import email
from email.policy import default
import re
from typing import List, Tuple
from app.models.header import EmailHeader, Hop, AuthenticationResults

# Known email provider IP ranges and server signatures that hide originating IPs
GMAIL_PROVIDERS = ['google.com', 'googlemail.com', 'gmail.com']
OUTLOOK_PROVIDERS = ['outlook.com', 'hotmail.com', 'live.com', 'microsoft.com', 'office365.com', 'protection.outlook.com']
YAHOO_PROVIDERS = ['yahoo.com', 'yahoodns.net']
KNOWN_PROVIDERS = GMAIL_PROVIDERS + OUTLOOK_PROVIDERS + YAHOO_PROVIDERS

# URL extraction pattern
URL_PATTERN = re.compile(
    r'https?://[^\s\'"<>{}|\\^`\[\]]+',
    re.IGNORECASE
)


class HeaderParser:
    """Service to parse raw email text or .eml files into structured EmailHeader models."""

    @staticmethod
    def parse_text(raw_text: str) -> EmailHeader:
        """Parses a raw string of email headers."""
        msg = email.message_from_string(raw_text, policy=default)
        return HeaderParser._extract_fields(msg, raw_text)

    @staticmethod
    def parse_file(file_path: str) -> EmailHeader:
        """Parses an .eml or .txt file containing email headers."""
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            msg = email.message_from_file(f, policy=default)
            f.seek(0)
            raw_text = f.read()
        return HeaderParser._extract_fields(msg, raw_text)

    @staticmethod
    def _extract_fields(msg: email.message.EmailMessage, raw_text: str) -> EmailHeader:
        headers_dict = dict(msg.items())

        # --- Single-value headers ---
        subject = msg.get('Subject', 'No Subject')
        from_address = msg.get('From', '')
        to_address = msg.get('To', '')
        cc_address = msg.get('Cc', '')
        date = msg.get('Date', '')
        reply_to = msg.get('Reply-To', '')
        return_path = msg.get('Return-Path', '')
        message_id = msg.get('Message-ID', '')
        mime_version = msg.get('MIME-Version', '')
        content_type = msg.get('Content-Type', '')
        user_agent = msg.get('User-Agent', '') or msg.get('X-Mailer', '')
        x_mailer = msg.get('X-Mailer', '')
        x_spam_status = msg.get('X-Spam-Status', '')
        x_spam_score = msg.get('X-Spam-Score', '')

        # --- Display Name Extraction ---
        display_name = HeaderParser._extract_display_name(str(from_address))
        from_domain = HeaderParser._extract_domain(str(from_address))
        reply_to_domain = HeaderParser._extract_domain(str(reply_to))
        return_path_domain = HeaderParser._extract_domain(str(return_path))

        # --- Originating IP Detection ---
        originating_ip, ip_is_hidden, ip_provider = HeaderParser._detect_originating_ip(msg)

        # --- Routing Hops ---
        hops = HeaderParser._parse_received_hops(msg.get_all('Received', []))

        # --- Authentication Results ---
        auth_results_raw = "\n".join(msg.get_all('Authentication-Results', []))
        # Also check ARC-Authentication-Results
        arc_auth = "\n".join(msg.get_all('ARC-Authentication-Results', []))
        if arc_auth and not auth_results_raw:
            auth_results_raw = arc_auth
        auth_results = HeaderParser._parse_auth_results(auth_results_raw)

        # --- Duplicate Header Detection ---
        all_header_keys = [k for k, v in msg.items()]
        seen = set()
        duplicates = []
        for k in all_header_keys:
            k_lower = k.lower()
            if k_lower in seen and k_lower not in duplicates:
                duplicates.append(k_lower)
            seen.add(k_lower)

        # --- URL Extraction ---
        urls_found = HeaderParser._extract_urls(raw_text)

        # --- Clean fields ---
        def clean_field(field_val) -> str:
            return str(field_val).replace('\n', ' ').replace('\r', '').strip() if field_val else ''

        return EmailHeader(
            subject=clean_field(subject),
            from_address=clean_field(from_address),
            display_name=clean_field(display_name),
            from_domain=from_domain,
            to_address=clean_field(to_address),
            cc_address=clean_field(cc_address),
            date=clean_field(date),
            reply_to=clean_field(reply_to),
            reply_to_domain=reply_to_domain,
            return_path=clean_field(return_path),
            return_path_domain=return_path_domain,
            message_id=clean_field(message_id),
            mime_version=clean_field(mime_version),
            content_type=clean_field(content_type),
            user_agent=clean_field(user_agent),
            x_mailer=clean_field(x_mailer),
            x_spam_status=clean_field(x_spam_status),
            x_spam_score=clean_field(x_spam_score),
            originating_ip=clean_field(originating_ip),
            ip_is_hidden=ip_is_hidden,
            ip_provider=ip_provider,
            hops=hops,
            auth_results=auth_results,
            raw_headers=headers_dict,
            urls_found=urls_found,
            header_count=len(all_header_keys),
            duplicate_headers=duplicates,
        )

    @staticmethod
    def _extract_display_name(from_header: str) -> str:
        """Extracts the display name portion from a From header like 'Name <email@domain.com>'."""
        from_header = from_header.strip()
        # Match 'Display Name <email>' pattern
        match = re.match(r'^"?([^"<>]+?)"?\s*<', from_header)
        if match:
            return match.group(1).strip()
        return ""

    @staticmethod
    def _detect_originating_ip(msg: email.message.EmailMessage) -> Tuple[str, bool, str]:
        """
        Detects the originating IP from headers.
        Returns (ip_address, is_hidden, provider_name).
        """
        # 1. Direct X-Originating-IP header
        originating_ip = msg.get('X-Originating-IP', '')
        if originating_ip:
            return originating_ip.strip(), False, ""

        # 2. X-Forwarded-For
        xff = msg.get('X-Forwarded-For', '')
        if xff:
            ip_candidates = [x.strip() for x in xff.split(',')]
            for ip in ip_candidates:
                if HeaderParser._is_valid_public_ip(ip):
                    return ip, False, ""

        # 3. X-Sender-IP
        x_sender_ip = msg.get('X-Sender-IP', '')
        if x_sender_ip and HeaderParser._is_valid_public_ip(x_sender_ip.strip()):
            return x_sender_ip.strip(), False, ""

        # 4. Parse Received headers for IPs
        received_all = msg.get_all('Received', [])
        if received_all:
            # Try each received header from oldest to newest
            for rec in reversed(received_all):
                rec_text = rec.replace('\n', ' ').replace('\r', '')
                ip_match = re.search(r'\[([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\]', rec_text)
                if ip_match:
                    found_ip = ip_match.group(1)
                    if HeaderParser._is_valid_public_ip(found_ip):
                        return found_ip, False, ""

            # Check if the email comes from a known provider that hides IPs
            last_received = str(received_all[-1]).lower() if received_all else ""
            for provider in GMAIL_PROVIDERS:
                if provider in last_received:
                    return "", True, "Gmail"
            for provider in OUTLOOK_PROVIDERS:
                if provider in last_received:
                    return "", True, "Outlook/Microsoft"
            for provider in YAHOO_PROVIDERS:
                if provider in last_received:
                    return "", True, "Yahoo Mail"

        return "", False, ""

    @staticmethod
    def _is_valid_public_ip(ip: str) -> bool:
        """Returns True if the IP string is a valid, non-reserved IPv4 address."""
        parts = ip.split('.')
        if len(parts) != 4:
            return False
        try:
            nums = [int(p) for p in parts]
        except ValueError:
            return False
        if any(n < 0 or n > 255 for n in nums):
            return False
        # Exclude private/loopback/reserved ranges
        if nums[0] == 10:
            return False
        if nums[0] == 127:
            return False
        if nums[0] == 172 and 16 <= nums[1] <= 31:
            return False
        if nums[0] == 192 and nums[1] == 168:
            return False
        if nums[0] == 0:
            return False
        return True

    @staticmethod
    def _extract_urls(raw_text: str) -> List[str]:
        """Extracts all URLs from the raw email text."""
        urls = URL_PATTERN.findall(raw_text)
        # Deduplicate while preserving order
        seen = set()
        unique_urls = []
        for url in urls:
            # Clean trailing punctuation that might have been captured
            url = url.rstrip('.,;:)')
            if url not in seen:
                seen.add(url)
                unique_urls.append(url)
        return unique_urls[:50]  # Cap at 50 URLs

    @staticmethod
    def _parse_received_hops(received_list: List[str]) -> List[Hop]:
        """Parses 'Received' headers into an ordered list of Hops."""
        hops = []
        hop_num = len(received_list)

        # Email Received headers are in reverse chronological order
        for rec in received_list:
            rec = rec.replace('\n', ' ').replace('\r', '')

            from_match = re.search(r'from\s+([^\s\[]+)', rec, re.IGNORECASE)
            by_match = re.search(r'by\s+([^\s\[]+)', rec, re.IGNORECASE)
            with_match = re.search(r'with\s+([^\s;]+)', rec, re.IGNORECASE)
            ip_match = re.search(r'\[([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\]', rec)

            parts = rec.split(';')
            timestamp = parts[-1].strip() if len(parts) > 1 else ""

            from_server = from_match.group(1) if from_match else "Unknown"
            by_server = by_match.group(1) if by_match else "Unknown"
            ip_address = ip_match.group(1) if ip_match else ""

            # Flag suspicious hops: no 'by' server, using IP directly as from server
            is_suspicious = (
                not by_server or by_server == "Unknown" or
                bool(re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', from_server))
            )

            hops.append(Hop(
                hop_number=hop_num,
                from_server=from_server,
                by_server=by_server,
                with_protocol=with_match.group(1) if with_match else "SMTP",
                timestamp=timestamp,
                ip_address=ip_address,
                is_suspicious=is_suspicious,
            ))
            hop_num -= 1

        hops.reverse()  # Order from oldest (hop 1) to newest (hop N)
        return hops

    @staticmethod
    def _parse_auth_results(auth_header: str) -> AuthenticationResults:
        """Parses Authentication-Results for SPF, DKIM, and DMARC."""
        auth_header_lower = auth_header.lower()

        spf = "UNKNOWN"
        if "spf=pass" in auth_header_lower: spf = "PASS"
        elif "spf=fail" in auth_header_lower: spf = "FAIL"
        elif "spf=softfail" in auth_header_lower: spf = "SOFTFAIL"
        elif "spf=none" in auth_header_lower: spf = "NONE"
        elif "spf=neutral" in auth_header_lower: spf = "NEUTRAL"
        elif "spf=temperror" in auth_header_lower: spf = "TEMPERROR"

        dkim = "UNKNOWN"
        if "dkim=pass" in auth_header_lower: dkim = "PASS"
        elif "dkim=fail" in auth_header_lower: dkim = "FAIL"
        elif "dkim=none" in auth_header_lower: dkim = "NONE"
        elif "dkim=temperror" in auth_header_lower: dkim = "TEMPERROR"
        elif "dkim=neutral" in auth_header_lower: dkim = "NEUTRAL"

        dmarc = "UNKNOWN"
        if "dmarc=pass" in auth_header_lower: dmarc = "PASS"
        elif "dmarc=fail" in auth_header_lower: dmarc = "FAIL"
        elif "dmarc=none" in auth_header_lower: dmarc = "NONE"
        elif "dmarc=bestguesspass" in auth_header_lower: dmarc = "PASS"

        # Extract additional details
        spf_domain_match = re.search(r'spf=\w+\s+(?:\([^)]+\)\s+)?smtp\.(?:mailfrom|helo)=([^\s;]+)', auth_header, re.IGNORECASE)
        spf_domain = spf_domain_match.group(1) if spf_domain_match else ""

        dkim_domain_match = re.search(r'dkim=\w+.*?header\.d=([^\s;]+)', auth_header, re.IGNORECASE)
        dkim_domain = dkim_domain_match.group(1) if dkim_domain_match else ""

        dkim_selector_match = re.search(r'header\.s=([^\s;]+)', auth_header, re.IGNORECASE)
        dkim_selector = dkim_selector_match.group(1) if dkim_selector_match else ""

        dmarc_policy_match = re.search(r'dmarc=\w+.*?(?:policy|p)=([^\s;,]+)', auth_header, re.IGNORECASE)
        dmarc_policy = dmarc_policy_match.group(1) if dmarc_policy_match else ""

        return AuthenticationResults(
            spf=spf,
            dkim=dkim,
            dmarc=dmarc,
            raw_details=auth_header.strip(),
            spf_domain=spf_domain,
            dkim_domain=dkim_domain,
            dkim_selector=dkim_selector,
            dmarc_policy=dmarc_policy,
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
