import email
from email.policy import default
import re
from typing import List
from app.models.header import EmailHeader, Hop, AuthenticationResults

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
        
        # Extract single-value headers
        subject = msg.get('Subject', 'No Subject')
        from_address = msg.get('From', '')
        to_address = msg.get('To', '')
        date = msg.get('Date', '')
        reply_to = msg.get('Reply-To', '')
        return_path = msg.get('Return-Path', '')
        message_id = msg.get('Message-ID', '')
        mime_version = msg.get('MIME-Version', '')
        content_type = msg.get('Content-Type', '')
        user_agent = msg.get('User-Agent', '') or msg.get('X-Mailer', '')
        
        # Originating IP
        originating_ip = msg.get('X-Originating-IP', '')
        if not originating_ip:
            # Fallback: Try to find an IP in the earliest Received header
            received_all = msg.get_all('Received', [])
            if received_all:
                earliest_received = received_all[-1]
                ip_match = re.search(r'\[([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\]', earliest_received)
                if ip_match:
                    originating_ip = ip_match.group(1)

        hops = HeaderParser._parse_received_hops(msg.get_all('Received', []))
        
        # Get Authentication-Results. Some emails might have multiple, we join them.
        auth_results_raw = "\n".join(msg.get_all('Authentication-Results', []))
        auth_results = HeaderParser._parse_auth_results(auth_results_raw)
        
        # Clean up string fields (strip newlines which might occur in folded headers)
        def clean_field(field_val: str) -> str:
            return str(field_val).replace('\n', ' ').replace('\r', '').strip()

        return EmailHeader(
            subject=clean_field(subject),
            from_address=clean_field(from_address),
            to_address=clean_field(to_address),
            date=clean_field(date),
            reply_to=clean_field(reply_to),
            return_path=clean_field(return_path),
            message_id=clean_field(message_id),
            mime_version=clean_field(mime_version),
            content_type=clean_field(content_type),
            user_agent=clean_field(user_agent),
            originating_ip=clean_field(originating_ip),
            hops=hops,
            auth_results=auth_results,
            raw_headers=headers_dict
        )

    @staticmethod
    def _parse_received_hops(received_list: List[str]) -> List[Hop]:
        """Parses 'Received' headers into an ordered list of Hops."""
        hops = []
        hop_num = len(received_list)
        # Email Received headers are in reverse chronological order
        for rec in received_list:
            rec = rec.replace('\n', ' ').replace('\r', '')
            
            from_match = re.search(r'from\s+([^\s]+)', rec, re.IGNORECASE)
            by_match = re.search(r'by\s+([^\s]+)', rec, re.IGNORECASE)
            with_match = re.search(r'with\s+([^\s;]+)', rec, re.IGNORECASE)
            
            parts = rec.split(';')
            timestamp = parts[-1].strip() if len(parts) > 1 else ""
            
            hops.append(Hop(
                hop_number=hop_num,
                from_server=from_match.group(1) if from_match else "Unknown",
                by_server=by_match.group(1) if by_match else "Unknown",
                with_protocol=with_match.group(1) if with_match else "Unknown",
                timestamp=timestamp
            ))
            hop_num -= 1
            
        hops.reverse() # Order from oldest (hop 1) to newest (hop N)
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
        
        dkim = "UNKNOWN"
        if "dkim=pass" in auth_header_lower: dkim = "PASS"
        elif "dkim=fail" in auth_header_lower: dkim = "FAIL"
        elif "dkim=none" in auth_header_lower: dkim = "NONE"
        
        dmarc = "UNKNOWN"
        if "dmarc=pass" in auth_header_lower: dmarc = "PASS"
        elif "dmarc=fail" in auth_header_lower: dmarc = "FAIL"
        elif "dmarc=none" in auth_header_lower: dmarc = "NONE"
        
        return AuthenticationResults(
            spf=spf,
            dkim=dkim,
            dmarc=dmarc,
            raw_details=auth_header.strip()
        )
