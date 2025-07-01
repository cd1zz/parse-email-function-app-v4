#!/usr/bin/env python3
"""
Email Content Parser using Python's standard email library
Much more robust and simpler than manual regex parsing

KEY FEATURE: Binary format detection runs BEFORE MIME type filtering,
so .msg and TNEF files are detected even when mislabeled as 
'application/octet-stream' or other generic types.

NEW FEATURE: Extracts IP addresses, domains, and URLs from all text content
FIXED: Prevents HTML leakage into plain_text output through centralized cleaning
"""

import json
import argparse
import tempfile
import os
import re
import ipaddress
import html
from .html_cleaner import PhishingEmailHtmlCleaner as Cleaner
from pathlib import Path
from typing import List, Dict, Any, Iterator, Optional, Set, Tuple
import base64
import logging
import string
import unicodedata

import tldextract  # type: ignore

# Standard library email imports
from email import policy
from email.parser import BytesParser
from email.message import EmailMessage

# URL processing utilities
from .url.processor import UrlProcessor
from .pdf_utils import extract_text_from_pdf

logger = logging.getLogger(__name__)

class EmailParser:
    """Parser using standard library email package with artifact extraction and HTML leak prevention"""
    
    # Image MIME types to skip
    IMAGE_MIME_TYPES = {
        'image/jpeg', 'image/jpg', 'image/png', 'image/gif', 
        'image/bmp', 'image/svg+xml', 'image/webp', 'image/tiff',
        'image/x-icon', 'image/vnd.microsoft.icon'
    }
    
    # Email MIME types that should be recursively parsed
    EMAIL_MIME_TYPES = {
        'message/rfc822',
        'application/vnd.ms-outlook',
        'application/x-ms-outlook',
        'application/ms-outlook',
        'application/ms-tnef',
        'message/partial',
        'message/external-body'
    }
    
    # Binary email format signatures
    OLE_SIGNATURE = b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1"     # .msg / CFBF
    TNEF_SIGNATURE = b"\x78\x9F\x3E\x22"                     # winmail.dat (TNEF)
    
    # Regex patterns for artifact extraction (permissive)
    URL_PATTERN = re.compile(
        r"(?i)\b(?:(?:https?|ftp|ftps|sftp|file|mailto|tel|sms)://|(?:www\d{0,3}\.))"
        r"[^\s<>\"'{}|\\^`\[\]]+",
        re.IGNORECASE,
    )

    # Detect scheme prefixes for URLs
    URL_SCHEME_PREFIX = re.compile(r'^[a-z][a-z0-9+.-]*://', re.IGNORECASE)

    # Common file extensions that should not be treated as TLDs
    COMMON_FILE_EXTENSIONS = {
        'pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'txt', 'csv', 'xml',
        'json', 'zip', 'rar', '7z', 'gz', 'tar', 'jpg', 'jpeg', 'png', 'gif',
        'bmp', 'svg', 'webp', 'tiff', 'eml', 'msg', 'dat', 'html', 'htm', 'php',
        'js', 'css', 'exe', 'dll', 'bin', 'bat', 'sh'
    }
    
    IP_PATTERN = re.compile(
        r'(?:\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b)'
        r'|'
        r'(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}'
    )
    
    DOMAIN_PATTERN = re.compile(
        r'\b(?:'
        r'(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)*'      # Subdomains
        r'[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?'             # Domain
        r'\.(?:com|org|net|edu|gov|mil|int|info|biz|name|museum|coop|aero|[a-z]{2,})'  # TLD
        r')\b'
        , re.IGNORECASE
    )

    def _has_valid_tld(self, domain: str) -> bool:
        """Check if the domain has a recognized TLD"""
        if not domain or '.' not in domain:
            return False
        tld = domain.rsplit('.', 1)[-1].lower()
        if tld in self.COMMON_FILE_EXTENSIONS:
            return False
        if self.tld_extractor:
            try:
                ext = self.tld_extractor(domain)
                return bool(ext.suffix)
            except Exception:
                return False
        # Fallback: basic alphabetic TLD check
        return bool(re.fullmatch(r'[a-z]{2,}', tld))
    
    def __init__(self, max_depth: int = 10, include_raw: bool = False,
                 include_images: bool = False,
                 include_large_images: bool = False,
                 parent_text_content: list = None):
        """Initialize parser configuration.

        Parameters
        ----------
        max_depth: int
            Maximum recursion depth when parsing nested content.
        include_raw: bool
            Whether to include raw base64 content for forensic analysis.
        include_images: bool
            When ``True`` image parts will have their bytes extracted.
            If ``False`` only metadata is recorded.
        include_large_images: bool
            Include image content even when it exceeds the default size
            threshold.
        parent_text_content: list | None
            Shared list used when recursively parsing nested messages.
        """

        self.max_depth = max_depth
        self.include_raw = include_raw
        self.include_images = include_images
        self.include_large_images = include_large_images
        self.parent_text_content = parent_text_content
        if tldextract:
            self.tld_extractor = tldextract.TLDExtract(suffix_list_urls=None)
        else:
            self.tld_extractor = None
        self.reset()
    
    def reset(self):
        """Reset parser state"""
        self.raw_content = b''
        self.content_blocks = []
        self.current_depth = 0
        self.statistics = {}
        # Use parent's list if provided, otherwise create new
        self.all_text_content = self.parent_text_content if self.parent_text_content is not None else []

    
    def parse_file(self, file_path: str, forensics_mode: bool = False) -> Dict[str, Any]:
        """Parse an email file"""
        file_path = Path(file_path)
        
        if not file_path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")
        
        with open(file_path, 'rb') as f:
            content = f.read()

        return self.parse(content, file_path.name, forensics_mode=forensics_mode)
    
    def parse(
        self,
        raw_content: bytes,
        source_name: str = "email",
        depth: int = 0,
        forensics_mode: bool = False,
    ) -> Dict[str, Any]:
        """Parse email content using std-lib email module."""
        self.reset()
        self.current_depth = depth
        self.raw_content = raw_content  # Keep for statistics
        
        # Check depth limit
        if depth > self.max_depth:
            return {
                'source': source_name,
                'error': f'Maximum depth ({self.max_depth}) exceeded',
                'depth': depth
            }
        
        try:
            # Parse email using standard library
            msg: EmailMessage = BytesParser(policy=policy.default).parsebytes(raw_content)
            
            # Walk the message tree and collect content blocks
            self.content_blocks = list(self._walk_message(msg, depth))

            # Build and return output (includes artifact extraction)
            return self._build_output(source_name, msg, forensics_mode)
            
        except Exception as e:
            return {
                'source': source_name,
                'error': f'Email parsing failed: {str(e)}',
                'depth': depth,
                'size': len(raw_content)
            }
    
    def _normalize_whitespace(self, text: str) -> str:
        """Collapse excessive whitespace and blank lines."""
        if not text:
            return ""

        text = text.replace('\r\n', '\n').replace('\r', '\n')
        lines = [re.sub(r'[ \t]+', ' ', line.strip()) for line in text.split('\n')]

        cleaned_lines: list[str] = []
        blank = False
        for line in lines:
            if line:
                cleaned_lines.append(line)
                blank = False
            else:
                if not blank:
                    cleaned_lines.append('')
                    blank = True
        return '\n'.join(cleaned_lines).strip()

    def _contains_html_tags(self, text: str) -> bool:
        """Check if text contains HTML tags, ignoring angle-bracketed URLs."""
        if not text:
            return False
        # Remove patterns like <http://example.com> which are not HTML tags
        sanitized = re.sub(r'<https?://[^>]+>', '', text, flags=re.IGNORECASE)
        return bool(re.search(r'<[^>]+>', sanitized))

    def _fallback_html_clean(self, text: str) -> str:
        """Fallback HTML cleaning when html2text fails."""
        if not text:
            return ""
            
        # Remove script/style tags completely
        text = re.sub(r'<script[^>]*>.*?</script>', '', text, flags=re.DOTALL | re.IGNORECASE)
        text = re.sub(r'<style[^>]*>.*?</style>', '', text, flags=re.DOTALL | re.IGNORECASE)
        
        # Extract URLs before removing tags so artifact extraction can capture
        # them even if the href attribute is stripped during cleaning
        url_pattern = r'href\s*=\s*["\']([^"\']+)["\']'
        urls = re.findall(url_pattern, text, re.IGNORECASE)
        
        # Remove all HTML tags
        text = re.sub(r'<[^>]+>', ' ', text)
        
        # Decode HTML entities
        text = html.unescape(text)
        
        # Clean whitespace
        text = re.sub(r'\s+', ' ', text).strip()
        
        # Previously the extracted URLs were appended to the cleaned text in an
        # "Extracted URLs" section. This polluted the plain text output and
        # duplicated data already available via the dedicated artifacts field.
        # The URLs are still returned separately by the artifact extraction
        # routines, so we no longer include them here.

        text = Cleaner._remove_invisible_chars_aggressive(text)
        text = unicodedata.normalize("NFKC", text)
        text = Cleaner._replace_problematic_unicode_chars(text)
        text = Cleaner._normalize_whitespace(text)
        return text

    def _clean_html(self, text: str) -> str:
        """Extract plain text from HTML with robust error handling."""
        if not text or not text.strip():
            return ""
            
        try:
            cleaned = Cleaner.clean_html(text, aggressive_cleaning=True)
            
            # Validation: ensure no HTML tags remain
            if self._contains_html_tags(cleaned):
                logger.warning("HTML tags detected in cleaned text, applying fallback cleaning")
                cleaned = self._fallback_html_clean(text)
                
            return cleaned
            
        except Exception as e:
            logger.error(f"HTML cleaning failed: {e}, applying fallback")
            return self._fallback_html_clean(text)

    def _is_likely_html_content(self, text: str, declared_mime_type: str) -> bool:
        """Detect if content is likely HTML regardless of declared MIME type."""
        if not text:
            return False
            
        # Check for common HTML patterns
        html_indicators = [
            r'<html\b[^>]*>',
            r'<head\b[^>]*>',
            r'<body\b[^>]*>',
            r'<div\b[^>]*>',
            r'<p\b[^>]*>',
            r'<a\b[^>]*href=',
            r'<img\b[^>]*src=',
            r'<script\b[^>]*>',
            r'<style\b[^>]*>',
            r'<!DOCTYPE\s+html'
        ]
        
        text_sample = text[:1000].lower()  # Check first 1KB
        html_matches = sum(1 for pattern in html_indicators if re.search(pattern, text_sample))
        
        # If we find multiple HTML indicators, treat as HTML regardless of MIME type
        return html_matches >= 2
    
    def _extract_artifacts_from_text(self, text: str) -> Dict[str, Set[str]]:
        """Extract URLs, IPs, and domains from text content"""
        if not text or len(text.strip()) < 3:
            return {'urls': set(), 'ips': set(), 'domains': set()}

        urls = set()
        domains = set()

        # Extract URLs from href/src attributes before stripping HTML
        attr_pattern = r'(?i)(?:href|src)\s*=\s*[\'"\']([^\'"\']+)[\'"\']'
        for attr_url in re.findall(attr_pattern, text):
            cleaned = attr_url.strip().strip('.,;:!?<>')
            if len(cleaned) > 3 and '.' in cleaned:
                if self.URL_SCHEME_PREFIX.match(cleaned) or '/' in cleaned or '?' in cleaned or '#' in cleaned:
                    urls.add(cleaned.lower())
                elif self.DOMAIN_PATTERN.fullmatch(cleaned) and self._has_valid_tld(cleaned):
                    domains.add(cleaned.lower())
                else:
                    urls.add(cleaned.lower())

        # Extract URLs that may be wrapped in angle brackets before HTML cleaning
        for match in self.URL_PATTERN.finditer(text):
            raw_val = match.group().strip('.,;:!?<>')
            if len(raw_val) > 3 and '.' in raw_val:
                if self.URL_SCHEME_PREFIX.match(raw_val) or '/' in raw_val or '?' in raw_val or '#' in raw_val:
                    urls.add(raw_val.lower())
                elif self.DOMAIN_PATTERN.fullmatch(raw_val) and self._has_valid_tld(raw_val):
                    domains.add(raw_val.lower())
                else:
                    urls.add(raw_val.lower())

        # Clean HTML for further text extraction
        clean_text = self._clean_html(text)

        # Extract URLs from plain text after cleaning
        for match in self.URL_PATTERN.finditer(clean_text):
            url = match.group().strip('.,;:!?<>')
            if len(url) > 3 and '.' in url:
                if self.URL_SCHEME_PREFIX.match(url) or '/' in url or '?' in url or '#' in url:
                    urls.add(url.lower())
                elif self.DOMAIN_PATTERN.fullmatch(url) and self._has_valid_tld(url):
                    domains.add(url.lower())
                else:
                    urls.add(url.lower())
        
        # Extract IP addresses using permissive candidate search
        ips = set()
        ip_candidates = re.findall(r'[0-9a-fA-F:.]{3,}', clean_text)
        for cand in ip_candidates:
            cand = cand.strip("[]()<>\"' ,;")
            if '.' not in cand and ':' not in cand:
                continue
            if len(cand) > 45:
                continue
            try:
                ip_obj = ipaddress.ip_address(cand)
                ips.add(str(ip_obj))
            except ValueError:
                continue
        
        # Extract domains
        for match in self.DOMAIN_PATTERN.finditer(clean_text):
            domain = match.group().lower().strip('.,;:!?')
            # Basic validation
            if (len(domain) > 3 and
                domain.count('.') >= 1 and
                not domain.startswith('.') and
                not domain.endswith('.') and
                self._has_valid_tld(domain)):
                domains.add(domain)
        
        # Remove domains that are already captured in URLs
        filtered_domains = set()
        for domain in domains:
            # Check if this domain appears in any URL
            domain_in_url = any(domain in url for url in urls)
            if not domain_in_url:
                filtered_domains.add(domain)
        
        return {
            'urls': urls,
            'ips': ips, 
            'domains': filtered_domains
        }
    
    def _collect_text_content(self, content_block: Dict[str, Any]) -> None:
        """Enhanced text collection with better HTML detection and cleaning."""
        block_type = content_block.get('type', '')
        content = content_block.get('content', '')
        encoding = content_block.get('encoding')
        mime_type = content_block.get('mime_type', '')

        logger.debug(
            f"_collect_text_content: type={block_type}, encoding={encoding}, "
            f"content_length={len(str(content))}, mime_type={mime_type}"
        )

        # Handle PDF extraction first
        pdf_added = False
        if (block_type == 'mime_part' and mime_type == 'application/pdf'):
            pdf_text = content_block.get('pdf_text')
            if isinstance(pdf_text, str) and pdf_text.strip():
                logger.debug("  Collecting text from PDF attachment")
                self.all_text_content.append({
                    'text': pdf_text,
                    'source': f"pdf_{content_block.get('filename', 'attachment')}",
                    'block_type': 'pdf_attachment',
                })
                pdf_added = True

        # Skip if no usable content (but still recurse)
        if (not content or encoding == 'base64') and not pdf_added:
            logger.debug(f"  Skipping text collection: empty={not content}, base64={encoding == 'base64'}")
            self._recurse_nested_content(content_block)
            return
        
        # Process based on block type with enhanced HTML detection
        if block_type == 'email_headers':
            self._collect_header_text(content_block)
        elif block_type in ['email_body', 'mime_part']:
            self._collect_body_text_enhanced(content_block, content, mime_type)
        elif block_type == 'tnef_container':
            self._collect_tnef_text(content_block)
        
        # Always recurse into nested content
        self._recurse_nested_content(content_block)

    def _collect_header_text(self, content_block: Dict[str, Any]) -> None:
        """Extract text from email headers."""
        headers = content_block.get('headers', {})
        for header_name, header_value in headers.items():
            if isinstance(header_value, str) and header_value:
                self.all_text_content.append({
                    'text': header_value,
                    'source': f"header_{header_name.lower()}",
                    'block_type': 'email_headers'
                })

    def _collect_body_text_enhanced(self, content_block: Dict[str, Any], 
                                   content: str, mime_type: str) -> None:
        """Enhanced body text collection with html2text cleaning."""
        if not isinstance(content, str) or not content.strip():
            return
            
        logger.debug(f"Processing {mime_type} content ({len(content)} chars)")
        
        # ENHANCED: Check if content is actually HTML regardless of MIME type
        is_html_content = (
            mime_type == 'text/html' or 
            self._is_likely_html_content(content, mime_type)
        )
        
        if is_html_content:
            logger.debug(f"Processing as HTML content (declared: {mime_type})")
            text_to_add = self._clean_html(content)
            source_suffix = "html_cleaned"
        else:
            logger.debug(f"Processing as plain text content")
            text_to_add = Cleaner._remove_invisible_chars_aggressive(content)
            text_to_add = unicodedata.normalize("NFKC", text_to_add)
            text_to_add = Cleaner._replace_problematic_unicode_chars(text_to_add)
            text_to_add = Cleaner._normalize_whitespace(text_to_add)
            source_suffix = mime_type or 'plain'

        if text_to_add.strip():
            self.all_text_content.append({
                'text': text_to_add,
                'source': f"{content_block['type']}_{source_suffix}",
                'block_type': content_block['type']
            })
            logger.debug(f"Added text ({len(text_to_add)} chars), total blocks: {len(self.all_text_content)}")

    def _collect_tnef_text(self, content_block: Dict[str, Any]) -> None:
        """Extract text from TNEF attachments."""
        attachments = content_block.get('attachments', [])
        for i, attachment in enumerate(attachments):
            att_content = attachment.get('content', '')
            if isinstance(att_content, str) and att_content.strip():
                # Only process if not base64 encoded
                if attachment.get('encoding') != 'base64':
                    self.all_text_content.append({
                        'text': att_content,
                        'source': f"tnef_attachment_{i}",
                        'block_type': 'tnef_container'
                    })

    def _recurse_nested_content(self, content_block: Dict[str, Any]) -> None:
        """Recursively process nested content."""
        nested_content = content_block.get('nested_content')
        if nested_content and isinstance(nested_content, dict):
            nested_blocks = nested_content.get('content', [])
            if isinstance(nested_blocks, list):
                for nested_block in nested_blocks:
                    self._collect_text_content(nested_block)

    def _build_plain_text_from_cleaned_collection(self) -> str:
        """Build plain text from the same cleaned text collection used for artifacts.
        
        This ensures consistency and prevents HTML leakage.
        """
        plain_text_parts = []
        processed_sources = set()
        
        # Process cleaned text blocks (same as artifact extraction)
        for text_block in self.all_text_content:
            text = text_block['text']
            source = text_block['source']
            block_type = text_block['block_type']
            
            # Avoid duplicating content from the same source
            if source in processed_sources:
                continue
                
            if text and text.strip():
                # Skip header fields that are too technical for plain text
                if block_type == 'email_headers' and source.startswith('header_'):
                    header_name = source.replace('header_', '')
                    if header_name.lower() in ['subject', 'from', 'to', 'date']:
                        plain_text_parts.append(f"{header_name.title()}: {text}")
                else:
                    plain_text_parts.append(text)
                    
                processed_sources.add(source)
        
        # Combine and normalize
        combined_text = "\n\n".join(plain_text_parts)
        return self._normalize_whitespace(combined_text)

    def _parse_msg_file(self, payload: bytes, depth: int, part_id: str) -> dict:
        """Parse MSG file using extract_msg library"""
        try:
            import extract_msg
            
            # Create a temporary file to store the MSG data
            with tempfile.NamedTemporaryFile(suffix='.msg', delete=False) as tmp_file:
                tmp_file.write(payload)
                tmp_file_path = tmp_file.name
            
            try:
                # Parse the MSG file from the temporary file
                msg_obj = extract_msg.Message(tmp_file_path)
                
                # Extract the RFC822 representation
                # Note: extract_msg doesn't have as_bytes(), we need to construct RFC822 manually
                rfc822_content = self._msg_to_rfc822(msg_obj)
                
                # Parse the converted content recursively
                nested_parser = EmailParser(
                    max_depth=self.max_depth,
                    include_raw=self.include_raw,
                    include_images=self.include_images,
                    include_large_images=self.include_large_images,
                    parent_text_content=self.all_text_content
                )
                nested_result = nested_parser.parse(
                    rfc822_content, 
                    f"nested_msg_{part_id}", 
                    depth + 1
                )
                
                return {
                    'type': 'nested_msg',
                    'detected_format': 'outlook_msg',
                    'size': len(payload),
                    'converted_size': len(rfc822_content),
                    'nested_content': nested_result,
                    'depth': depth,
                    'msg_metadata': {
                        'subject': getattr(msg_obj, 'subject', ''),
                        'sender': getattr(msg_obj, 'sender', ''),
                        'to': getattr(msg_obj, 'to', ''),
                        'date': str(getattr(msg_obj, 'date', '')),
                        'message_id': getattr(msg_obj, 'messageId', ''),
                    }
                }
                
            finally:
                # Clean up the temporary file
                try:
                    os.unlink(tmp_file_path)
                except:
                    pass
                    
        except Exception as e:
                return {
                    'type': 'binary_msg',
                    'detected_format': 'outlook_msg',
                    'size': len(payload),
                    'error': str(e),
                    'encoding': 'base64',
                    'depth': depth
                }

    def _msg_to_rfc822(self, msg_obj) -> bytes:
        """Convert extract_msg Message object to RFC822 format."""
        try:
            lines = []
            
            logger.debug("=== MSG to RFC822 Conversion Debug ===")
            
            # Check and log the body content
            if hasattr(msg_obj, 'body') and msg_obj.body:
                body_preview = msg_obj.body[:500] if isinstance(msg_obj.body, str) else str(msg_obj.body)[:500]
                logger.debug(f"MSG text body found ({len(str(msg_obj.body))} chars)")
                logger.debug(f"Text body preview: {body_preview}")
            else:
                logger.debug("No text body found in MSG")
                
            # Check and log the HTML body content  
            if hasattr(msg_obj, 'htmlBody') and msg_obj.htmlBody:
                html_preview = msg_obj.htmlBody[:500] if isinstance(msg_obj.htmlBody, str) else str(msg_obj.htmlBody)[:500]
                logger.debug(f"MSG HTML body found ({len(str(msg_obj.htmlBody))} chars)")
                logger.debug(f"HTML body preview: {html_preview}")
            else:
                logger.debug("No HTML body found in MSG")
                
            logger.debug("=== End MSG Debug ===")
    
            # Add headers
            if hasattr(msg_obj, 'subject') and msg_obj.subject:
                subj = msg_obj.subject
                if isinstance(subj, bytes):
                    subj = self._to_str(subj, None)[0]
                lines.append(f"Subject: {subj}")
    
            if hasattr(msg_obj, 'sender') and msg_obj.sender:
                sender = msg_obj.sender
                if isinstance(sender, bytes):
                    sender = self._to_str(sender, None)[0]
                lines.append(f"From: {sender}")
    
            if hasattr(msg_obj, 'to') and msg_obj.to:
                to_addr = msg_obj.to
                if isinstance(to_addr, bytes):
                    to_addr = self._to_str(to_addr, None)[0]
                lines.append(f"To: {to_addr}")
    
            if hasattr(msg_obj, 'date') and msg_obj.date:
                date_val = msg_obj.date
                if isinstance(date_val, bytes):
                    date_val = self._to_str(date_val, None)[0]
                lines.append(f"Date: {date_val}")
    
            if hasattr(msg_obj, 'messageId') and msg_obj.messageId:
                mid = msg_obj.messageId
                if isinstance(mid, bytes):
                    mid = self._to_str(mid, None)[0]
                lines.append(f"Message-ID: {mid}")
    
            has_html = hasattr(msg_obj, 'htmlBody') and msg_obj.htmlBody
            has_text = hasattr(msg_obj, 'body') and msg_obj.body
    
            html_body = msg_obj.htmlBody if has_html else None
            if isinstance(html_body, bytes):
                html_body = self._to_str(html_body, None)[0]
            text_body = msg_obj.body if has_text else None
            if isinstance(text_body, bytes):
                text_body = self._to_str(text_body, None)[0]
    
            if has_html and has_text:
                boundary = 'msg_to_rfc822_boundary'
                lines.append(f"Content-Type: multipart/alternative; boundary=\"{boundary}\"")
                lines.append('MIME-Version: 1.0')
                lines.append('')
    
                lines.append(f"--{boundary}")
                lines.append('Content-Type: text/plain; charset=utf-8')
                lines.append('Content-Transfer-Encoding: 8bit')
                lines.append('')
                lines.append(text_body or '')
                lines.append('')
    
                lines.append(f"--{boundary}")
                lines.append('Content-Type: text/html; charset=utf-8')
                lines.append('Content-Transfer-Encoding: 8bit')
                lines.append('')
                lines.append(html_body or '')
                lines.append('')
                lines.append(f"--{boundary}--")
            elif has_html:
                lines.append('Content-Type: text/html; charset=utf-8')
                lines.append('Content-Transfer-Encoding: 8bit')
                lines.append('')
                lines.append(html_body or '')
            elif has_text:
                lines.append('Content-Type: text/plain; charset=utf-8')
                lines.append('Content-Transfer-Encoding: 8bit')
                lines.append('')
                lines.append(text_body or '')
            else:
                lines.append('Content-Type: text/plain; charset=utf-8')
                lines.append('')
                lines.append('[No body content found]')
    
            rfc822_content = '\r\n'.join(lines)
            return rfc822_content.encode('utf-8')
    
        except Exception as e:
            fallback_content = f"Subject: [MSG Parse Error: {e}]\r\n\r\n[Could not convert MSG to RFC822 format]"
            return fallback_content.encode('utf-8')
    
    def _walk_message(self, msg: EmailMessage, depth: int) -> Iterator[Dict[str, Any]]:
        """Yield dictionaries describing each part, recurse on nested emails."""
        
        # Collect all headers for this message/part
        headers = dict(msg.items())
        
        # Always yield headers
        header_block = {
            'type': 'email_headers',
            'headers': headers,
            'depth': depth,
            'message_id': headers.get('Message-ID', ''),
            'subject': headers.get('Subject', ''),
            'from': headers.get('From', ''),
            'to': headers.get('To', ''),
            'date': headers.get('Date', '')
        }
        
        # Collect text content for artifact extraction
        self._collect_text_content(header_block)
        yield header_block
        
        # Handle multipart messages
        if msg.is_multipart():
            logger.debug(f"{'  ' * depth}Processing multipart message: {msg.get_content_type()}")

            for i, part in enumerate(msg.iter_parts()):
                content_type = part.get_content_type().lower()

                logger.debug(f"{'  ' * depth}  Part {i}: {content_type}")

                # Recurse into any multipart container
                if hasattr(part, 'is_multipart') and part.is_multipart():
                    logger.debug(f"{'  ' * depth}    Recursing into multipart part: {content_type}")
                    for sub_block in self._walk_message(part, depth + 1):
                        yield sub_block
                    continue

                # Decode payload first for all processing
                payload = part.get_payload(decode=True) or b''
                
                # 1️⃣ Check for binary email formats FIRST (before MIME type filtering)
                binary_kind = self._detect_binary_email(payload)
                
                if binary_kind == "msg":
                    logger.debug(f"{'  ' * depth}    Detected .msg file by signature ({len(payload):,} bytes)")
                    result = self._parse_msg_file(payload, depth, str(id(part)))
                    result['mime_type'] = content_type
                    result['declared_type'] = content_type
                    result['filename'] = part.get_filename()
                    
                    # Collect text content for artifact extraction
                    self._collect_text_content(result)
                    yield result
                    continue
                
                elif binary_kind == "tnef":
                    logger.debug(f"{'  ' * depth}    Detected TNEF file by signature ({len(payload):,} bytes)")
                    try:
                        from tnefparse import TNEF
                        tnef_obj = TNEF(payload)
                        
                        # Extract attachment information
                        attachments = []
                        for attachment in tnef_obj.attachments:
                            att_info = {
                                'filename': attachment.name,
                                'size': len(attachment.data),
                                'long_filename': getattr(attachment, 'long_filename', None),
                                'created': str(getattr(attachment, 'created', None)),
                                'modified': str(getattr(attachment, 'modified', None))
                            }
                            
                            # Include small attachments, skip large ones
                            if len(attachment.data) < 100000:  # 100KB limit
                                att_info['encoding'] = self._determine_encoding(attachment.data)
                            else:
                                att_info['note'] = 'Content skipped due to size'
                            
                            attachments.append(att_info)
                        
                        tnef_block = {
                            'type': 'tnef_container',
                            'mime_type': content_type,
                            'declared_type': content_type,
                            'detected_format': 'tnef_winmail',
                            'size': len(payload),
                            'filename': part.get_filename(),
                            'attachment_count': len(attachments),
                            'attachments': attachments,
                            'depth': depth
                        }
                        
                        # Collect text content for artifact extraction
                        self._collect_text_content(tnef_block)
                        yield tnef_block
                        
                    except Exception as e:
                        logger.error(f"{'  ' * depth}        Error parsing TNEF file: {e}")
                        result = {
                            'type': 'binary_tnef',
                            'mime_type': content_type,
                            'declared_type': content_type,
                            'detected_format': 'tnef_winmail',
                            'size': len(payload),
                            'filename': part.get_filename(),
                            'error': str(e),
                            'encoding': 'base64',
                            'depth': depth
                        }
                        self._collect_text_content(result)
                        yield result
                    continue
                
                # 2️⃣ Handle image parts (after binary detection)
                if self._is_image_mime_type(content_type):
                    logger.debug(f"{'  ' * depth}    Processing image part ({len(payload):,} bytes)")

                    is_large = len(payload) >= 10000
                    block_type = 'large_image_part' if is_large else 'image_part'
                    block = {
                        'type': block_type,
                        'mime_type': content_type,
                        'filename': part.get_filename(),
                        'size': len(payload),
                        'depth': depth
                    }

                    # Binary image data should never be stored in JSON output.
                    note = 'Image extraction disabled'
                    if self.include_images and is_large and not self.include_large_images:
                        note = 'Content skipped due to size'
                    block['note'] = note
                    block['encoding'] = 'base64'

                    yield block
                    continue
                
                # 3️⃣ Handle nested email messages (RFC822, etc.)
                if content_type in self.EMAIL_MIME_TYPES:
                    logger.debug(f"{'  ' * depth}    Processing nested email/message format")
                    
                    try:
                        # For message/rfc822, the payload might already be an EmailMessage
                        if content_type == 'message/rfc822':
                            nested_msg = part.get_payload()[0] if part.get_payload() else None
                            if isinstance(nested_msg, EmailMessage):

                                # Recursively walk the nested message
                                # IMPORTANT: Pass parent's text content list to share collection
                                nested_parser = EmailParser(
                                    max_depth=self.max_depth,
                                    include_raw=self.include_raw,
                                    include_images=self.include_images,
                                    include_large_images=self.include_large_images,
                                    parent_text_content=self.all_text_content  # Share the text collection!
                                )

                                # Process the nested message content
                                nested_content = list(nested_parser._walk_message(nested_msg, depth + 1))

                                result = {
                                    'type': 'nested_email',
                                    'mime_type': content_type,
                                    'nested_content': {
                                        'source': f"nested_email_{id(part)}",
                                        'content': nested_content,
                                        'depth': depth + 1
                                    },
                                    'depth': depth
                                }
                                self._collect_text_content(result)
                                yield result
                                continue
                        
                        # Fallback: parse raw bytes as email
                        if payload:
                            nested_parser = EmailParser(
                                max_depth=self.max_depth,
                                include_raw=self.include_raw,
                                include_images=self.include_images,
                                include_large_images=self.include_large_images,
                                parent_text_content=self.all_text_content  # Pass the parent's list
                            )
                            nested_result = nested_parser.parse(
                                payload,
                                source_name=f"nested_email_{id(part)}",
                                depth=depth + 1
                            )
                            result = {
                                'type': 'nested_email',
                                'mime_type': content_type,
                                'nested_content': nested_result,
                                'depth': depth
                            }
                            self._collect_text_content(result)
                            yield result
                        
                    except Exception as e:
                        logger.error(f"{'  ' * depth}    Error parsing nested email: {e}")
                        yield {
                            'type': 'nested_email_error',
                            'mime_type': content_type,
                            'error': str(e),
                            'depth': depth
                        }
                    continue
                
                # 4️⃣ Handle regular MIME parts (everything else)
                try:
                    # Get additional metadata
                    disposition = part.get_content_disposition() or ''
                    filename = part.get_filename()
                    charset = part.get_content_charset()

                    logger.debug(f"{'  ' * depth}    Processing {content_type} part ({len(payload):,} bytes)")

                    # Use improved charset handling
                    text, encoding = self._to_str(payload, charset)

                    pdf_text = None
                    if content_type.lower() == 'application/pdf':
                        pdf_text = extract_text_from_pdf(payload)

                    mime_part_data = {
                        'type': 'mime_part',
                        'mime_type': content_type,
                        'disposition': disposition,
                        'filename': filename,
                        'charset': charset,
                        'size': len(payload),
                        'encoding': encoding,
                        'headers': dict(part.items()),
                        'depth': depth
                    }

                    # Store extracted text only when it's actually text.
                    if encoding != 'base64':
                        mime_part_data['content'] = text
                        
                        # ENHANCED: Always check for HTML content regardless of declared type
                        is_html = (
                            content_type == 'text/html' or 
                            self._is_likely_html_content(text, content_type)
                        )
                        
                        if is_html:
                            try:
                                mime_part_data['text_only'] = self._clean_html(text)
                                logger.debug(f"Created text_only for {content_type} content")
                            except Exception as e:
                                logger.error(f"Failed to create text_only for {content_type}: {e}")
                                # Set a fallback cleaned version
                                mime_part_data['text_only'] = self._fallback_html_clean(text)

                    if pdf_text:
                        mime_part_data['pdf_text'] = pdf_text
                    
                    # Collect text content for artifact extraction
                    self._collect_text_content(mime_part_data)
                    yield mime_part_data
                    
                except Exception as e:
                    logger.error(f"{'  ' * depth}    Error processing part: {e}")
                    yield {
                        'type': 'mime_part_error',
                        'mime_type': content_type,
                        'error': str(e),
                        'depth': depth
                    }
        
        # Handle single-part messages
        else:
            logger.debug(f"{'  ' * depth}Processing single-part message: {msg.get_content_type()}")
            
            try:
                payload = msg.get_payload(decode=True) or b''
                content_type = msg.get_content_type().lower()
                
                # 1️⃣ Check for binary email formats FIRST (same as multipart)
                binary_kind = self._detect_binary_email(payload)
                
                if binary_kind == "msg":
                    logger.debug(f"{'  ' * depth}  Detected .msg file by signature ({len(payload):,} bytes)")
                    result = self._parse_msg_file(payload, depth, "single")
                    result['mime_type'] = content_type
                    result['declared_type'] = content_type
                    self._collect_text_content(result)
                    yield result
                    return  # Don't process as regular body
                
                elif binary_kind == "tnef":
                    logger.debug(f"{'  ' * depth}  Detected TNEF file by signature ({len(payload):,} bytes)")
                    try:
                        from tnefparse import TNEF
                        tnef_obj = TNEF(payload)
                        
                        # Extract attachment information
                        attachments = []
                        for attachment in tnef_obj.attachments:
                            att_info = {
                                'filename': attachment.name,
                                'size': len(attachment.data),
                                'long_filename': getattr(attachment, 'long_filename', None),
                                'created': str(getattr(attachment, 'created', None)),
                                'modified': str(getattr(attachment, 'modified', None))
                            }
                            
                            # Include small attachments, skip large ones
                            if len(attachment.data) < 100000:  # 100KB limit
                                att_info['encoding'] = self._determine_encoding(attachment.data)
                            else:
                                att_info['note'] = 'Content skipped due to size'
                            
                            attachments.append(att_info)
                        
                        result = {
                            'type': 'tnef_container',
                            'mime_type': content_type,
                            'declared_type': content_type,
                            'detected_format': 'tnef_winmail',
                            'size': len(payload),
                            'attachment_count': len(attachments),
                            'attachments': attachments,
                            'depth': depth
                        }
                        self._collect_text_content(result)
                        yield result
                        return  # Don't process as regular body
                        
                    except Exception as e:
                        logger.error(f"{'  ' * depth}    Error parsing TNEF file: {e}")
                        result = {
                            'type': 'binary_tnef',
                            'mime_type': content_type,
                            'declared_type': content_type,
                            'detected_format': 'tnef_winmail',
                            'size': len(payload),
                            'error': str(e),
                            'encoding': 'base64',
                            'depth': depth
                        }
                        self._collect_text_content(result)
                        yield result
                        return
                
                # 2️⃣ Not a binary format, treat as regular email body
                charset = msg.get_content_charset()
                text, encoding = self._to_str(payload, charset)
                
                email_body_data = {
                    'type': 'email_body',
                    'mime_type': content_type,
                    'charset': charset,
                    'size': len(payload),
                    'encoding': encoding,
                    'depth': depth
                }

                if encoding != 'base64':
                    email_body_data['content'] = text
                    # ENHANCED: Check for HTML content regardless of declared type
                    is_html = (
                        content_type == 'text/html' or 
                        self._is_likely_html_content(text, content_type)
                    )
                    
                    if is_html:
                        try:
                            email_body_data['text_only'] = self._clean_html(text)
                        except Exception as e:
                            logger.error(f"Failed to create text_only for email body: {e}")
                            email_body_data['text_only'] = self._fallback_html_clean(text)
                
                # Collect text content for artifact extraction
                self._collect_text_content(email_body_data)
                yield email_body_data
                
            except Exception as e:
                logger.error(f"{'  ' * depth}Error processing email body: {e}")
                yield {
                    'type': 'email_body_error',
                    'error': str(e),
                    'depth': depth
                }
    
    def _is_image_mime_type(self, mime_type: str) -> bool:
        """Check if a MIME type is an image"""
        return (mime_type.lower() in self.IMAGE_MIME_TYPES or 
                mime_type.lower().startswith('image/'))
    
    def _detect_binary_email(self, buf: bytes) -> Optional[str]:
        """Detect binary email formats by signature"""
        if not buf:
            return None
        if buf.startswith(self.OLE_SIGNATURE):
            return "msg"
        if buf.startswith(self.TNEF_SIGNATURE):
            return "tnef"
        return None

    def _is_probably_binary(self, buf: bytes, threshold: float = 0.1) -> bool:
        """Heuristic check to determine if data is binary."""
        if not buf:
            return False
        if b"\x00" in buf:
            return True
        printable = set(bytes(string.printable, "ascii"))
        non_printable = sum(b not in printable for b in buf)
        return non_printable / len(buf) > threshold

    def _to_str(self, data: bytes, charset: str | None) -> tuple[str, str]:
        """
        Return (text, encoding_name) – text is always a str.
        If decoding fails we fall back to base64.
        """
        if not data:
            return "", "empty"

        # If content appears binary, immediately return base64
        if self._is_probably_binary(data):
            return base64.b64encode(data).decode("ascii"), "base64"

        try:
            # prefer part's charset, else utf-8
            text = data.decode(charset or "utf-8", errors="replace")
            # If decoded text still looks binary, fall back to base64
            if self._is_probably_binary(text.encode("utf-8", errors="ignore")):
                return base64.b64encode(data).decode("ascii"), "base64"
            return text, (charset or "utf-8").lower()
        except LookupError:           # unknown charset label
            pass
        except UnicodeDecodeError:    # declared charset wrong
            pass

        # Try charset detection
        import chardet
        detected = chardet.detect(data)
        if detected and detected['encoding'] and detected['confidence'] > 0.7:
            try:
                text = data.decode(detected['encoding'], errors="replace")
                return text, detected['encoding'].lower()
            except (LookupError, UnicodeDecodeError):
                pass

        # last resort – keep as base64
        return base64.b64encode(data).decode("ascii"), "base64"
    
    def _encode_content(self, content: bytes) -> str:
        """Encode content for JSON storage (legacy method)"""
        text, _ = self._to_str(content, None)
        return text
    
    def _determine_encoding(self, content: bytes) -> str:
        """Determine how content was encoded for storage (legacy method)"""
        _, encoding = self._to_str(content, None)
        return encoding
    
    def _extract_all_artifacts(self) -> Dict[str, Any]:
        """Extract and deduplicate all artifacts from collected text content"""
        all_urls = set()
        all_ips = set()
        all_domains = set()
        
        # Source breakdown for detailed analysis
        sources_breakdown = {}
        
        logger.debug(f"Extracting artifacts from {len(self.all_text_content)} text blocks")
        
        for text_block in self.all_text_content:
            text = text_block['text']
            source = text_block['source']
            
            # Extract artifacts from this text block
            artifacts = self._extract_artifacts_from_text(text)
            
            # Add to global sets
            all_urls.update(artifacts['urls'])
            all_ips.update(artifacts['ips'])
            all_domains.update(artifacts['domains'])
            
            # Track per-source statistics
            if artifacts['urls'] or artifacts['ips'] or artifacts['domains']:
                sources_breakdown[source] = {
                    'urls': len(artifacts['urls']),
                    'ips': len(artifacts['ips']),
                    'domains': len(artifacts['domains']),
                    'block_type': text_block['block_type']
                }
        
        # Process and expand URLs
        processed = UrlProcessor.process_urls(sorted(all_urls))
        expanded = UrlProcessor.batch_expand_urls(processed, delay=0)
        expanded = UrlProcessor.fix_url_expansions(expanded)

        return {
            'urls': expanded,
            'ip_addresses': sorted(list(all_ips)),
            'domains': sorted(list(all_domains)),
            'statistics': {
                'total_urls': len(expanded),
                'total_ips': len(all_ips),
                'total_domains': len(all_domains),
                'sources_with_artifacts': len(sources_breakdown),
                'text_blocks_processed': len(self.all_text_content)
            },
            'sources_breakdown': sources_breakdown
        }

    def _validate_and_repair_html_cleaning(self, content_blocks: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Validate HTML cleaning and automatically repair issues."""
        
        def repair_block(block, path="root"):
            if not isinstance(block, dict):
                return block
                
            # Check for HTML content missing text_only
            if (block.get('mime_type') in ['text/html', 'text/plain'] and 
                'content' in block and 
                block.get('encoding') != 'base64'):
                
                content = block['content']
                if self._is_likely_html_content(content, block.get('mime_type', '')):
                    if 'text_only' not in block:
                        logger.warning(f"Auto-repairing missing text_only at {path}")
                        block['text_only'] = self._clean_html(content)
                    
                    # Double-check the cleaning worked
                    if 'text_only' in block and self._contains_html_tags(block['text_only']):
                        logger.error(f"HTML tags still present after cleaning at {path}")
                        block['text_only'] = self._fallback_html_clean(content)
            
            # Recursively repair nested content
            if 'nested_content' in block:
                nested = block['nested_content']
                if isinstance(nested, dict) and 'content' in nested:
                    if isinstance(nested['content'], list):
                        nested['content'] = [repair_block(nb, f"{path}.nested[{i}]") 
                                           for i, nb in enumerate(nested['content'])]
            
            return block
        
        return [repair_block(block, f"block[{i}]") for i, block in enumerate(content_blocks)]

    def _truncate_content_for_brevity(self, content_blocks: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Truncate content fields in blocks for non-forensics mode while preserving structure.
        
        Note: text_only fields are NEVER truncated as they contain valuable extracted plain text.
        Only raw binary/HTML content fields are truncated.
        """
        truncated_blocks = []
        
        for block in content_blocks:
            # Make a copy to avoid modifying the original
            truncated_block = dict(block)
            
            # Truncate large raw content fields but keep the block structure
            if 'content' in truncated_block and isinstance(truncated_block['content'], str):
                content = truncated_block['content']
                # Only truncate if it's not already base64 encoded and is longer than 500 chars
                if len(content) > 500 and truncated_block.get('encoding') != 'base64':
                    truncated_block['content'] = content[:500] + '... [truncated for brevity]'
            
            # NEVER truncate text_only - this is the valuable extracted plain text
            # text_only should always contain the complete cleaned text extraction
            
            # Recursively handle nested content
            if 'nested_content' in truncated_block:
                nested = truncated_block['nested_content']
                if isinstance(nested, dict) and 'content' in nested:
                    if isinstance(nested['content'], list):
                        truncated_block['nested_content'] = dict(nested)
                        truncated_block['nested_content']['content'] = self._truncate_content_for_brevity(nested['content'])
            
            truncated_blocks.append(truncated_block)
        
        return truncated_blocks
    
    def _build_output(
        self,
        source_name: str,
        msg: EmailMessage | None = None,
        forensics_mode: bool = False,
    ) -> Dict[str, Any]:
        """Build the final output structure with centralized plain text generation."""

        # Debug logging of collected text blocks and parser depth
        logger.debug(f"=== _build_output for {source_name} (depth={self.current_depth}) ===")
        logger.debug(f"Total content blocks: {len(self.content_blocks)}")
        logger.debug(f"Total text blocks in all_text_content: {len(self.all_text_content)}")

        for i, text_block in enumerate(self.all_text_content):
            source = text_block['source']
            text_len = len(text_block['text'])
            preview = text_block['text'][:100].replace('\n', ' ') if text_len > 0 else '[empty]'
            logger.debug(f"  Text block {i}: source={source}, length={text_len}")
            logger.debug(f"    Preview: {preview}...")

        logger.debug("=== End text block summary ===")
        
        # Sort content blocks by depth and type for better organization
        sorted_blocks = sorted(self.content_blocks, 
                             key=lambda x: (x['depth'], x['type'], x.get('mime_type', '')))
        
        # CRITICAL: Validate and repair HTML cleaning
        sorted_blocks = self._validate_and_repair_html_cleaning(sorted_blocks)
        
        # Collect statistics
        type_counts = {}
        mime_type_counts = {}
        depth_counts = {}
        
        for block in sorted_blocks:
            # Count by type
            block_type = block['type']
            type_counts[block_type] = type_counts.get(block_type, 0) + 1
            
            # Count by MIME type
            mime_type = block.get('mime_type', 'unknown')
            if mime_type != 'unknown':
                mime_type_counts[mime_type] = mime_type_counts.get(mime_type, 0) + 1
            
            # Count by depth
            depth = block['depth']
            depth_counts[depth] = depth_counts.get(depth, 0) + 1
        
        # Build comprehensive statistics
        statistics = {
            'total_size': len(self.raw_content),
            'content_blocks': len(sorted_blocks),
            'max_depth': max(depth_counts.keys()) if depth_counts else 0,
            'type_counts': type_counts,
            'mime_type_counts': mime_type_counts,
            'depth_distribution': depth_counts,
            'has_nested_emails': any(b['type'] == 'nested_email' for b in sorted_blocks),
            'has_attachments': any(b.get('disposition', '').lower() == 'attachment' for b in sorted_blocks),
            'multipart': msg.is_multipart() if msg else False
        }
        
        # Add email-specific metadata if available
        email_metadata = {}
        if msg:
            email_metadata = {
                'subject': msg.get('Subject', ''),
                'from': msg.get('From', ''),
                'to': msg.get('To', ''),
                'date': msg.get('Date', ''),
                'message_id': msg.get('Message-ID', ''),
                'content_type': msg.get_content_type()
            }
        
        # Extract artifacts from all collected text content
        extracted_artifacts = self._extract_all_artifacts()

        # CRITICAL FIX: Build plain_text from the SAME cleaned text used for artifacts
        plain_text = self._build_plain_text_from_cleaned_collection()

        # Apply content truncation if needed
        if not forensics_mode:
            sorted_blocks = self._truncate_content_for_brevity(sorted_blocks)

        output = {
            'source': source_name,
            'size': len(self.raw_content),
            'depth': self.current_depth,
            'email_metadata': email_metadata,
            'content': sorted_blocks,  # Always a list, never a string
            'statistics': statistics,
            'extracted_artifacts': extracted_artifacts,
            'plain_text': plain_text,
        }

        return output