# ============================================================================
# phishing_email_parser/core_extractors.py
# ============================================================================
"""
Core email content extractors implementing SOLID principles.
Handles header and body extraction with proper error handling and type safety.
"""

import logging
import re
from email.message import Message
from typing import Any, Dict, List, Optional

from .interfaces import IHeaderExtractor, IBodyExtractor
from .data_models import EmailHeaders, EmailBody, create_email_headers, create_email_body
from .exceptions import handle_processing_errors, EmailParsingError
from .core.html_cleaner import PhishingEmailHtmlCleaner

logger = logging.getLogger(__name__)


class HeaderExtractor(IHeaderExtractor):
    """
    Extracts and cleans email headers with security-focused sanitization.
    
    Preserves ALL functionality from original _extract_headers and _clean_header_value methods.
    """
    
    @handle_processing_errors("header extraction")
    def extract_headers(self, msg: Message) -> EmailHeaders:
        """
        Extract all relevant headers from email message.
        
        PRESERVES: All original header extraction logic from main_parser.py
        ENHANCES: Uses structured EmailHeaders dataclass
        """
        logger.debug("Extracting headers from email message")
        
        try:
            headers = create_email_headers(
                subject=self.clean_header_value(msg.get("subject", "")),
                from_addr=self.clean_header_value(msg.get("from", "")),
                to=self.clean_header_value(msg.get("to", "")),
                cc=self.clean_header_value(msg.get("cc", "")),
                bcc=self.clean_header_value(msg.get("bcc", "")),
                date=self.clean_header_value(msg.get("date", "")),
                message_id=self.clean_header_value(msg.get("message-id", "")),
                reply_to=self.clean_header_value(msg.get("reply-to", "")),
                return_path=self.clean_header_value(msg.get("return-path", "")),
                received=[
                    self.clean_header_value(r) for r in (msg.get_all("received") or [])
                ],
                x_headers={
                    k: self.clean_header_value(v)
                    for k, v in msg.items()
                    if k.lower().startswith("x-")
                }
            )
            
            logger.debug(f"Extracted headers: subject='{headers.subject[:50]}...', from='{headers.from_addr}'")
            return headers
            
        except Exception as e:
            logger.error(f"Failed to extract headers: {e}")
            raise EmailParsingError(f"Header extraction failed: {e}", {"message_keys": list(msg.keys())})
    
    def clean_header_value(self, value: Any) -> str:
        """
        Clean header values by removing null terminators and control characters.
        
        PRESERVES: Exact logic from original _clean_header_value method
        CRITICAL: This security sanitization prevents issues with null bytes in headers
        """
        if not value:
            return ""
        
        # Handle bytes input
        if isinstance(value, bytes):
            value = value.decode("utf-8", errors="replace")
        
        if isinstance(value, str):
            # CRITICAL: Remove null terminators and other control characters (from original)
            value = value.rstrip("\x00").strip()
            # Remove other common problematic characters (from original)
            value = value.replace("\x00", "").replace("\r", "").replace("\n", " ")
        
        return value


class BodyExtractor(IBodyExtractor):
    """
    Extracts and processes email body content with HTML cleaning.
    
    Preserves ALL functionality from original _extract_body method.
    """
    
    def __init__(self, aggressive_cleaning: bool = True):
        """Initialize with HTML cleaning configuration."""
        self.aggressive_cleaning = aggressive_cleaning
    
    @handle_processing_errors("body extraction")
    def extract_body(self, msg: Message) -> EmailBody:
        """
        Extract and process email body content.
        
        PRESERVES: Complete logic from original _extract_body method
        ENHANCES: Uses structured EmailBody dataclass and better error handling
        """
        logger.debug("Extracting body content from email message")
        
        body_data = {
            "plain_text": "",
            "html_text": "",
            "converted_text": "",
            "has_html": False,
            "has_plain": False,
        }
        
        try:
            if msg.is_multipart():
                self._extract_multipart_body(msg, body_data)
            else:
                self._extract_single_part_body(msg, body_data)
            
            # Use converted text if available, otherwise use plain text (original logic)
            if body_data["converted_text"]:
                final_text = body_data["converted_text"]
            else:
                final_text = body_data["plain_text"]
            
            result = create_email_body(
                plain_text=body_data["plain_text"],
                html_text=body_data["html_text"],
                converted_text=body_data["converted_text"],
                final_text=final_text,
                has_html=body_data["has_html"],
                has_plain=body_data["has_plain"]
            )
            
            logger.debug(
                f"Body extraction complete: plain={len(result.plain_text)} chars, "
                f"html={len(result.html_text)} chars, final={len(result.final_text)} chars"
            )
            
            return result
            
        except Exception as e:
            logger.error(f"Failed to extract body content: {e}")
            raise EmailParsingError(f"Body extraction failed: {e}")
    
    def _extract_multipart_body(self, msg: Message, body_data: Dict[str, Any]) -> None:
        """
        Extract body content from multipart message.
        
        PRESERVES: Exact logic from original _extract_body for multipart messages
        """
        for part in msg.walk():
            content_type = part.get_content_type()
            
            # FIXED: Clean content type (from original)
            if content_type:
                content_type = content_type.rstrip("\x00").strip()
            
            if content_type == "text/plain" and not part.get_filename():
                plain_content = self.get_content_safe(part)
                if plain_content:
                    if PhishingEmailHtmlCleaner.contains_html(plain_content):
                        body_data["html_text"] = plain_content
                        body_data["has_html"] = True
                        body_data["converted_text"] = PhishingEmailHtmlCleaner.clean_html(
                            plain_content, aggressive_cleaning=self.aggressive_cleaning
                        )
                    else:
                        body_data["plain_text"] = plain_content
                        body_data["has_plain"] = True
                        # Skip if it looks like base64 encoded data (original logic)
                        if len(body_data["plain_text"]) > 800 and re.fullmatch(
                            r"[A-Za-z0-9+/=\s]{800,}", body_data["plain_text"]
                        ):
                            body_data["plain_text"] = ""
                            
            elif content_type == "text/html" and not part.get_filename():
                html_content = self.get_content_safe(part)
                if html_content:
                    body_data["html_text"] = html_content
                    body_data["has_html"] = True
                    # Convert HTML to plain text (original logic)
                    body_data["converted_text"] = PhishingEmailHtmlCleaner.clean_html(
                        html_content, aggressive_cleaning=self.aggressive_cleaning
                    )
    
    def _extract_single_part_body(self, msg: Message, body_data: Dict[str, Any]) -> None:
        """
        Extract body content from single-part message.
        
        PRESERVES: Exact logic from original _extract_body for single-part messages
        """
        content_type = msg.get_content_type()
        
        # FIXED: Clean content type (from original)
        if content_type:
            content_type = content_type.rstrip("\x00").strip()
        
        content = self.get_content_safe(msg)
        if content:
            if content_type == "text/plain":
                if PhishingEmailHtmlCleaner.contains_html(content):
                    body_data["html_text"] = content
                    body_data["has_html"] = True
                    body_data["converted_text"] = PhishingEmailHtmlCleaner.clean_html(
                        content, aggressive_cleaning=self.aggressive_cleaning
                    )
                else:
                    body_data["plain_text"] = content
                    body_data["has_plain"] = True
                    # Skip if it looks like base64 encoded data (original logic)
                    if len(body_data["plain_text"]) > 800 and re.fullmatch(
                        r"[A-Za-z0-9+/=\s]{800,}", body_data["plain_text"]
                    ):
                        body_data["plain_text"] = ""
                        
            elif content_type == "text/html":
                body_data["html_text"] = content
                body_data["has_html"] = True
                body_data["converted_text"] = PhishingEmailHtmlCleaner.clean_html(
                    content, aggressive_cleaning=self.aggressive_cleaning
                )
    
    def get_content_safe(self, part: Message) -> str:
        """
        Safely get content from an email part.
        
        PRESERVES: Exact logic from original get_content_safe function
        CRITICAL: Handles null bytes and other problematic characters
        """
        try:
            content = part.get_content()
            # Clean the content of null bytes and other problematic characters (original logic)
            if isinstance(content, str):
                content = content.replace("\x00", "")
            return content
        except Exception as e:
            logger.warning(f"Error getting content from email part: {e}")
            return ""


# Factory functions for dependency injection
def create_header_extractor() -> IHeaderExtractor:
    """Create header extractor instance."""
    return HeaderExtractor()


def create_body_extractor(aggressive_cleaning: bool = True) -> IBodyExtractor:
    """Create body extractor instance with configuration."""
    return BodyExtractor(aggressive_cleaning=aggressive_cleaning)