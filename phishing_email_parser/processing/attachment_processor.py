#!/usr/bin/env python3
"""
Comprehensive phishing email parser for LLM analysis.

This parser handles user-submitted phishing emails, detects carrier emails
from security appliances, recursively parses nested structures, and outputs
structured JSON for LLM analysis.
"""

import sys
import os
import json
import logging
import re
from pathlib import Path
from typing import Dict, List, Any, Optional
from email import policy
from email.parser import BytesParser
from email.message import Message
import tempfile
import shutil

# Import our modules - FIXED IMPORTS
from ..core.html_cleaner import PhishingEmailHtmlCleaner
from .attachment_processor import AttachmentProcessor
from .msg_converter import MSGConverter
from ..url_processing.processor import UrlProcessor

# For compatibility with original script functionality
from PIL import Image
import pytesseract
from io import BytesIO

logger = logging.getLogger(__name__)


class PhishingEmailParser:
    """Main parser for phishing emails submitted by users."""
    
    def __init__(self, temp_dir: Optional[str] = None):
        """Initialize parser with optional temporary directory."""
        self.temp_dir = temp_dir or tempfile.mkdtemp(prefix="phishing_parser_")
        self.attachment_processor = AttachmentProcessor(self.temp_dir)
        self.msg_converter = MSGConverter()
        
    def __enter__(self):
        return self
        
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Clean up temporary directory."""
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def parse_email_file(self, email_path: str) -> Dict[str, Any]:
        """
        Parse an email file (.eml or .msg) and return structured data.
        
        Args:
            email_path: Path to email file
            
        Returns:
            Dictionary with parsed email structure
        """
        email_path = Path(email_path)
        
        if not email_path.exists():
            raise FileNotFoundError(f"Email file not found: {email_path}")
            
        # Convert .msg to .eml if needed
        if email_path.suffix.lower() == '.msg':
            eml_path = self.msg_converter.convert_msg_to_eml(
                str(email_path), 
                self.temp_dir
            )
            email_path = Path(eml_path)
        
        # Parse the email
        with open(email_path, 'rb') as f:
            msg = BytesParser(policy=policy.default).parse(f)
            
        return self._parse_message_structure(msg, str(email_path.parent))
    
    def _clean_header_value(self, value):
        """Clean header values by removing null terminators and other issues."""
        if not value:
            return ""
        if isinstance(value, bytes):
            value = value.decode('utf-8', errors='replace')
        if isinstance(value, str):
            # Remove null terminators and other control characters
            value = value.rstrip('\x00').strip()
            # Remove other common problematic characters
            value = value.replace('\x00', '').replace('\r', '').replace('\n', ' ')
        return value
    
    def _parse_message_structure(self, root_msg: Message, output_dir: str) -> Dict[str, Any]:
        """Parse the complete message structure including nested emails."""
        result = {
            "parser_info": {
                "version": "1.0",
                "purpose": "phishing_email_analysis"
            },
            "message_layers": [],
            "summary": {
                "total_layers": 0,
                "carrier_emails": [],
                "total_attachments": 0,
                "total_images": 0,
                "total_urls": 0,
                "has_nested_emails": False
            }
        }
        
        # Track processed nested emails to prevent duplicates
        processed_nested_emails = set()
        
        # Walk through all message layers using the existing MIME walker
        for depth, msg, vendor_tag in walk_layers(root_msg):
            layer_data = self._parse_single_layer(msg, depth, vendor_tag, output_dir)
            
            # Track message-rfc822 parts that were processed by walk_layers
            message_id = msg.get('Message-ID', '')
            if message_id:
                processed_nested_emails.add(message_id)
            
            result["message_layers"].append(layer_data)
            
            # Update summary
            result["summary"]["total_layers"] += 1
            if vendor_tag:
                result["summary"]["carrier_emails"].append({
                    "layer": depth,
                    "vendor": vendor_tag
                })
            if depth > 0:
                result["summary"]["has_nested_emails"] = True
        
        # FIXED: Only process attachment-based nested emails that weren't already processed by walk_layers
        nested_layers = self._process_nested_email_attachments(
            result["message_layers"], 
            output_dir, 
            processed_nested_emails
        )
        result["message_layers"].extend(nested_layers)
        
        # Update summary counts after processing nested emails
        result["summary"]["total_layers"] = len(result["message_layers"])
        if nested_layers:
            result["summary"]["has_nested_emails"] = True
            
        # Aggregate URLs, attachments, and images across all layers
        all_urls = []
        total_attachments = 0
        total_images = 0
        
        for layer in result["message_layers"]:
            if "urls" in layer:
                all_urls.extend(layer["urls"])
            if "attachments" in layer:
                total_attachments += len(layer["attachments"])
            if "images" in layer:
                total_images += len(layer["images"])
                
        result["summary"]["total_urls"] = len(all_urls)
        result["summary"]["total_attachments"] = total_attachments
        result["summary"]["total_images"] = total_images
        
        return result

    def _process_nested_email_attachments(self, existing_layers: List[Dict], 
                                        output_dir: str, 
                                        processed_nested_emails: set) -> List[Dict]:
        """Process nested email attachments that weren't already processed by walk_layers."""
        nested_layers = []
        
        for layer in existing_layers:
            current_depth = layer.get("layer_depth", 0)
            attachments = layer.get("attachments", [])
            
            for attachment in attachments:
                # FIXED: Only process attachments that are NOT message/rfc822
                # (message/rfc822 parts are handled by walk_layers)
                if (attachment.get("is_nested_email", False) and 
                    attachment.get("content_type") != "message/rfc822"):
                    
                    logger.info(f"Processing attachment-based nested email: {attachment['filename']}")
                    
                    try:
                        # Check if this email was already processed
                        nested_email_layers = self._parse_nested_email_attachment(
                            attachment, current_depth + 1, output_dir, processed_nested_emails
                        )
                        nested_layers.extend(nested_email_layers)
                        
                    except Exception as e:
                        logger.error(f"Error parsing nested email {attachment['filename']}: {e}")
                        # Add error info to the attachment
                        attachment["nested_parse_error"] = str(e)
        
        return nested_layers

    def _parse_nested_email_attachment(self, attachment: Dict, base_depth: int, 
                                     output_dir: str, processed_nested_emails: set) -> List[Dict]:
        """Parse a single nested email attachment and return its layers."""
        disk_path = attachment.get("disk_path")
        if not disk_path or not os.path.exists(disk_path):
            logger.warning(f"Nested email file not found: {disk_path}")
            return []
        
        try:
            # Load and parse the nested email file
            with open(disk_path, 'rb') as f:
                nested_msg = BytesParser(policy=policy.default).parse(f)
            
            # Check if this email was already processed by walk_layers
            message_id = nested_msg.get('Message-ID', '')
            if message_id and message_id in processed_nested_emails:
                logger.debug(f"Skipping {attachment['filename']} - already processed by MIME walker")
                return []
            
            logger.debug(f"Parsing nested email from {attachment['filename']} at depth {base_depth}")
            
            nested_layers = []
            
            # Walk through the nested email using the same logic
            for depth, msg, vendor_tag in walk_layers(nested_msg):
                # Adjust depth to be relative to the parent layer
                adjusted_depth = base_depth + depth
                
                layer_data = self._parse_single_layer(msg, adjusted_depth, vendor_tag, output_dir)
                
                # Add metadata to show this came from a nested attachment
                layer_data["parent_attachment"] = {
                    "filename": attachment["filename"],
                    "parent_layer_depth": base_depth - 1,
                    "attachment_index": attachment.get("index")
                }
                
                # Track this email as processed
                msg_id = msg.get('Message-ID', '')
                if msg_id:
                    processed_nested_emails.add(msg_id)
                
                nested_layers.append(layer_data)
                
                logger.debug(f"Added nested layer at depth {adjusted_depth} from {attachment['filename']}")
            
            # Recursively process any nested emails found in this nested email
            if nested_layers:
                deeper_nested = self._process_nested_email_attachments(
                    nested_layers, output_dir, processed_nested_emails
                )
                nested_layers.extend(deeper_nested)
            
            return nested_layers
            
        except Exception as e:
            logger.error(f"Error parsing nested email file {disk_path}: {e}")
            raise

    def _parse_single_layer(self, msg: Message, depth: int, vendor_tag: Optional[str],
                           output_dir: str) -> Dict[str, Any]:
        """Parse a single message layer."""
        logger.debug(f"Parsing layer {depth}, vendor: {vendor_tag}")
        
        layer = {
            "layer_depth": depth,
            "is_carrier_email": vendor_tag is not None,
            "carrier_vendor": vendor_tag,
            "headers": self._extract_headers(msg),
            "body": self._extract_body(msg),
            "attachments": [],
            "images": [],
            "urls": [],
            "nested_emails": []
        }
        
        # Process attachments
        attachments = self.attachment_processor.process_attachments(msg, output_dir)
        if attachments:
            layer["attachments"] = attachments
        logger.debug("Layer %d - %d attachments processed", depth, len(attachments))
        
        # Extract images with OCR
        images = self._extract_images_with_ocr(msg, output_dir)
        layer["images"] = images
        logger.debug("Layer %d - %d images processed", depth, len(images))
        
        # Extract URLs from body, attachments, and images
        urls = self._extract_all_urls(layer["body"], layer["attachments"], images)
        layer["urls"] = urls
        logger.debug("Layer %d - %d URLs extracted", depth, len(urls))

        # Truncate html_text to keep output concise and mark truncation
        html_text = layer["body"].get("html_text")
        if html_text:
            truncated = html_text[:100]
            if len(html_text) > 100:
                truncated += "... [truncated]"
            layer["body"]["html_text"] = truncated

        return layer
    
    def _extract_headers(self, msg: Message) -> Dict[str, Any]:
        """Extract relevant headers from message."""
        return {
            "subject": self._clean_header_value(msg.get("subject", "")),
            "from": self._clean_header_value(msg.get("from", "")),
            "to": self._clean_header_value(msg.get("to", "")),
            "cc": self._clean_header_value(msg.get("cc", "")),
            "bcc": self._clean_header_value(msg.get("bcc", "")),
            "date": self._clean_header_value(msg.get("date", "")),
            "message_id": self._clean_header_value(msg.get("message-id", "")),
            "reply_to": self._clean_header_value(msg.get("reply-to", "")),
            "return_path": self._clean_header_value(msg.get("return-path", "")),
            "received": [self._clean_header_value(r) for r in (msg.get_all("received") or [])],
            "x_headers": {
                k: self._clean_header_value(v) 
                for k, v in msg.items() 
                if k.lower().startswith('x-')
            }
        }
    
    def _extract_body(self, msg: Message) -> Dict[str, Any]:
        """Extract and process email body content."""
        body_data = {
            "plain_text": "",
            "html_text": "",
            "converted_text": "",
            "has_html": False,
            "has_plain": False
        }
        
        def get_content_safe(part):
            """Safely get content from an email part."""
            try:
                content = part.get_content()
                # Clean the content of null bytes and other problematic characters
                if isinstance(content, str):
                    content = content.replace('\x00', '')
                return content
            except Exception as e:
                logger.warning(f"Error getting content from email part: {e}")
                return ""
        
        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                # FIXED: Clean content type
                if content_type:
                    content_type = content_type.rstrip('\x00').strip()
                    
                if content_type == "text/plain" and not part.get_filename():
                    plain_content = get_content_safe(part)
                    if plain_content:
                        if PhishingEmailHtmlCleaner.contains_html(plain_content):
                            body_data["html_text"] = plain_content
                            body_data["has_html"] = True
                            body_data["converted_text"] = PhishingEmailHtmlCleaner.clean_html(
                                plain_content, aggressive_cleaning=True
                            )
                        else:
                            body_data["plain_text"] = plain_content
                            body_data["has_plain"] = True
                            # Skip if it looks like base64 encoded data
                            if (
                                len(body_data["plain_text"]) > 800
                                and re.fullmatch(r"[A-Za-z0-9+/=\s]{800,}", body_data["plain_text"])
                            ):
                                body_data["plain_text"] = ""
                elif content_type == "text/html" and not part.get_filename():
                    html_content = get_content_safe(part)
                    if html_content:
                        body_data["html_text"] = html_content
                        body_data["has_html"] = True
                        # Convert HTML to plain text
                        body_data["converted_text"] = PhishingEmailHtmlCleaner.clean_html(
                            html_content, aggressive_cleaning=True
                        )
        else:
            content_type = msg.get_content_type()
            # FIXED: Clean content type
            if content_type:
                content_type = content_type.rstrip('\x00').strip()
                
            content = get_content_safe(msg)
            if content:
                if content_type == "text/plain":
                    if PhishingEmailHtmlCleaner.contains_html(content):
                        body_data["html_text"] = content
                        body_data["has_html"] = True
                        body_data["converted_text"] = PhishingEmailHtmlCleaner.clean_html(
                            content, aggressive_cleaning=True
                        )
                    else:
                        body_data["plain_text"] = content
                        body_data["has_plain"] = True
                        # Skip if it looks like base64 encoded data
                        if (
                            len(body_data["plain_text"]) > 800
                            and re.fullmatch(r"[A-Za-z0-9+/=\s]{800,}", body_data["plain_text"])
                        ):
                            body_data["plain_text"] = ""
                elif content_type == "text/html":
                    body_data["html_text"] = content
                    body_data["has_html"] = True
                    body_data["converted_text"] = PhishingEmailHtmlCleaner.clean_html(
                        content, aggressive_cleaning=True
                    )
        
        # Use converted text if available, otherwise use plain text
        if body_data["converted_text"]:
            body_data["final_text"] = body_data["converted_text"]
        else:
            body_data["final_text"] = body_data["plain_text"]
            
        return body_data
    
    def _extract_all_urls(self, body_data: Dict[str, Any], attachments: List[Dict], 
                         images: List[Dict]) -> List[Dict]:
        """Extract and process URLs from body, attachments, and images."""
        all_urls = []
        
        # Extract URLs from email body
        body_text = body_data.get("final_text", "")
        if body_text:
            urls = self._extract_urls_from_text(body_text)
            all_urls.extend(urls)
            
        # Extract URLs from HTML body if available
        html_text = body_data.get("html_text", "")
        if html_text:
            html_urls = self._extract_urls_from_html(html_text)
            all_urls.extend(html_urls)
        
        # Extract URLs from attachments
        attachment_urls = UrlProcessor.extract_urls_from_attachments(attachments)
        all_urls.extend(attachment_urls)
        
        # Extract URLs from OCR text in images
        for image in images:
            if image.get("ocr_text"):
                image_urls = self._extract_urls_from_text(image["ocr_text"])
                all_urls.extend(image_urls)
        
        # Process and deduplicate URLs
        processed_urls = UrlProcessor.process_urls(all_urls)
        return processed_urls
    
    def _extract_images_with_ocr(self, msg: Message, output_dir: str) -> List[Dict[str, Any]]:
        """Extract images and perform OCR (from original script functionality)."""
        images = []
        image_idx = 1
        
        for part in msg.walk():
            ctype = part.get_content_type()
            if ctype.startswith("image/"):
                content_id = part.get("Content-ID")
                filename = part.get_filename() or f"image_{image_idx}.png"
                
                # FIXED: Strip null terminators and other problematic characters
                if filename:
                    filename = filename.rstrip('\x00').strip()
                    
                # FIXED: Clean content type
                if ctype:
                    ctype = ctype.rstrip('\x00').strip()
                    
                out_path = os.path.join(output_dir, filename)
                payload = part.get_payload(decode=True)
                ocr_text = None
                
                if payload:
                    # Save image to disk
                    try:
                        with open(out_path, "wb") as out:
                            out.write(payload)
                    except Exception as e:
                        logger.warning(f"Error saving image {filename}: {e}")
                        out_path = None
                    
                    # Perform OCR
                    try:
                        img = Image.open(BytesIO(payload))
                        img = img.convert('L')  # Convert to grayscale
                        ocr_text = pytesseract.image_to_string(img)
                        if ocr_text:
                            ocr_text = ocr_text.strip()
                    except Exception as e:
                        logger.warning(f"Error performing OCR on {filename}: {e}")
                        ocr_text = None
                
                # FIXED: Clean content_id of null bytes too
                clean_content_id = None
                if content_id:
                    clean_content_id = content_id.rstrip('\x00').strip()
                
                images.append({
                    "index": image_idx,
                    "filename": filename,
                    "disk_path": out_path,
                    "content_id": clean_content_id,
                    "content_type": ctype,  # Now cleaned
                    "ocr_text": ocr_text,
                    "size": len(payload) if payload else 0
                })
                image_idx += 1
        
        return images
    
    def _extract_urls_from_text(self, text: str) -> List[str]:
        """Extract URLs from plain text."""
        import re
        
        # Pattern to match URLs
        url_pattern = re.compile(
            r'https?://[^\s<>"{}|\\^`\[\]]+|www\.[^\s<>"{}|\\^`\[\]]+',
            re.IGNORECASE
        )
        
        urls = url_pattern.findall(text)
        return [url.rstrip('.,;:!?)]}') for url in urls]
    
    def _extract_urls_from_html(self, html_text: str) -> List[str]:
        """Extract URLs from HTML content."""
        from bs4 import BeautifulSoup
        
        try:
            soup = BeautifulSoup(html_text, 'html.parser')
            urls = []
            
            # Extract from href attributes
            for link in soup.find_all(['a', 'link'], href=True):
                urls.append(link['href'])
                
            # Extract from src attributes
            for element in soup.find_all(['img', 'script', 'iframe'], src=True):
                urls.append(element['src'])
                
            return [url for url in urls if url.startswith(('http://', 'https://'))]
        except Exception as e:
            logger.warning(f"Error extracting URLs from HTML: {e}")
            return []


def main():
    """Command line interface for the phishing email parser."""
    if len(sys.argv) not in (2, 3):
        print(f"Usage: {sys.argv[0]} <email_file> [output_file]")
        print("  email_file: Path to .eml or .msg file")
        print("  output_file: Optional JSON output file (default: stdout)")
        sys.exit(1)
    
    email_file = sys.argv[1]
    output_file = sys.argv[2] if len(sys.argv) == 3 else None
    
    # Configure logging
    logging.basicConfig(
        level=logging.DEBUG,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    try:
        with PhishingEmailParser() as parser:
            result = parser.parse_email_file(email_file)
            
            if output_file:
                with open(output_file, 'w', encoding='utf-8') as f:
                    json.dump(result, f, indent=2, ensure_ascii=False)
                print(f"Results written to {output_file}")
            else:
                print(json.dumps(result, indent=2, ensure_ascii=False))
                
    except Exception as e:
        logger.error(f"Error parsing email: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()