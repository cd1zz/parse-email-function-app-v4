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
from .core.mime_walker import walk_layers
from .core.html_cleaner import PhishingEmailHtmlCleaner
from .processing.attachment_processor import AttachmentProcessor
from .processing.msg_converter import MSGConverter
from .url_processing.processor import UrlProcessor

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
        
        # Walk through all message layers
        for depth, msg, vendor_tag in walk_layers(root_msg):
            layer_data = self._parse_single_layer(msg, depth, vendor_tag, output_dir)
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
            "subject": msg.get("subject", ""),
            "from": msg.get("from", ""),
            "to": msg.get("to", ""),
            "cc": msg.get("cc", ""),
            "bcc": msg.get("bcc", ""),
            "date": msg.get("date", ""),
            "message_id": msg.get("message-id", ""),
            "reply_to": msg.get("reply-to", ""),
            "return_path": msg.get("return-path", ""),
            "received": msg.get_all("received") or [],
            "x_headers": {k: v for k, v in msg.items() if k.lower().startswith('x-')}
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
                return part.get_content()
            except Exception as e:
                logger.warning(f"Error getting content from email part: {e}")
                return ""
        
        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
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
                    
                    # Strip null terminators and other problematic characters
                    if filename:
                        filename = filename.rstrip('\x00').strip()
                        
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
                    
                    images.append({
                        "index": image_idx,
                        "filename": filename,
                        "disk_path": out_path,
                        "content_id": content_id,
                        "content_type": ctype,
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
