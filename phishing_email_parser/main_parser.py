#!/usr/bin/env python3
"""
Comprehensive phishing email parser for LLM analysis.

This parser handles user-submitted phishing emails, detects carrier emails
from security appliances and user submissions, recursively parses nested
structures, and outputs structured JSON for LLM analysis with enhanced
carrier detection and content deduplication.
"""

import hashlib
import json
import logging
import os
import re
import shutil
import sys
import tempfile
from email import policy
from email.message import Message
from email.parser import BytesParser
from io import BytesIO
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

import pytesseract

# For compatibility with original script functionality
from PIL import Image

from .core.carrier_detector import (
    analyze_potential_carrier,
    detect_vendor_enhanced,
    format_carrier_summary,
    get_carrier_analysis_priority,
)
from .core.html_cleaner import PhishingEmailHtmlCleaner

# Import our modules
from .core.mime_walker import walk_layers
from .processing.attachment_processor import AttachmentProcessor
from .processing.msg_converter import MSGConverter
from .url_processing.processor import UrlProcessor
from .config import DEFAULT_CONFIG, ParserConfig
from .exceptions import AttachmentProcessingError, EmailParserError

logger = logging.getLogger(__name__)


class EmailContentDeduplicator:
    """Handles deduplication of email content during nested processing."""

    def __init__(self):
        self.processed_content_hashes: Set[str] = set()
        self.processed_message_ids: Set[str] = set()
        self.layer_content_signatures: Dict[int, str] = {}

    def generate_content_signature(self, msg: Message) -> str:
        """Generate a unique signature for email content."""
        # Combine key identifying fields
        subject = msg.get("subject", "").strip()
        from_addr = msg.get("from", "").strip()
        date = msg.get("date", "").strip()
        message_id = msg.get("message-id", "").strip()

        # Get a sample of body content for comparison
        body_sample = ""
        if msg.is_multipart():
            for part in msg.walk():
                if part.get_content_type() == "text/plain":
                    try:
                        content = part.get_content()
                        if content:
                            body_sample = content[:500]  # First 500 chars
                            break
                    except Exception:
                        continue
        else:
            try:
                content = msg.get_content()
                if content:
                    body_sample = content[:500]
            except Exception:
                pass

        # Create signature from combined fields
        signature_data = f"{subject}|{from_addr}|{date}|{message_id}|{body_sample}"
        return hashlib.sha256(signature_data.encode("utf-8")).hexdigest()[:16]

    def is_duplicate_content(self, msg: Message, current_depth: int) -> bool:
        """Check if this message content has already been processed."""
        # Check by Message-ID first (most reliable)
        message_id = msg.get("message-id", "").strip()
        if message_id and message_id in self.processed_message_ids:
            logger.debug(f"Duplicate detected by Message-ID: {message_id}")
            return True

        # Check by content signature
        content_sig = self.generate_content_signature(msg)
        if content_sig in self.processed_content_hashes:
            logger.debug(f"Duplicate detected by content signature: {content_sig}")
            return True

        # Check for identical content in parent layers
        for layer_depth, layer_sig in self.layer_content_signatures.items():
            if layer_depth < current_depth and layer_sig == content_sig:
                logger.debug(
                    f"Duplicate content found: layer {current_depth} matches layer {layer_depth}"
                )
                return True

        return False

    def mark_as_processed(self, msg: Message, depth: int):
        """Mark this message as processed to prevent future duplicates."""
        message_id = msg.get("message-id", "").strip()
        if message_id:
            self.processed_message_ids.add(message_id)

        content_sig = self.generate_content_signature(msg)
        self.processed_content_hashes.add(content_sig)
        self.layer_content_signatures[depth] = content_sig

        logger.debug(f"Marked layer {depth} as processed (sig: {content_sig[:8]}...)")


class PhishingEmailParser:
    """Main parser for phishing emails with enhanced carrier detection."""

    def __init__(
        self, temp_dir: Optional[str] = None, config: ParserConfig | None = None
    ) -> None:
        """Initialize the parser.

        Args:
            temp_dir: Optional path to a temporary directory. If ``None`` a new directory is created.
            config: Optional parser configuration to customize behaviour.
        """

        self.temp_dir = temp_dir or tempfile.mkdtemp(prefix="phishing_parser_")
        self.config = config or DEFAULT_CONFIG
        self.attachment_processor = AttachmentProcessor(self.temp_dir, self.config)
        self.msg_converter = MSGConverter()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Clean up temporary directory."""
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir, ignore_errors=True)

    def parse_email_file(self, email_path: str | Path) -> Dict[str, Any]:
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

        if email_path.suffix.lower() not in {".eml", ".msg"}:
            raise ValueError(
                "Unsupported email file type. Only .eml and .msg are allowed"
            )

        # Convert .msg to .eml if needed
        if email_path.suffix.lower() == ".msg":
            eml_path = self.msg_converter.convert_msg_to_eml(
                str(email_path), self.temp_dir
            )
            email_path = Path(eml_path)

        # Parse the email
        with open(email_path, "rb") as f:
            msg = BytesParser(policy=policy.default).parse(f)

        try:
            return self._parse_message_structure(msg, str(email_path.parent))
        except AttachmentProcessingError as exc:
            raise EmailParserError(f"Attachment processing failed: {exc}") from exc

    def _parse_single_layer(
        self, msg: Message, depth: int, vendor_tag: Optional[str], output_dir: str
    ) -> Dict[str, Any]:
        """Parse a single message layer with enhanced carrier detection."""
        logger.debug(f"Parsing layer {depth}, vendor: {vendor_tag}")

        # Get enhanced carrier detection details
        vendor_tag_enhanced, carrier_details = detect_vendor_enhanced(msg)

        # Use enhanced detection if it found something, otherwise use walk_layers result
        final_vendor_tag = vendor_tag_enhanced or vendor_tag
        analysis_priority = get_carrier_analysis_priority(final_vendor_tag)

        layer = {
            "layer_depth": depth,
            "is_carrier_email": final_vendor_tag is not None,
            "carrier_vendor": final_vendor_tag,
            "carrier_details": carrier_details,
            "analysis_priority": analysis_priority,
            "carrier_summary": format_carrier_summary(
                final_vendor_tag, carrier_details
            ),
            "headers": self._extract_headers(msg),
            "body": self._extract_body(msg),
            "attachments": [],
            "images": [],
            "urls": [],
            "nested_emails": [],
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
            "received": [
                self._clean_header_value(r) for r in (msg.get_all("received") or [])
            ],
            "x_headers": {
                k: self._clean_header_value(v)
                for k, v in msg.items()
                if k.lower().startswith("x-")
            },
        }

    def _clean_header_value(self, value):
        """Clean header values by removing null terminators and other issues."""
        if not value:
            return ""
        if isinstance(value, bytes):
            value = value.decode("utf-8", errors="replace")
        if isinstance(value, str):
            # Remove null terminators and other control characters
            value = value.rstrip("\x00").strip()
            # Remove other common problematic characters
            value = value.replace("\x00", "").replace("\r", "").replace("\n", " ")
        return value

    def _extract_body(self, msg: Message) -> Dict[str, Any]:
        """Extract and process email body content."""
        body_data = {
            "plain_text": "",
            "html_text": "",
            "converted_text": "",
            "has_html": False,
            "has_plain": False,
        }

        def get_content_safe(part):
            """Safely get content from an email part."""
            try:
                content = part.get_content()
                # Clean the content of null bytes and other problematic characters
                if isinstance(content, str):
                    content = content.replace("\x00", "")
                return content
            except Exception as e:
                logger.warning(f"Error getting content from email part: {e}")
                return ""

        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                # FIXED: Clean content type
                if content_type:
                    content_type = content_type.rstrip("\x00").strip()

                if content_type == "text/plain" and not part.get_filename():
                    plain_content = get_content_safe(part)
                    if plain_content:
                        if PhishingEmailHtmlCleaner.contains_html(plain_content):
                            body_data["html_text"] = plain_content
                            body_data["has_html"] = True
                            body_data["converted_text"] = (
                                PhishingEmailHtmlCleaner.clean_html(
                                    plain_content, aggressive_cleaning=True
                                )
                            )
                        else:
                            body_data["plain_text"] = plain_content
                            body_data["has_plain"] = True
                            # Skip if it looks like base64 encoded data
                            if len(body_data["plain_text"]) > 800 and re.fullmatch(
                                r"[A-Za-z0-9+/=\s]{800,}", body_data["plain_text"]
                            ):
                                body_data["plain_text"] = ""
                elif content_type == "text/html" and not part.get_filename():
                    html_content = get_content_safe(part)
                    if html_content:
                        body_data["html_text"] = html_content
                        body_data["has_html"] = True
                        # Convert HTML to plain text
                        body_data["converted_text"] = (
                            PhishingEmailHtmlCleaner.clean_html(
                                html_content, aggressive_cleaning=True
                            )
                        )
        else:
            content_type = msg.get_content_type()
            # FIXED: Clean content type
            if content_type:
                content_type = content_type.rstrip("\x00").strip()

            content = get_content_safe(msg)
            if content:
                if content_type == "text/plain":
                    if PhishingEmailHtmlCleaner.contains_html(content):
                        body_data["html_text"] = content
                        body_data["has_html"] = True
                        body_data["converted_text"] = (
                            PhishingEmailHtmlCleaner.clean_html(
                                content, aggressive_cleaning=True
                            )
                        )
                    else:
                        body_data["plain_text"] = content
                        body_data["has_plain"] = True
                        # Skip if it looks like base64 encoded data
                        if len(body_data["plain_text"]) > 800 and re.fullmatch(
                            r"[A-Za-z0-9+/=\s]{800,}", body_data["plain_text"]
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

    def _extract_all_urls(
        self, body_data: Dict[str, Any], attachments: List[Dict], images: List[Dict]
    ) -> List[Dict]:
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

    def _extract_images_with_ocr(
        self, msg: Message, output_dir: str
    ) -> List[Dict[str, Any]]:
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
                    filename = filename.rstrip("\x00").strip()

                # FIXED: Clean content type
                if ctype:
                    ctype = ctype.rstrip("\x00").strip()

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
                        img = img.convert("L")  # Convert to grayscale
                        ocr_text = pytesseract.image_to_string(img)
                        if ocr_text:
                            ocr_text = ocr_text.strip()
                    except Exception as e:
                        logger.warning(f"Error performing OCR on {filename}: {e}")
                        ocr_text = None

                # FIXED: Clean content_id of null bytes too
                clean_content_id = None
                if content_id:
                    clean_content_id = content_id.rstrip("\x00").strip()

                images.append(
                    {
                        "index": image_idx,
                        "filename": filename,
                        "disk_path": out_path,
                        "content_id": clean_content_id,
                        "content_type": ctype,  # Now cleaned
                        "ocr_text": ocr_text,
                        "size": len(payload) if payload else 0,
                    }
                )
                image_idx += 1

        return images

    def _extract_urls_from_text(self, text: str) -> List[str]:
        """Extract URLs from plain text."""
        import re

        # Pattern to match URLs
        url_pattern = re.compile(
            r'https?://[^\s<>"{}|\\^`\[\]]+|www\.[^\s<>"{}|\\^`\[\]]+', re.IGNORECASE
        )

        urls = url_pattern.findall(text)
        return [url.rstrip(".,;:!?)]}") for url in urls]

    def _extract_urls_from_html(self, html_text: str) -> List[str]:
        """Extract URLs from HTML content."""
        from bs4 import BeautifulSoup

        try:
            soup = BeautifulSoup(html_text, "html.parser")
            urls = []

            # Extract from href attributes
            for link in soup.find_all(["a", "link"], href=True):
                urls.append(link["href"])

            # Extract from src attributes
            for element in soup.find_all(["img", "script", "iframe"], src=True):
                urls.append(element["src"])

            return [url for url in urls if url.startswith(("http://", "https://"))]
        except Exception as e:
            logger.warning(f"Error extracting URLs from HTML: {e}")
            return []

    def _parse_message_structure(
        self, root_msg: Message, output_dir: str
    ) -> Dict[str, Any]:
        """Parse the complete message structure with content deduplication and enhanced carrier detection."""
        result = {
            "parser_info": {
                "version": "1.1",
                "purpose": "phishing_email_analysis",
                "features": [
                    "content_deduplication",
                    "enhanced_carrier_detection",
                    "user_submission_detection",
                ],
            },
            "message_layers": [],
            "carrier_analysis": {
                "total_carriers": 0,
                "security_appliances": [],
                "user_submissions": [],
                "analysis_recommendations": [],
            },
            "summary": {
                "total_layers": 0,
                "carrier_emails": [],
                "total_attachments": 0,
                "total_images": 0,
                "total_urls": 0,
                "has_nested_emails": False,
            },
        }

        # Initialize deduplicator
        deduplicator = EmailContentDeduplicator()

        # Walk through all message layers using the existing MIME walker
        for depth, msg, vendor_tag in walk_layers(root_msg):
            # Check for duplicate content
            if deduplicator.is_duplicate_content(msg, depth):
                logger.info(f"Skipping duplicate content at layer {depth}")
                continue

            # Mark as processed before parsing to prevent recursion issues
            deduplicator.mark_as_processed(msg, depth)

            layer_data = self._parse_single_layer(msg, depth, vendor_tag, output_dir)
            result["message_layers"].append(layer_data)

            # Log layer processing for debugging
            self._log_layer_processing(layer_data)

            # Update carrier analysis
            self._update_carrier_analysis(layer_data, result["carrier_analysis"])

            # Update summary
            result["summary"]["total_layers"] += 1
            if layer_data["is_carrier_email"]:
                result["summary"]["carrier_emails"].append(
                    {
                        "layer": depth,
                        "vendor": layer_data["carrier_vendor"],
                        "type": layer_data.get("carrier_details", {}).get(
                            "type", "unknown"
                        ),
                        "priority": layer_data["analysis_priority"],
                    }
                )
            if depth > 0:
                result["summary"]["has_nested_emails"] = True

        # Process attachment-based nested emails (with deduplication)
        nested_layers = self._process_nested_email_attachments_dedupe(
            result["message_layers"], output_dir, deduplicator
        )

        # Update carrier analysis for nested layers
        for nested_layer in nested_layers:
            self._update_carrier_analysis(nested_layer, result["carrier_analysis"])

        result["message_layers"].extend(nested_layers)

        # Final summary update
        result["summary"]["total_layers"] = len(result["message_layers"])
        if nested_layers:
            result["summary"]["has_nested_emails"] = True

        # Generate analysis recommendations
        self._generate_analysis_recommendations(result)

        # Aggregate final counts
        self._update_summary_counts(result)

        return result

    def _update_carrier_analysis(
        self, layer_data: Dict[str, Any], carrier_analysis: Dict[str, Any]
    ):
        """Update carrier analysis with information from a processed layer."""
        if not layer_data.get("is_carrier_email"):
            return

        carrier_analysis["total_carriers"] += 1

        carrier_details = layer_data.get("carrier_details")
        if carrier_details:
            carrier_type = carrier_details.get("type")

            if carrier_type == "security_appliance":
                carrier_analysis["security_appliances"].append(
                    {
                        "layer": layer_data["layer_depth"],
                        "vendor": layer_data["carrier_vendor"],
                        "detection_method": carrier_details.get(
                            "detection_method", "unknown"
                        ),
                    }
                )
            elif carrier_type == "user_submission":
                evidence = carrier_details.get("evidence", {})
                carrier_analysis["user_submissions"].append(
                    {
                        "layer": layer_data["layer_depth"],
                        "submission_type": layer_data["carrier_vendor"],
                        "confidence_score": evidence.get("confidence_score", 0),
                        "evidence_count": len(
                            evidence.get("structural_indicators", [])
                        ),
                        "summary": layer_data["carrier_summary"],
                    }
                )

    def _generate_analysis_recommendations(self, result: Dict[str, Any]):
        """Generate LLM analysis recommendations based on carrier detection."""
        recommendations = []
        high_priority_layers = []

        for layer in result["message_layers"]:
            if layer.get("analysis_priority") == "HIGH":
                high_priority_layers.append(layer["layer_depth"])

        if high_priority_layers:
            recommendations.append(
                {
                    "priority": "HIGH",
                    "action": "focus_analysis",
                    "layers": high_priority_layers,
                    "reason": "These layers contain non-carrier content and should be the primary focus of threat analysis",
                }
            )

        if result["carrier_analysis"]["user_submissions"]:
            recommendations.append(
                {
                    "priority": "MEDIUM",
                    "action": "validate_submission_context",
                    "reason": "User-submitted carriers detected - validate internal submission workflow and sender legitimacy",
                }
            )

        if result["carrier_analysis"]["security_appliances"]:
            recommendations.append(
                {
                    "priority": "LOW",
                    "action": "review_security_processing",
                    "reason": "Security appliance processing detected - review why email reached analysis (bypass detection?)",
                }
            )

        if result["summary"]["total_layers"] > 3:
            recommendations.append(
                {
                    "priority": "MEDIUM",
                    "action": "analyze_nesting_complexity",
                    "reason": f"Complex nesting detected ({result['summary']['total_layers']} layers) - may indicate advanced evasion techniques",
                }
            )

        result["carrier_analysis"]["analysis_recommendations"] = recommendations

    def _process_nested_email_attachments_dedupe(
        self,
        existing_layers: List[Dict],
        output_dir: str,
        deduplicator: EmailContentDeduplicator,
    ) -> List[Dict]:
        """Process nested email attachments with content deduplication."""
        nested_layers = []

        for layer in existing_layers:
            current_depth = layer.get("layer_depth", 0)
            attachments = layer.get("attachments", [])

            for attachment in attachments:
                # Only process attachment-based nested emails
                # BUT exclude message/rfc822 since those are handled by walk_layers
                if (
                    attachment.get("is_nested_email", False)
                    and attachment.get("content_type") != "message/rfc822"
                ):

                    logger.info(
                        f"Processing attachment-based nested email: {attachment['filename']}"
                    )

                    try:
                        nested_email_layers = (
                            self._parse_nested_email_attachment_dedupe(
                                attachment, current_depth + 1, output_dir, deduplicator
                            )
                        )
                        nested_layers.extend(nested_email_layers)

                    except Exception as e:
                        logger.error(
                            f"Error parsing nested email {attachment['filename']}: {e}"
                        )
                        attachment["nested_parse_error"] = str(e)

        return nested_layers

    def _parse_nested_email_attachment_dedupe(
        self,
        attachment: Dict,
        base_depth: int,
        output_dir: str,
        deduplicator: EmailContentDeduplicator,
    ) -> List[Dict]:
        """Parse a nested email attachment with deduplication."""
        disk_path = attachment.get("disk_path")
        if not disk_path or not os.path.exists(disk_path):
            logger.warning(f"Nested email file not found: {disk_path}")
            return []

        try:
            # Load and parse the nested email file
            with open(disk_path, "rb") as f:
                nested_msg = BytesParser(policy=policy.default).parse(f)

            # Check if this content is a duplicate
            if deduplicator.is_duplicate_content(nested_msg, base_depth):
                logger.info(
                    f"Skipping duplicate nested email: {attachment['filename']}"
                )
                return []

            logger.debug(
                f"Processing unique nested email from {attachment['filename']} at depth {base_depth}"
            )

            nested_layers = []

            # Walk through the nested email
            for depth, msg, vendor_tag in walk_layers(nested_msg):
                adjusted_depth = base_depth + depth

                # Check for duplicates at adjusted depth
                if deduplicator.is_duplicate_content(msg, adjusted_depth):
                    logger.debug(f"Skipping duplicate layer at depth {adjusted_depth}")
                    continue

                # Mark as processed
                deduplicator.mark_as_processed(msg, adjusted_depth)

                layer_data = self._parse_single_layer(
                    msg, adjusted_depth, vendor_tag, output_dir
                )

                # Add metadata showing this came from a nested attachment
                layer_data["parent_attachment"] = {
                    "filename": attachment["filename"],
                    "parent_layer_depth": base_depth - 1,
                    "attachment_index": attachment.get("index"),
                }

                # Log layer processing
                self._log_layer_processing(layer_data)

                nested_layers.append(layer_data)
                logger.debug(f"Added unique nested layer at depth {adjusted_depth}")

            # Recursively process any further nested emails
            if nested_layers:
                deeper_nested = self._process_nested_email_attachments_dedupe(
                    nested_layers, output_dir, deduplicator
                )
                nested_layers.extend(deeper_nested)

            return nested_layers

        except Exception as e:
            logger.error(f"Error parsing nested email file {disk_path}: {e}")
            raise

    def _update_summary_counts(self, result: Dict[str, Any]):
        """Update summary counts after deduplication."""
        all_urls = []
        total_attachments = 0
        total_images = 0
        total_embedded_images = 0

        for layer in result["message_layers"]:
            if "urls" in layer:
                all_urls.extend(layer["urls"])
            if "attachments" in layer:
                total_attachments += len(layer["attachments"])
                # Count embedded images from Excel files
                for attachment in layer["attachments"]:
                    if "embedded_images" in attachment:
                        total_embedded_images += len(attachment["embedded_images"])
            if "images" in layer:
                total_images += len(layer["images"])

        result["summary"]["total_urls"] = len(all_urls)
        result["summary"]["total_attachments"] = total_attachments
        result["summary"]["total_images"] = total_images
        result["summary"]["total_embedded_images"] = total_embedded_images

        # Log embedded image extraction results
        if total_embedded_images > 0:
            logger.info(
                f"Found {total_embedded_images} embedded images in Excel attachments"
            )

    def _log_layer_processing(self, layer_data: Dict[str, Any]):
        """Log layer processing details for debugging."""
        depth = layer_data.get("layer_depth", 0)
        subject = layer_data.get("headers", {}).get("subject", "No Subject")[:50]
        from_addr = layer_data.get("headers", {}).get("from", "No From")[:30]

        carrier_info = ""
        if layer_data.get("is_carrier_email"):
            carrier_info = (
                f" [{layer_data['carrier_vendor']} - {layer_data['analysis_priority']}]"
            )

        logger.info(f"Layer {depth}: '{subject}' from '{from_addr}'{carrier_info}")

        if layer_data.get("parent_attachment"):
            parent_info = layer_data["parent_attachment"]
            logger.info(f"  ↳ From attachment: {parent_info['filename']}")

    def analyze_email_structure(self, email_path: str) -> Dict[str, Any]:
        """
        Perform detailed analysis of email structure for debugging and understanding.

        Args:
            email_path: Path to email file

        Returns:
            Detailed analysis including carrier detection debugging
        """
        email_path = Path(email_path)

        if not email_path.exists():
            raise FileNotFoundError(f"Email file not found: {email_path}")

        # Convert .msg to .eml if needed
        if email_path.suffix.lower() == ".msg":
            eml_path = self.msg_converter.convert_msg_to_eml(
                str(email_path), self.temp_dir
            )
            email_path = Path(eml_path)

        # Parse the email
        with open(email_path, "rb") as f:
            msg = BytesParser(policy=policy.default).parse(f)

        # Perform detailed analysis
        analysis = {
            "file_info": {
                "path": str(email_path),
                "size": email_path.stat().st_size,
                "type": email_path.suffix,
            },
            "structure_analysis": analyze_potential_carrier(msg),
            "parsing_preview": self._parse_message_structure(
                msg, str(email_path.parent)
            ),
        }

        return analysis


def main():
    """Command line interface for the phishing email parser."""
    if len(sys.argv) not in (2, 3, 4):
        print(f"Usage: {sys.argv[0]} <email_file> [output_file] [--analyze]")
        print("  email_file: Path to .eml or .msg file")
        print("  output_file: Optional JSON output file (default: stdout)")
        print("  --analyze: Perform detailed structure analysis (debugging)")
        sys.exit(1)

    email_file = sys.argv[1]
    output_file = (
        sys.argv[2] if len(sys.argv) >= 3 and not sys.argv[2].startswith("--") else None
    )
    analyze_mode = "--analyze" in sys.argv

    # Configure logging
    logging.basicConfig(
        level=logging.DEBUG,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )

    try:
        with PhishingEmailParser() as parser:
            if analyze_mode:
                result = parser.analyze_email_structure(email_file)
                print("DETAILED EMAIL STRUCTURE ANALYSIS")
                print("=" * 50)
            else:
                result = parser.parse_email_file(email_file)

            if output_file:
                with open(output_file, "w", encoding="utf-8") as f:
                    json.dump(result, f, indent=2, ensure_ascii=False)
                print(f"Results written to {output_file}")
            else:
                print(json.dumps(result, indent=2, ensure_ascii=False))

    except Exception as e:
        logger.error(f"Error parsing email: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
