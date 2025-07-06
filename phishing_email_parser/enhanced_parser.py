# ============================================================================
# phishing_email_parser/enhanced_parser.py
# ============================================================================
"""
Consolidated enhanced parser with pure structural representation and content consolidation.
Combines the best of both refactored_parser.py and enhanced_parser.py.
"""

import hashlib
import logging
import os
import re
import shutil
import tempfile
import time
from email import policy
from email.message import Message
from email.parser import BytesParser
from pathlib import Path
from typing import List, Optional, Dict, Any, Set

# Core imports
from .core.mime_walker import walk_layers
from .processing.msg_converter import MSGConverter
from .url_processing.processor import UrlProcessor

# Enhanced components
from .data_models import (
    EmailLayer, ParsingResult, StructuralSummary, ConsolidatedContent, 
    LayerReference, create_email_layer, create_parsing_result, 
    create_layer_reference, CarrierAnalysis
)
from .content_consolidator import ContentConsolidator, LayerRelationshipBuilder
from .config_manager import ParserConfiguration, get_default_config
from .exceptions import handle_processing_errors, EmailParsingError, SecurityViolationError, ResourceManagementError
from .interfaces import IParser, IHeaderExtractor, IBodyExtractor, IAttachmentProcessor, IImageProcessor, IURLProcessor, ICarrierDetector, IDeduplicator, IResourceManager, IContentValidator

# Import existing processors
from .processing.attachment_processor import AttachmentProcessor
from .core_extractors import HeaderExtractor, BodyExtractor
from .production_carrier_detector import ProductionCarrierDetector

logger = logging.getLogger(__name__)


class ContentDeduplicator(IDeduplicator):
    """Content deduplicator to prevent processing duplicate content across layers."""
    
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
    
    def mark_as_processed(self, msg: Message, depth: int) -> None:
        """Mark this message as processed to prevent future duplicates."""
        message_id = msg.get("message-id", "").strip()
        if message_id:
            self.processed_message_ids.add(message_id)

        content_sig = self.generate_content_signature(msg)
        self.processed_content_hashes.add(content_sig)
        self.layer_content_signatures[depth] = content_sig

        logger.debug(f"Marked layer {depth} as processed (sig: {content_sig[:8]}...)")


class ResourceManager(IResourceManager):
    """Manages temporary files and resource cleanup."""
    
    def __init__(self, temp_dir: Optional[str] = None):
        self.temp_dir = temp_dir or tempfile.mkdtemp(prefix="phishing_parser_")
        self.created_files: Set[str] = set()
        self.created_dirs: Set[str] = set()
    
    def create_temp_directory(self) -> str:
        """Create temporary directory for processing."""
        temp_path = tempfile.mkdtemp(prefix="parser_", dir=self.temp_dir)
        self.created_dirs.add(temp_path)
        return temp_path
    
    def save_attachment(self, data: bytes, filename: str, output_dir: str) -> str:
        """Save attachment data to disk."""
        os.makedirs(output_dir, exist_ok=True)
        file_path = os.path.join(output_dir, filename)
        
        try:
            with open(file_path, "wb") as f:
                f.write(data)
            self.created_files.add(file_path)
            return file_path
        except Exception as e:
            logger.error(f"Failed to save attachment {filename}: {e}")
            raise ResourceManagementError(f"Failed to save file: {e}")
    
    def cleanup_resources(self) -> None:
        """Clean up temporary resources."""
        try:
            if os.path.exists(self.temp_dir):
                shutil.rmtree(self.temp_dir, ignore_errors=True)
                logger.debug(f"Cleaned up temp directory: {self.temp_dir}")
        except Exception as e:
            logger.warning(f"Failed to cleanup temp directory: {e}")


class ContentValidator(IContentValidator):
    """Validates content against security limits."""
    
    def __init__(self, config: ParserConfiguration):
        self.config = config
    
    def validate_file_size(self, size: int, filename: str) -> None:
        """Validate file size against limits."""
        max_bytes = self.config.security.max_file_size_mb * 1024 * 1024
        if size > max_bytes:
            raise SecurityViolationError(
                f"File '{filename}' exceeds size limit",
                {
                    "filename": filename,
                    "size_mb": size / (1024 * 1024),
                    "max_size_mb": self.config.security.max_file_size_mb
                }
            )
    
    def validate_nesting_depth(self, depth: int) -> None:
        """Validate email nesting depth."""
        if depth > self.config.security.max_nested_depth:
            raise SecurityViolationError(
                f"Email nesting too deep: {depth} exceeds limit",
                {
                    "current_depth": depth,
                    "max_depth": self.config.security.max_nested_depth
                }
            )
    
    def validate_attachment_count(self, count: int) -> None:
        """Validate attachment count."""
        if count > self.config.security.max_attachments:
            raise SecurityViolationError(
                f"Too many attachments: {count} exceeds limit",
                {
                    "attachment_count": count,
                    "max_attachments": self.config.security.max_attachments
                }
            )


class ImageProcessor(IImageProcessor):
    """Image processing with OCR capabilities."""
    
    def __init__(self, config: ParserConfiguration):
        self.config = config
        # Import OCR dependencies only when needed
        self._ocr_available = None
        self._pytesseract = None
        self._PIL_Image = None
    
    def _check_ocr_dependencies(self):
        """Check if OCR dependencies are available."""
        if self._ocr_available is None:
            try:
                import pytesseract
                from PIL import Image
                self._pytesseract = pytesseract
                self._PIL_Image = Image
                self._ocr_available = True
            except ImportError:
                self._ocr_available = False
                logger.warning("OCR libraries not available - cannot process images")
    
    @handle_processing_errors("image extraction with OCR")
    def extract_images_with_ocr(self, msg: Message, output_dir: str) -> List[Dict[str, Any]]:
        """Extract images and perform OCR."""
        self._check_ocr_dependencies()
        
        images = []
        image_idx = 1

        for part in msg.walk():
            ctype = part.get_content_type()
            if ctype.startswith("image/"):
                content_id = part.get("Content-ID")
                filename = part.get_filename() or f"image_{image_idx}.png"

                # Strip null terminators and other problematic characters
                if filename:
                    filename = filename.rstrip("\x00").strip()

                # Clean content type
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
                    ocr_text = self.perform_ocr(payload, filename)

                # Clean content_id of null bytes too
                clean_content_id = None
                if content_id:
                    clean_content_id = content_id.rstrip("\x00").strip()

                images.append({
                    "index": image_idx,
                    "filename": filename,
                    "disk_path": out_path,
                    "content_id": clean_content_id,
                    "content_type": ctype,
                    "ocr_text": ocr_text,
                    "size": len(payload) if payload else 0,
                })
                image_idx += 1

        return images
    
    def perform_ocr(self, image_data: bytes, filename: str) -> Optional[str]:
        """Perform OCR on image data."""
        if not self._ocr_available or not self.config.ocr.enabled:
            return None
        
        try:
            from io import BytesIO
            
            img = self._PIL_Image.open(BytesIO(image_data))
            img = img.convert("L")  # Convert to grayscale
            
            ocr_text = self._pytesseract.image_to_string(
                img, 
                config=self.config.ocr.config_options
            )
            
            if ocr_text:
                ocr_text = ocr_text.strip()
                # Limit text length for performance
                if len(ocr_text) > self.config.processing.max_ocr_text_length:
                    ocr_text = ocr_text[:self.config.processing.max_ocr_text_length] + "..."
                return ocr_text
                
        except Exception as e:
            logger.warning(f"Error performing OCR on {filename}: {e}")
            
        return None


class URLProcessorWrapper(IURLProcessor):
    """Wrapper for existing URL processor to implement interface."""
    
    def __init__(self, config: ParserConfiguration):
        self.config = config
    
    def extract_all_urls(self, body_data, attachments: List[Any], images: List[Dict]) -> List[Dict]:
        """Extract and process URLs from body, attachments, and images."""
        all_urls = []

        # Extract URLs from email body
        body_text = body_data.get("final_text", "") if isinstance(body_data, dict) else body_data.final_text
        if body_text:
            urls = self._extract_urls_from_text(body_text)
            all_urls.extend(urls)

        # Extract URLs from HTML body if available  
        html_text = body_data.get("html_text", "") if isinstance(body_data, dict) else body_data.html_text
        if html_text:
            html_urls = self._extract_urls_from_html(html_text)
            all_urls.extend(html_urls)

        # Extract URLs from attachments
        attachment_dicts = [att.to_dict() if hasattr(att, 'to_dict') else att for att in attachments]
        attachment_urls = UrlProcessor.extract_urls_from_attachments(attachment_dicts)
        all_urls.extend(attachment_urls)

        # Extract URLs from OCR text in images
        for image in images:
            if image.get("ocr_text"):
                image_urls = self._extract_urls_from_text(image["ocr_text"])
                all_urls.extend(image_urls)

        # Process and deduplicate URLs
        processed_urls = UrlProcessor.process_urls(all_urls)
        return processed_urls
    
    def process_urls(self, urls: List[str]) -> List[Dict]:
        """Process and deduplicate URLs."""
        return UrlProcessor.process_urls(urls)
    
    def expand_urls(self, urls: List[Dict]) -> List[Dict]:
        """Expand shortened URLs."""
        if self.config.url_processing.enable_expansion:
            return UrlProcessor.batch_expand_urls(urls, delay=self.config.url_processing.batch_delay)
        return urls
    
    def _extract_urls_from_text(self, text: str) -> List[str]:
        """Extract URLs from plain text."""
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


class BodyContentSeparator:
    """Handles separation of carrier wrapper content from quoted/forwarded content."""
    
    @staticmethod
    def analyze_carrier_content(body: Dict[str, Any], is_carrier: bool) -> Dict[str, Any]:
        """Analyze carrier email body to separate wrapper from quoted content."""
        if not is_carrier:
            return body
        
        final_text = body.get('final_text', '')
        if not final_text:
            return body
        
        # Detect forwarding patterns
        wrapper_indicators = [
            r"-----Original Message-----",
            r"Begin forwarded message:",
            r"^From:\s*.+@.+",
            r"^Sent:\s*.+",
            r"forwarded for (analysis|review)",
            r"please (analyze|check|review)",
            r"flagged as suspicious"
        ]
        
        wrapper_content = ""
        quoted_content_start = -1
        
        lines = final_text.split('\n')
        for i, line in enumerate(lines):
            for pattern in wrapper_indicators:
                if re.search(pattern, line, re.IGNORECASE | re.MULTILINE):
                    if "original message" in line.lower() or "forwarded message" in line.lower():
                        quoted_content_start = i
                        wrapper_content = '\n'.join(lines[:i]).strip()
                        break
            if quoted_content_start >= 0:
                break
        
        # If we found a clear separation, provide both parts
        if quoted_content_start >= 0 and wrapper_content:
            body['wrapper_content'] = wrapper_content
            body['quoted_content_preview'] = '\n'.join(lines[quoted_content_start:quoted_content_start+5])
            body['content_summary'] = f"Carrier email with {len(wrapper_content)} chars wrapper content"
        else:
            # No clear separation found, treat as unified content
            body['content_summary'] = f"Carrier email with {len(final_text)} chars total content"
        
        return body


class EnhancedProductionParser(IParser):
    """
    Enhanced parser that provides pure structural representation.
    Combines the best components from both refactored and enhanced parsers.
    """
    
    def __init__(
        self,
        header_extractor: IHeaderExtractor,
        body_extractor: IBodyExtractor,
        attachment_processor: IAttachmentProcessor,
        image_processor: IImageProcessor,
        url_processor: IURLProcessor,
        carrier_detector: ICarrierDetector,
        deduplicator: IDeduplicator,
        resource_manager: IResourceManager,
        content_validator: IContentValidator,
        config: ParserConfiguration,
        msg_converter: Optional[MSGConverter] = None
    ):
        """Initialize enhanced parser with all dependencies."""
        self.header_extractor = header_extractor
        self.body_extractor = body_extractor
        self.attachment_processor = attachment_processor
        self.image_processor = image_processor
        self.url_processor = url_processor
        self.carrier_detector = carrier_detector
        self.deduplicator = deduplicator
        self.resource_manager = resource_manager
        self.content_validator = content_validator
        self.config = config
        self.msg_converter = msg_converter or MSGConverter()
        
        # Add enhanced components
        self.content_consolidator = ContentConsolidator()
        self.relationship_builder = LayerRelationshipBuilder()
        self.body_separator = BodyContentSeparator()
        
        # Processing metadata
        self.processing_start_time = None
        self.layers_processed = 0
    
    def __enter__(self):
        """Context manager entry."""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit with cleanup."""
        self.resource_manager.cleanup_resources()
    
    @handle_processing_errors("enhanced email file parsing")
    def parse_email_file(self, email_path: str) -> ParsingResult:
        """Parse email file with enhanced structural representation."""
        self.processing_start_time = time.time()
        
        email_path = Path(email_path)
        
        if not email_path.exists():
            raise EmailParsingError(f"Email file not found: {email_path}")

        if email_path.suffix.lower() not in {".eml", ".msg"}:
            raise EmailParsingError(
                "Unsupported email file type",
                {"file_path": str(email_path), "supported_types": [".eml", ".msg"]}
            )

        # Validate file size
        file_size = email_path.stat().st_size
        self.content_validator.validate_file_size(file_size, email_path.name)

        # Convert .msg to .eml if needed
        if email_path.suffix.lower() == ".msg":
            temp_dir = self.resource_manager.create_temp_directory()
            eml_path = self.msg_converter.convert_msg_to_eml(str(email_path), temp_dir)
            email_path = Path(eml_path)

        # Parse the email
        with open(email_path, "rb") as f:
            msg = BytesParser(policy=policy.default).parse(f)

        return self.parse_message(msg, str(email_path.parent))
    
    @handle_processing_errors("enhanced message parsing")
    def parse_message(self, msg: Message, output_dir: str) -> ParsingResult:
        """Parse message with enhanced structural representation."""
        logger.info("Starting enhanced message parsing with pure structural representation")
        
        enhanced_layers = []
        
        # Walk through all message layers using existing MIME walker
        for depth, layer_msg, vendor_tag in walk_layers(msg):
            # Validate nesting depth
            self.content_validator.validate_nesting_depth(depth)
            
            # Check for duplicate content
            if self.deduplicator.is_duplicate_content(layer_msg, depth):
                logger.info(f"Skipping duplicate content at layer {depth}")
                continue

            # Mark as processed before parsing
            self.deduplicator.mark_as_processed(layer_msg, depth)

            enhanced_layer = self._parse_single_enhanced_layer(
                layer_msg, depth, vendor_tag, output_dir
            )
            enhanced_layers.append(enhanced_layer)
            
            self.layers_processed += 1

        # Process attachment-based nested emails
        nested_layers = self._process_nested_email_attachments_enhanced(
            enhanced_layers, output_dir
        )
        enhanced_layers.extend(nested_layers)

        # Build layer relationships
        self.relationship_builder.build_layer_relationships(enhanced_layers)

        # Consolidate all content with provenance tracking
        consolidated_content = self.content_consolidator.consolidate_all_content(enhanced_layers)

        # Generate structural summary
        structural_summary = self._generate_structural_summary(enhanced_layers)

        # Generate nesting chain description
        nesting_chain = self._generate_nesting_chain(enhanced_layers)
        structural_summary.nesting_chain = nesting_chain

        # Create carrier detection summary (pure detection, no analysis)
        carrier_analysis = self._generate_carrier_analysis(enhanced_layers)

        # Generate final enhanced result
        processing_time = time.time() - self.processing_start_time if self.processing_start_time else 0
        
        result = create_parsing_result(
            layers=enhanced_layers,
            consolidated_content=consolidated_content,
            structural_summary=structural_summary,
            carrier_analysis=carrier_analysis,
            processing_metadata={
                "processing_time_seconds": processing_time,
                "layers_processed": self.layers_processed,
                "architecture_version": "2.0_enhanced_consolidated"
            }
        )
        
        logger.info(
            f"Enhanced parsing complete: {len(enhanced_layers)} layers, "
            f"{len(consolidated_content.all_urls)} URLs, "
            f"{len(consolidated_content.all_attachments)} attachments, "
            f"{processing_time:.2f}s"
        )
        
        return result
    
    def _parse_single_enhanced_layer(
        self, msg: Message, depth: int, vendor_tag: Optional[str], output_dir: str
    ) -> EmailLayer:
        """Parse a single message layer with enhanced structure."""
        logger.debug(f"Parsing enhanced layer {depth}, vendor: {vendor_tag}")

        # Enhanced carrier detection
        is_carrier, enhanced_vendor_tag, carrier_details = self.carrier_detector.detect_carrier(msg)
        final_vendor_tag = enhanced_vendor_tag or vendor_tag

        # Extract headers and body using existing extractors
        headers = self.header_extractor.extract_headers(msg)
        body_data = self.body_extractor.extract_body(msg)

        # Convert body to dict format for analysis
        body_dict = body_data.to_dict()
        
        # Analyze carrier content separation
        enhanced_body_dict = self.body_separator.analyze_carrier_content(body_dict, is_carrier)
        
        # Reconstruct body object with enhanced data
        from .data_models import create_email_body
        enhanced_body = create_email_body(**enhanced_body_dict)

        # Process attachments using existing processor
        attachment_results = self.attachment_processor.process_attachments(msg, output_dir)
        
        # Validate attachment count
        self.content_validator.validate_attachment_count(len(attachment_results))

        # Extract images with OCR using existing processor
        images = self.image_processor.extract_images_with_ocr(msg, output_dir)

        # Extract and process URLs using existing processor
        url_results = self.url_processor.extract_all_urls(enhanced_body, attachment_results, images)

        # Create enhanced email layer
        enhanced_layer = create_email_layer(
            layer_depth=depth,
            is_carrier_email=is_carrier,
            headers=headers,
            body=enhanced_body,
            carrier_vendor=final_vendor_tag,
            carrier_details=carrier_details,
            attachments=attachment_results,
            images=images,
            urls=url_results
        )

        # Log layer processing
        self._log_enhanced_layer_processing(enhanced_layer)
        
        return enhanced_layer
    
    def _process_nested_email_attachments_enhanced(
        self, existing_layers: List[EmailLayer], output_dir: str
    ) -> List[EmailLayer]:
        """Process nested email attachments with enhanced tracking."""
        nested_layers = []

        for layer in existing_layers:
            current_depth = layer.layer_depth
            attachments = layer.attachments

            for attachment in attachments:
                # Handle both dict and object formats
                attachment_dict = attachment.to_dict() if hasattr(attachment, 'to_dict') else attachment
                
                # Only process attachment-based nested emails
                if (
                    attachment_dict.get("is_nested_email", False)
                    and attachment_dict.get("content_type") != "message/rfc822"
                ):
                    logger.info(f"Processing nested email: {attachment_dict['filename']}")

                    try:
                        nested_email_layers = self._parse_nested_email_attachment_enhanced(
                            attachment_dict, current_depth + 1, output_dir, layer
                        )
                        nested_layers.extend(nested_email_layers)

                    except Exception as e:
                        logger.error(f"Error parsing nested email {attachment_dict['filename']}: {e}")
                        attachment_dict["nested_parse_error"] = str(e)

        return nested_layers
    
    def _parse_nested_email_attachment_enhanced(
        self, attachment: Dict, base_depth: int, output_dir: str, parent_layer: EmailLayer
    ) -> List[EmailLayer]:
        """Parse a nested email attachment with enhanced relationship tracking."""
        disk_path = attachment.get("disk_path")
        if not disk_path or not Path(disk_path).exists():
            logger.warning(f"Nested email file not found: {disk_path}")
            return []

        try:
            # Load and parse the nested email file
            with open(disk_path, "rb") as f:
                nested_msg = BytesParser(policy=policy.default).parse(f)

            # Check if this content is a duplicate
            if self.deduplicator.is_duplicate_content(nested_msg, base_depth):
                logger.info(f"Skipping duplicate nested email: {attachment['filename']}")
                return []

            nested_layers = []

            # Walk through the nested email
            for depth, msg, vendor_tag in walk_layers(nested_msg):
                adjusted_depth = base_depth + depth

                # Check for duplicates at adjusted depth
                if self.deduplicator.is_duplicate_content(msg, adjusted_depth):
                    logger.debug(f"Skipping duplicate layer at depth {adjusted_depth}")
                    continue

                # Mark as processed
                self.deduplicator.mark_as_processed(msg, adjusted_depth)

                enhanced_layer = self._parse_single_enhanced_layer(
                    msg, adjusted_depth, vendor_tag, output_dir
                )

                # Add enhanced parent reference
                parent_ref = create_layer_reference(
                    layer_depth=parent_layer.layer_depth,
                    relationship="attached_to_layer",
                    via_attachment=attachment["filename"],
                    via_mime_type=attachment.get("content_type")
                )
                enhanced_layer.parent_reference = parent_ref

                nested_layers.append(enhanced_layer)

            return nested_layers

        except Exception as e:
            logger.error(f"Error parsing nested email file {disk_path}: {e}")
            raise
    
    def _generate_structural_summary(self, layers: List[EmailLayer]) -> StructuralSummary:
        """Generate structural summary without analytical judgments."""
        
        layer_types = []
        for layer in layers:
            layer_type = {
                "layer": layer.layer_depth,
                "type": "carrier" if layer.is_carrier_email else "content",
                "vendor": layer.carrier_vendor,
                "has_nested_refs": len(layer.nested_email_references) > 0,
                "has_parent_ref": layer.parent_reference is not None,
                "content_summary": getattr(layer.body, 'content_summary', None)
            }
            layer_types.append(layer_type)
        
        return StructuralSummary(
            total_layers=len(layers),
            total_attachments=sum(len(layer.attachments) for layer in layers),
            total_images=sum(len(layer.images) for layer in layers),
            total_urls=sum(len(layer.urls) for layer in layers),
            has_nested_emails=any(layer.layer_depth > 0 for layer in layers),
            layer_types=layer_types
        )
    
    def _generate_nesting_chain(self, layers: List[EmailLayer]) -> List[str]:
        """Generate a description of the nesting chain."""
        chain = []
        
        for layer in sorted(layers, key=lambda l: l.layer_depth):
            if layer.is_carrier_email:
                chain.append(f"carrier_email_layer_{layer.layer_depth}")
            elif layer.parent_reference and layer.parent_reference.via_attachment:
                filename = layer.parent_reference.via_attachment
                if filename.lower().endswith('.eml'):
                    chain.append(f"nested_eml_layer_{layer.layer_depth}")
                elif filename.lower().endswith(('.xlsx', '.xls')):
                    chain.append(f"excel_attachment_layer_{layer.layer_depth}")
                else:
                    chain.append(f"attachment_{filename}_layer_{layer.layer_depth}")
            else:
                chain.append(f"content_layer_{layer.layer_depth}")
        
        return chain
    
    def _generate_carrier_analysis(self, layers: List[EmailLayer]) -> CarrierAnalysis:
        """Generate pure carrier detection analysis without judgments."""
        
        detected_carriers = []
        non_carrier_layers = []
        
        for layer in layers:
            if layer.is_carrier_email:
                carrier_info = {
                    "layer": layer.layer_depth,
                    "vendor": layer.carrier_vendor,
                    "detection_summary": layer.carrier_summary
                }
                
                if layer.carrier_details:
                    carrier_info.update({
                        "type": layer.carrier_details.carrier_type.value,
                        "confidence": layer.carrier_details.confidence,
                        "detection_method": layer.carrier_details.detection_method
                    })
                
                detected_carriers.append(carrier_info)
            else:
                non_carrier_layers.append(layer.layer_depth)
        
        return CarrierAnalysis(
            total_carriers=len(detected_carriers),
            carrier_details=detected_carriers,
            non_carrier_layers=non_carrier_layers
        )
    
    def _log_enhanced_layer_processing(self, layer: EmailLayer) -> None:
        """Log enhanced layer processing details."""
        depth = layer.layer_depth
        subject = layer.headers.subject[:50] if layer.headers.subject else "No Subject"
        from_addr = layer.headers.from_addr[:30] if layer.headers.from_addr else "No From"

        carrier_info = ""
        if layer.is_carrier_email:
            carrier_info = f" [CARRIER: {layer.carrier_vendor}]"

        logger.info(f"Enhanced Layer {depth}: '{subject}' from '{from_addr}'{carrier_info}")

        content_summary = getattr(layer.body, 'content_summary', None)
        if content_summary:
            logger.debug(f"  Content: {content_summary}")

        if layer.parent_reference:
            parent_info = layer.parent_reference
            logger.info(f"  ↳ Child of layer {parent_info.layer_depth} via {parent_info.via_attachment}")

        if layer.nested_email_references:
            for ref in layer.nested_email_references:
                logger.info(f"  ↳ Contains layer {ref.layer_depth} via {ref.via_attachment}")


# Factory function for creating enhanced parser
def create_enhanced_parser(
    config: Optional[ParserConfiguration] = None,
    temp_dir: Optional[str] = None
) -> EnhancedProductionParser:
    """
    Factory function to create fully configured enhanced parser.
    Combines the best of both parsers with enhanced capabilities.
    """
    if config is None:
        config = get_default_config()
    
    # Create resource manager
    resource_manager = ResourceManager(temp_dir)
    
    # Create all dependencies
    header_extractor = HeaderExtractor()
    body_extractor = BodyExtractor(aggressive_cleaning=config.processing.aggressive_html_cleaning)
    attachment_processor = AttachmentProcessor(resource_manager.temp_dir, config)
    image_processor = ImageProcessor(config)
    url_processor = URLProcessorWrapper(config)
    carrier_detector = ProductionCarrierDetector()
    deduplicator = ContentDeduplicator()
    content_validator = ContentValidator(config)
    
    return EnhancedProductionParser(
        header_extractor=header_extractor,
        body_extractor=body_extractor,
        attachment_processor=attachment_processor,
        image_processor=image_processor,
        url_processor=url_processor,
        carrier_detector=carrier_detector,
        deduplicator=deduplicator,
        resource_manager=resource_manager,
        content_validator=content_validator,
        config=config
    )