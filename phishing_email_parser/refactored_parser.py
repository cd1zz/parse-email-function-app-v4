# ============================================================================
# phishing_email_parser/refactored_parser.py
# ============================================================================
"""
Production-ready email parser with dependency injection and SOLID principles.

PRESERVES: ALL functionality from main_parser.py including:
- Email parsing (.eml and .msg support)
- Nested email detection and processing  
- Attachment processing with Excel image extraction
- URL extraction from all sources
- Content deduplication
- OCR capabilities
- Carrier detection (both security appliances and user submissions)

ENHANCES: 
- SOLID architecture with dependency injection
- Comprehensive error handling
- Resource management
- Type safety throughout
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
from typing import Dict, Any, List, Optional, Set

# Core imports - using existing functionality
from .core.mime_walker import walk_layers
from .processing.msg_converter import MSGConverter
from .url_processing.processor import UrlProcessor

# New architecture imports
from .interfaces import (
    IParser, IHeaderExtractor, IBodyExtractor, IAttachmentProcessor,
    IImageProcessor, IURLProcessor, ICarrierDetector, IDeduplicator,
    IResourceManager, IContentValidator
)
from .data_models import (
    ParsingResult, EmailLayer, ProcessingSummary, CarrierAnalysis,
    create_parsing_result, create_email_layer, AnalysisPriority
)
from .config_manager import ParserConfiguration, get_default_config
from .exceptions import (
    handle_processing_errors, EmailParsingError, AttachmentProcessingError,
    SecurityViolationError, ResourceManagementError
)

# Import existing processors to preserve functionality
from .processing.attachment_processor import AttachmentProcessor
from .core_extractors import HeaderExtractor, BodyExtractor
from .production_carrier_detector import ProductionCarrierDetector

logger = logging.getLogger(__name__)


class ContentDeduplicator(IDeduplicator):
    """
    Content deduplicator to prevent processing duplicate content across layers.
    
    PRESERVES: All original deduplication logic from EmailContentDeduplicator
    ENHANCES: Implements interface and adds better logging
    """
    
    def __init__(self):
        self.processed_content_hashes: Set[str] = set()
        self.processed_message_ids: Set[str] = set()
        self.layer_content_signatures: Dict[int, str] = {}
    
    def generate_content_signature(self, msg: Message) -> str:
        """
        Generate a unique signature for email content.
        
        PRESERVES: Exact logic from original EmailContentDeduplicator
        """
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
        """
        Check if this message content has already been processed.
        
        PRESERVES: Exact logic from original EmailContentDeduplicator
        """
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
        """
        Mark this message as processed to prevent future duplicates.
        
        PRESERVES: Exact logic from original EmailContentDeduplicator
        """
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
    """
    Image processing with OCR capabilities.
    
    PRESERVES: All original OCR functionality from _extract_images_with_ocr
    """
    
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
        """
        Extract images and perform OCR.
        
        PRESERVES: Complete logic from original _extract_images_with_ocr method
        """
        self._check_ocr_dependencies()
        
        images = []
        image_idx = 1

        for part in msg.walk():
            ctype = part.get_content_type()
            if ctype.startswith("image/"):
                content_id = part.get("Content-ID")
                filename = part.get_filename() or f"image_{image_idx}.png"

                # PRESERVED: Strip null terminators and other problematic characters
                if filename:
                    filename = filename.rstrip("\x00").strip()

                # PRESERVED: Clean content type
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

                # PRESERVED: Clean content_id of null bytes too
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
        """
        Perform OCR on image data.
        
        PRESERVES: Original OCR logic
        """
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
    """
    Wrapper for existing URL processor to implement interface.
    
    PRESERVES: All original URL processing functionality
    """
    
    def __init__(self, config: ParserConfiguration):
        self.config = config
    
    def extract_all_urls(self, body_data, attachments: List[Any], images: List[Dict]) -> List[Dict]:
        """
        Extract and process URLs from body, attachments, and images.
        
        PRESERVES: Complete logic from original _extract_all_urls method
        """
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
        """Extract URLs from plain text (preserved from original)."""
        url_pattern = re.compile(
            r'https?://[^\s<>"{}|\\^`\[\]]+|www\.[^\s<>"{}|\\^`\[\]]+', re.IGNORECASE
        )
        urls = url_pattern.findall(text)
        return [url.rstrip(".,;:!?)]}") for url in urls]
    
    def _extract_urls_from_html(self, html_text: str) -> List[str]:
        """Extract URLs from HTML content (preserved from original)."""
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


class ProductionEmailParser(IParser):
    """
    Production-ready email parser with dependency injection.
    
    PRESERVES: ALL functionality from PhishingEmailParser class
    ENHANCES: SOLID architecture, dependency injection, comprehensive error handling
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
        """Initialize parser with injected dependencies."""
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
        
        # Processing metadata
        self.processing_start_time = None
        self.layers_processed = 0
    
    def __enter__(self):
        """Context manager entry."""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit with cleanup."""
        self.resource_manager.cleanup_resources()
    
    @handle_processing_errors("email file parsing")
    def parse_email_file(self, email_path: str) -> ParsingResult:
        """
        Parse an email file (.eml or .msg) and return structured data.
        
        PRESERVES: Complete logic from original parse_email_file method
        ENHANCES: Uses dependency injection and structured result
        """
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

        # Convert .msg to .eml if needed (preserved logic)
        if email_path.suffix.lower() == ".msg":
            temp_dir = self.resource_manager.create_temp_directory()
            eml_path = self.msg_converter.convert_msg_to_eml(str(email_path), temp_dir)
            email_path = Path(eml_path)

        # Parse the email
        with open(email_path, "rb") as f:
            msg = BytesParser(policy=policy.default).parse(f)

        try:
            return self.parse_message(msg, str(email_path.parent))
        except AttachmentProcessingError as exc:
            raise EmailParsingError(f"Attachment processing failed: {exc}") from exc
    
    @handle_processing_errors("message parsing")
    def parse_message(self, msg: Message, output_dir: str) -> ParsingResult:
        """
        Parse an email message object.
        
        PRESERVES: Complete logic from original _parse_message_structure method
        ENHANCES: Structured return and dependency injection
        """
        logger.info("Starting message parsing with enhanced architecture")
        
        result_layers = []
        carrier_analysis = CarrierAnalysis()
        
        # Walk through all message layers using existing MIME walker (PRESERVED)
        for depth, layer_msg, vendor_tag in walk_layers(msg):
            # Validate nesting depth
            self.content_validator.validate_nesting_depth(depth)
            
            # Check for duplicate content
            if self.deduplicator.is_duplicate_content(layer_msg, depth):
                logger.info(f"Skipping duplicate content at layer {depth}")
                continue

            # Mark as processed before parsing
            self.deduplicator.mark_as_processed(layer_msg, depth)

            layer_data = self._parse_single_layer(layer_msg, depth, vendor_tag, output_dir)
            result_layers.append(layer_data)
            
            # Update carrier analysis
            self._update_carrier_analysis(layer_data, carrier_analysis)
            
            self.layers_processed += 1

        # Process attachment-based nested emails (PRESERVED functionality)
        nested_layers = self._process_nested_email_attachments(result_layers, output_dir)
        result_layers.extend(nested_layers)

        # Generate final result
        processing_time = time.time() - self.processing_start_time if self.processing_start_time else 0
        
        result = create_parsing_result(
            message_layers=result_layers,
            carrier_analysis=carrier_analysis,
            processing_metadata={
                "processing_time_seconds": processing_time,
                "layers_processed": self.layers_processed,
                "architecture_version": "2.0_solid_di"
            }
        )
        
        # Generate analysis recommendations
        self._generate_analysis_recommendations(result)
        
        logger.info(f"Parsing complete: {len(result_layers)} layers, {processing_time:.2f}s")
        
        return result
    
    def _parse_single_layer(
        self, msg: Message, depth: int, vendor_tag: Optional[str], output_dir: str
    ) -> EmailLayer:
        """
        Parse a single message layer.
        
        PRESERVES: Complete logic from original _parse_single_layer method
        ENHANCES: Uses dependency injection and structured data models
        """
        logger.debug(f"Parsing layer {depth}, vendor: {vendor_tag}")

        # Enhanced carrier detection
        is_carrier, enhanced_vendor_tag, carrier_details = self.carrier_detector.detect_carrier(msg)
        final_vendor_tag = enhanced_vendor_tag or vendor_tag
        
        # Determine analysis priority
        analysis_priority = AnalysisPriority.LOW if is_carrier else AnalysisPriority.HIGH
        carrier_summary = self.carrier_detector.format_carrier_summary(final_vendor_tag, carrier_details)

        # Extract headers and body using injected extractors
        headers = self.header_extractor.extract_headers(msg)
        body = self.body_extractor.extract_body(msg)

        # Process attachments using injected processor
        attachment_results = self.attachment_processor.process_attachments(msg, output_dir)
        
        # Validate attachment count
        self.content_validator.validate_attachment_count(len(attachment_results))
        
        # Convert attachment results to proper format
        attachments = []
        for att_dict in attachment_results:
            # Handle both dict and AttachmentInfo objects
            if hasattr(att_dict, 'to_dict'):
                attachments.append(att_dict)
            else:
                # Convert dict to structured format if needed
                attachments.append(att_dict)

        # Extract images with OCR using injected processor
        images = self.image_processor.extract_images_with_ocr(msg, output_dir)

        # Extract and process URLs using injected processor
        url_results = self.url_processor.extract_all_urls(body, attachments, images)

        # Create structured email layer
        layer = create_email_layer(
            layer_depth=depth,
            is_carrier_email=is_carrier,
            headers=headers,
            body=body,
            carrier_vendor=final_vendor_tag,
            carrier_details=carrier_details,
            analysis_priority=analysis_priority,
            carrier_summary=carrier_summary,
            attachments=attachments,
            images=images,
            urls=url_results
        )

        # Log layer processing
        self._log_layer_processing(layer)
        
        return layer
    
    def _process_nested_email_attachments(
        self, existing_layers: List[EmailLayer], output_dir: str
    ) -> List[EmailLayer]:
        """
        Process nested email attachments.
        
        PRESERVES: Logic from _process_nested_email_attachments_dedupe method
        """
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
                        nested_email_layers = self._parse_nested_email_attachment(
                            attachment_dict, current_depth + 1, output_dir
                        )
                        nested_layers.extend(nested_email_layers)

                    except Exception as e:
                        logger.error(f"Error parsing nested email {attachment_dict['filename']}: {e}")
                        attachment_dict["nested_parse_error"] = str(e)

        return nested_layers
    
    def _parse_nested_email_attachment(
        self, attachment: Dict, base_depth: int, output_dir: str
    ) -> List[EmailLayer]:
        """Parse a nested email attachment."""
        disk_path = attachment.get("disk_path")
        if not disk_path or not os.path.exists(disk_path):
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

                layer_data = self._parse_single_layer(msg, adjusted_depth, vendor_tag, output_dir)

                # Add metadata showing this came from a nested attachment
                layer_data.parent_attachment = {
                    "filename": attachment["filename"],
                    "parent_layer_depth": base_depth - 1,
                    "attachment_index": attachment.get("index"),
                }

                nested_layers.append(layer_data)

            return nested_layers

        except Exception as e:
            logger.error(f"Error parsing nested email file {disk_path}: {e}")
            raise
    
    def _update_carrier_analysis(self, layer_data: EmailLayer, carrier_analysis: CarrierAnalysis) -> None:
        """Update carrier analysis with information from a processed layer."""
        if not layer_data.is_carrier_email:
            return

        carrier_analysis.total_carriers += 1

        if layer_data.carrier_details:
            if layer_data.carrier_details.carrier_type.value == "security_appliance":
                carrier_analysis.security_appliances.append({
                    "layer": layer_data.layer_depth,
                    "vendor": layer_data.carrier_vendor,
                    "detection_method": layer_data.carrier_details.detection_method,
                })
            else:  # User submission
                evidence = layer_data.carrier_details.evidence
                carrier_analysis.user_submissions.append({
                    "layer": layer_data.layer_depth,
                    "submission_type": layer_data.carrier_vendor,
                    "confidence_score": evidence.confidence_score if evidence else 0,
                    "evidence_count": len(evidence.structural_indicators) if evidence else 0,
                    "summary": layer_data.carrier_summary,
                })
    
    def _generate_analysis_recommendations(self, result: ParsingResult) -> None:
        """Generate LLM analysis recommendations based on carrier detection."""
        recommendations = []
        high_priority_layers = []

        for layer in result.message_layers:
            if layer.analysis_priority == AnalysisPriority.HIGH:
                high_priority_layers.append(layer.layer_depth)

        if high_priority_layers:
            recommendations.append({
                "priority": "HIGH",
                "action": "focus_analysis",
                "layers": high_priority_layers,
                "reason": "These layers contain non-carrier content and should be the primary focus of threat analysis",
            })

        if result.carrier_analysis.user_submissions:
            recommendations.append({
                "priority": "MEDIUM",
                "action": "validate_submission_context",
                "reason": "User-submitted carriers detected - validate internal submission workflow and sender legitimacy",
            })

        if result.carrier_analysis.security_appliances:
            recommendations.append({
                "priority": "LOW",
                "action": "review_security_processing",
                "reason": "Security appliance processing detected - review why email reached analysis",
            })

        result.carrier_analysis.analysis_recommendations = recommendations
    
    def _log_layer_processing(self, layer_data: EmailLayer) -> None:
        """Log layer processing details for debugging."""
        depth = layer_data.layer_depth
        subject = layer_data.headers.subject[:50] if layer_data.headers.subject else "No Subject"
        from_addr = layer_data.headers.from_addr[:30] if layer_data.headers.from_addr else "No From"

        carrier_info = ""
        if layer_data.is_carrier_email:
            carrier_info = f" [{layer_data.carrier_vendor} - {layer_data.analysis_priority.value}]"

        logger.info(f"Layer {depth}: '{subject}' from '{from_addr}'{carrier_info}")

        if layer_data.parent_attachment:
            parent_info = layer_data.parent_attachment
            logger.info(f"  ↳ From attachment: {parent_info['filename']}")


# Factory function for creating complete parser with dependency injection
def create_production_parser(
    config: Optional[ParserConfiguration] = None,
    temp_dir: Optional[str] = None
) -> ProductionEmailParser:
    """
    Factory function to create fully configured production parser.
    
    This preserves the simple interface while using dependency injection internally.
    """
    if config is None:
        config = get_default_config()
    
    # Create resource manager
    resource_manager = ResourceManager(temp_dir)
    
    # Create all dependencies
    header_extractor = HeaderExtractor()
    body_extractor = BodyExtractor(aggressive_cleaning=config.processing.aggressive_html_cleaning)
    
    # Use existing AttachmentProcessor for compatibility
    attachment_processor = AttachmentProcessor(resource_manager.temp_dir, config)
    
    image_processor = ImageProcessor(config)
    url_processor = URLProcessorWrapper(config)
    carrier_detector = ProductionCarrierDetector()
    deduplicator = ContentDeduplicator()
    content_validator = ContentValidator(config)
    
    return ProductionEmailParser(
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