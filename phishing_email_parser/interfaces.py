# ============================================================================
# phishing_email_parser/interfaces.py
# ============================================================================
"""
Abstract interfaces for phishing email parser components.
Implements dependency inversion principle with clear contracts for all components.
"""

from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional, Protocol, runtime_checkable
from email.message import Message
from pathlib import Path

from .data_models import (
    EmailHeaders, EmailBody, AttachmentInfo, ImageInfo, URLInfo,
    CarrierDetails, EmailLayer, ParsingResult
)
from .config_manager import ParserConfiguration


# ============================================================================
# Core Processing Interfaces
# ============================================================================

class IHeaderExtractor(ABC):
    """Interface for email header extraction."""
    
    @abstractmethod
    def extract_headers(self, msg: Message) -> EmailHeaders:
        """Extract and clean email headers from message."""
        pass
    
    @abstractmethod
    def clean_header_value(self, value: Any) -> str:
        """Clean individual header values."""
        pass


class IBodyExtractor(ABC):
    """Interface for email body content extraction."""
    
    @abstractmethod
    def extract_body(self, msg: Message) -> EmailBody:
        """Extract and process email body content."""
        pass
    
    @abstractmethod
    def get_content_safe(self, part: Message) -> str:
        """Safely extract content from email part."""
        pass


class IAttachmentProcessor(ABC):
    """Interface for attachment processing."""
    
    @abstractmethod
    def process_attachments(self, msg: Message, output_dir: str) -> List[AttachmentInfo]:
        """Process all attachments in an email message."""
        pass
    
    @abstractmethod
    def extract_text_from_attachment(self, payload: bytes, content_type: str, filename: str) -> Optional[str]:
        """Extract text content from attachment based on content type."""
        pass


class ITextExtractor(ABC):
    """Interface for text extraction from various file types."""
    
    @abstractmethod
    def extract_from_pdf(self, pdf_data: bytes) -> str:
        """Extract text from PDF data."""
        pass
    
    @abstractmethod
    def extract_from_excel(self, excel_data: bytes, output_dir: Optional[str] = None) -> str:
        """Extract text from Excel data."""
        pass
    
    @abstractmethod
    def extract_from_word(self, word_data: bytes) -> str:
        """Extract text from Word document data."""
        pass


class IImageProcessor(ABC):
    """Interface for image processing and OCR."""
    
    @abstractmethod
    def extract_images_with_ocr(self, msg: Message, output_dir: str) -> List[ImageInfo]:
        """Extract images and perform OCR."""
        pass
    
    @abstractmethod
    def perform_ocr(self, image_data: bytes, filename: str) -> Optional[str]:
        """Perform OCR on image data."""
        pass


class IURLProcessor(ABC):
    """Interface for URL processing and extraction."""
    
    @abstractmethod
    def extract_all_urls(self, body_data: EmailBody, attachments: List[AttachmentInfo], 
                        images: List[ImageInfo]) -> List[URLInfo]:
        """Extract and process URLs from all sources."""
        pass
    
    @abstractmethod
    def process_urls(self, urls: List[str]) -> List[URLInfo]:
        """Process and deduplicate URLs."""
        pass
    
    @abstractmethod
    def expand_urls(self, urls: List[URLInfo]) -> List[URLInfo]:
        """Expand shortened URLs."""
        pass


class ICarrierDetector(ABC):
    """Interface for carrier email detection."""
    
    @abstractmethod
    def detect_carrier(self, msg: Message) -> tuple[bool, Optional[str], Optional[CarrierDetails]]:
        """Detect if message is a carrier email."""
        pass


class IContentValidator(ABC):
    """Interface for content validation and security checks."""
    
    @abstractmethod
    def validate_file_size(self, size: int, filename: str) -> None:
        """Validate file size against limits."""
        pass
    
    @abstractmethod
    def validate_nesting_depth(self, depth: int) -> None:
        """Validate email nesting depth."""
        pass
    
    @abstractmethod
    def validate_attachment_count(self, count: int) -> None:
        """Validate attachment count."""
        pass


class IResourceManager(ABC):
    """Interface for resource management (temp files, cleanup, etc.)."""
    
    @abstractmethod
    def create_temp_directory(self) -> str:
        """Create temporary directory for processing."""
        pass
    
    @abstractmethod
    def cleanup_resources(self) -> None:
        """Clean up temporary resources."""
        pass
    
    @abstractmethod
    def save_attachment(self, data: bytes, filename: str, output_dir: str) -> str:
        """Save attachment data to disk."""
        pass


class IDeduplicator(ABC):
    """Interface for content deduplication."""
    
    @abstractmethod
    def is_duplicate_content(self, msg: Message, current_depth: int) -> bool:
        """Check if message content has already been processed."""
        pass
    
    @abstractmethod
    def mark_as_processed(self, msg: Message, depth: int) -> None:
        """Mark message as processed to prevent future duplicates."""
        pass
    
    @abstractmethod
    def generate_content_signature(self, msg: Message) -> str:
        """Generate unique signature for email content."""
        pass


# ============================================================================
# High-Level Interfaces
# ============================================================================

class IParser(ABC):
    """Interface for the main email parser."""
    
    @abstractmethod
    def parse_email_file(self, email_path: str) -> ParsingResult:
        """Parse an email file and return structured results."""
        pass
    
    @abstractmethod
    def parse_message(self, msg: Message, output_dir: str) -> ParsingResult:
        """Parse an email message object."""
        pass


class IOutputFormatter(ABC):
    """Interface for formatting parser output."""
    
    @abstractmethod
    def format_json(self, result: ParsingResult) -> str:
        """Format result as JSON."""
        pass
    
    @abstractmethod
    def format_summary(self, result: ParsingResult) -> str:
        """Format result as summary."""
        pass
    
    @abstractmethod
    def format_detailed(self, result: ParsingResult) -> str:
        """Format result with full details."""
        pass


# ============================================================================
# Factory Protocols for Type Safety
# ============================================================================

@runtime_checkable
class IHeaderExtractorFactory(Protocol):
    """Factory protocol for creating header extractors."""
    
    def create(self, config: ParserConfiguration) -> IHeaderExtractor:
        """Create header extractor with configuration."""
        ...


@runtime_checkable
class IBodyExtractorFactory(Protocol):
    """Factory protocol for creating body extractors."""
    
    def create(self, config: ParserConfiguration) -> IBodyExtractor:
        """Create body extractor with configuration."""
        ...


@runtime_checkable
class IAttachmentProcessorFactory(Protocol):
    """Factory protocol for creating attachment processors."""
    
    def create(self, temp_dir: str, config: ParserConfiguration) -> IAttachmentProcessor:
        """Create attachment processor with temp directory and configuration."""
        ...


@runtime_checkable
class IImageProcessorFactory(Protocol):
    """Factory protocol for creating image processors."""
    
    def create(self, config: ParserConfiguration) -> IImageProcessor:
        """Create image processor with configuration."""
        ...


@runtime_checkable
class IURLProcessorFactory(Protocol):
    """Factory protocol for creating URL processors."""
    
    def create(self, config: ParserConfiguration) -> IURLProcessor:
        """Create URL processor with configuration."""
        ...


@runtime_checkable
class ICarrierDetectorFactory(Protocol):
    """Factory protocol for creating carrier detectors."""
    
    def create(self, config: ParserConfiguration) -> ICarrierDetector:
        """Create carrier detector with configuration."""
        ...


@runtime_checkable
class IDeduplicatorFactory(Protocol):
    """Factory protocol for creating deduplicators."""
    
    def create(self) -> IDeduplicator:
        """Create content deduplicator."""
        ...


# ============================================================================
# Service Protocols
# ============================================================================

@runtime_checkable
class IParserFactory(Protocol):
    """Factory protocol for creating complete parsers."""
    
    def create_parser(
        self,
        config: ParserConfiguration,
        temp_dir: Optional[str] = None
    ) -> IParser:
        """Create fully configured parser instance."""
        ...


@runtime_checkable
class IDependencyContainer(Protocol):
    """Dependency injection container protocol."""
    
    def get_header_extractor(self) -> IHeaderExtractor:
        """Get header extractor instance."""
        ...
    
    def get_body_extractor(self) -> IBodyExtractor:
        """Get body extractor instance."""
        ...
    
    def get_attachment_processor(self) -> IAttachmentProcessor:
        """Get attachment processor instance."""
        ...
    
    def get_image_processor(self) -> IImageProcessor:
        """Get image processor instance."""
        ...
    
    def get_url_processor(self) -> IURLProcessor:
        """Get URL processor instance."""
        ...
    
    def get_carrier_detector(self) -> ICarrierDetector:
        """Get carrier detector instance."""
        ...
    
    def get_deduplicator(self) -> IDeduplicator:
        """Get content deduplicator instance."""
        ...
    
    def get_resource_manager(self) -> IResourceManager:
        """Get resource manager instance."""
        ...
    
    def get_content_validator(self) -> IContentValidator:
        """Get content validator instance."""
        ...


# ============================================================================
# Configuration Protocols
# ============================================================================

@runtime_checkable
class IConfigurationProvider(Protocol):
    """Configuration provider protocol."""
    
    def get_config(self) -> ParserConfiguration:
        """Get current configuration."""
        ...
    
    def reload_config(self) -> None:
        """Reload configuration from source."""
        ...


# ============================================================================
# Validation Interfaces
# ============================================================================

class IDataValidator(ABC):
    """Interface for data validation."""
    
    @abstractmethod
    def validate_email_file(self, file_path: str) -> None:
        """Validate email file before processing."""
        pass
    
    @abstractmethod
    def validate_parsing_result(self, result: ParsingResult) -> None:
        """Validate parsing result structure."""
        pass


# ============================================================================
# Logging and Monitoring Interfaces  
# ============================================================================

class IProcessingLogger(ABC):
    """Interface for processing logging."""
    
    @abstractmethod
    def log_layer_processing(self, layer_data: EmailLayer) -> None:
        """Log layer processing details."""
        pass
    
    @abstractmethod
    def log_performance_metrics(self, metrics: Dict[str, Any]) -> None:
        """Log performance metrics."""
        pass
    
    @abstractmethod
    def log_error_context(self, error: Exception, context: Dict[str, Any]) -> None:
        """Log error with context."""
        pass


# ============================================================================
# Azure Function Specific Interfaces
# ============================================================================

class IAzureFunctionAdapter(ABC):
    """Interface for Azure Function adaptation."""
    
    @abstractmethod
    def handle_request(self, request_data: bytes, content_type: str) -> Dict[str, Any]:
        """Handle Azure Function request."""
        pass
    
    @abstractmethod
    def format_response(self, result: ParsingResult, format_type: str) -> Dict[str, Any]:
        """Format response for Azure Function."""
        pass
    
    @abstractmethod
    def handle_error(self, error: Exception) -> Dict[str, Any]:
        """Handle errors in Azure Function context."""
        pass