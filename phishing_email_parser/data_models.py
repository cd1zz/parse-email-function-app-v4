# ============================================================================
# phishing_email_parser/data_models.py
# ============================================================================
"""
Typed data models for phishing email parser.
Replaces dictionary usage with structured dataclasses for type safety.
"""

from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any, Union
from enum import Enum
from datetime import datetime


class AnalysisPriority(Enum):
    """Priority levels for LLM analysis focus."""
    LOW = "LOW"          # Carrier emails - focus on nested content  
    MEDIUM = "MEDIUM"    # Unknown carrier type or complex nesting
    HIGH = "HIGH"        # Direct content - primary threat analysis focus


class CarrierType(Enum):
    """Types of carrier email detection."""
    SECURITY_APPLIANCE = "security_appliance"
    USER_FORWARD = "user_forward" 
    SECURITY_SUBMISSION = "security_submission"
    HELPDESK_SUBMISSION = "helpdesk_submission"
    UNKNOWN = "unknown"


class ContentType(Enum):
    """Content types for processing decisions."""
    TEXT_PLAIN = "text/plain"
    TEXT_HTML = "text/html"
    APPLICATION_PDF = "application/pdf"
    APPLICATION_EXCEL = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    APPLICATION_WORD = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
    MESSAGE_RFC822 = "message/rfc822"
    IMAGE_PNG = "image/png"
    IMAGE_JPEG = "image/jpeg"
    APPLICATION_OCTET_STREAM = "application/octet-stream"


@dataclass
class EmailHeaders:
    """Structured email headers with all relevant fields."""
    subject: str = ""
    from_addr: str = ""  # 'from' is a Python keyword
    to: str = ""
    cc: str = ""
    bcc: str = ""
    date: str = ""
    message_id: str = ""
    reply_to: str = ""
    return_path: str = ""
    received: List[str] = field(default_factory=list)
    x_headers: Dict[str, str] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "subject": self.subject,
            "from": self.from_addr,  # Use 'from' in JSON output
            "to": self.to,
            "cc": self.cc,
            "bcc": self.bcc,
            "date": self.date,
            "message_id": self.message_id,
            "reply_to": self.reply_to,
            "return_path": self.return_path,
            "received": self.received,
            "x_headers": self.x_headers
        }


@dataclass
class EmailBody:
    """Structured email body content."""
    plain_text: str = ""
    html_text: str = ""
    converted_text: str = ""
    final_text: str = ""
    has_html: bool = False
    has_plain: bool = False
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "plain_text": self.plain_text,
            "html_text": self.html_text,
            "converted_text": self.converted_text,
            "final_text": self.final_text,
            "has_html": self.has_html,
            "has_plain": self.has_plain
        }


@dataclass
class URLInfo:
    """Information about extracted URLs."""
    original_url: str
    is_shortened: bool = False
    expanded_url: str = "Not Applicable"
    source: str = "unknown"  # body, attachment, ocr, etc.
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "original_url": self.original_url,
            "is_shortened": self.is_shortened,
            "expanded_url": self.expanded_url,
            "source": self.source
        }


@dataclass
class ImageInfo:
    """Information about extracted images."""
    index: int
    filename: str
    disk_path: Optional[str] = None
    content_id: Optional[str] = None
    content_type: str = ""
    ocr_text: Optional[str] = None
    size: int = 0
    urls_from_ocr: List[str] = field(default_factory=list)
    hyperlinks: List[str] = field(default_factory=list)
    is_excel_embedded: bool = False
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "index": self.index,
            "filename": self.filename,
            "disk_path": self.disk_path,
            "content_id": self.content_id,
            "content_type": self.content_type,
            "ocr_text": self.ocr_text,
            "size": self.size,
            "urls_from_ocr": self.urls_from_ocr,
            "hyperlinks": self.hyperlinks,
            "is_excel_embedded": self.is_excel_embedded
        }


@dataclass  
class AttachmentInfo:
    """Information about email attachments."""
    index: int
    filename: str
    content_type: str
    size: int
    sha256: str = ""
    disk_path: Optional[str] = None
    text_content: Optional[str] = None
    urls: List[str] = field(default_factory=list)
    is_nested_email: bool = False
    is_suspicious_extension: bool = False
    embedded_images: List[ImageInfo] = field(default_factory=list)
    processed: bool = True
    error: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "index": self.index,
            "filename": self.filename,
            "content_type": self.content_type,
            "size": self.size,
            "sha256": self.sha256,
            "disk_path": self.disk_path,
            "text_content": self.text_content,
            "urls": self.urls,
            "is_nested_email": self.is_nested_email,
            "is_suspicious_extension": self.is_suspicious_extension,
            "embedded_images": [img.to_dict() for img in self.embedded_images],
            "processed": self.processed,
            "error": self.error
        }


@dataclass
class CarrierDetectionEvidence:
    """Evidence collected during carrier detection."""
    subject_matches: List[str] = field(default_factory=list)
    body_matches: List[str] = field(default_factory=list)
    from_matches: List[str] = field(default_factory=list)
    structural_indicators: List[str] = field(default_factory=list)
    confidence_score: int = 0
    submission_type: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "subject_matches": self.subject_matches,
            "body_matches": self.body_matches,
            "from_matches": self.from_matches,
            "structural_indicators": self.structural_indicators,
            "confidence_score": self.confidence_score,
            "submission_type": self.submission_type
        }


@dataclass
class CarrierDetails:
    """Detailed carrier detection information."""
    carrier_type: CarrierType
    vendor: Optional[str] = None
    confidence: float = 0.0
    detection_method: str = ""
    evidence: Optional[CarrierDetectionEvidence] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "type": self.carrier_type.value,
            "vendor": self.vendor,
            "confidence": self.confidence,
            "detection_method": self.detection_method,
            "evidence": self.evidence.to_dict() if self.evidence else None
        }


@dataclass
class EmailLayer:
    """Complete information for a single email layer."""
    layer_depth: int
    is_carrier_email: bool
    carrier_vendor: Optional[str]
    carrier_details: Optional[CarrierDetails]
    analysis_priority: AnalysisPriority
    carrier_summary: str
    headers: EmailHeaders
    body: EmailBody
    attachments: List[AttachmentInfo] = field(default_factory=list)
    images: List[ImageInfo] = field(default_factory=list)
    urls: List[URLInfo] = field(default_factory=list)
    nested_emails: List[str] = field(default_factory=list)  # References to nested layers
    parent_attachment: Optional[Dict[str, Any]] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "layer_depth": self.layer_depth,
            "is_carrier_email": self.is_carrier_email,
            "carrier_vendor": self.carrier_vendor,
            "carrier_details": self.carrier_details.to_dict() if self.carrier_details else None,
            "analysis_priority": self.analysis_priority.value,
            "carrier_summary": self.carrier_summary,
            "headers": self.headers.to_dict(),
            "body": self.body.to_dict(),
            "attachments": [att.to_dict() for att in self.attachments],
            "images": [img.to_dict() for img in self.images],
            "urls": [url.to_dict() for url in self.urls],
            "nested_emails": self.nested_emails,
            "parent_attachment": self.parent_attachment
        }


@dataclass
class ProcessingSummary:
    """Summary of processing results."""
    total_layers: int = 0
    total_attachments: int = 0
    total_images: int = 0
    total_embedded_images: int = 0
    total_urls: int = 0
    has_nested_emails: bool = False
    carrier_emails: List[Dict[str, Any]] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "total_layers": self.total_layers,
            "total_attachments": self.total_attachments,
            "total_images": self.total_images,
            "total_embedded_images": self.total_embedded_images,
            "total_urls": self.total_urls,
            "has_nested_emails": self.has_nested_emails,
            "carrier_emails": self.carrier_emails
        }


@dataclass
class CarrierAnalysis:
    """Analysis of carrier detection across all layers."""
    total_carriers: int = 0
    security_appliances: List[Dict[str, Any]] = field(default_factory=list)
    user_submissions: List[Dict[str, Any]] = field(default_factory=list)
    analysis_recommendations: List[Dict[str, Any]] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "total_carriers": self.total_carriers,
            "security_appliances": self.security_appliances,
            "user_submissions": self.user_submissions,
            "analysis_recommendations": self.analysis_recommendations
        }


@dataclass
class ParsingResult:
    """Complete parsing result with all information."""
    parser_info: Dict[str, Any] = field(default_factory=dict)
    message_layers: List[EmailLayer] = field(default_factory=list)
    carrier_analysis: CarrierAnalysis = field(default_factory=CarrierAnalysis)
    summary: ProcessingSummary = field(default_factory=ProcessingSummary)
    processing_metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization (backward compatibility)."""
        return {
            "parser_info": self.parser_info,
            "message_layers": [layer.to_dict() for layer in self.message_layers],
            "carrier_analysis": self.carrier_analysis.to_dict(),
            "summary": self.summary.to_dict(),
            "processing_metadata": self.processing_metadata
        }


# Factory functions for creating models
def create_email_headers(
    subject: str = "",
    from_addr: str = "",
    to: str = "",
    date: str = "",
    message_id: str = "",
    **kwargs
) -> EmailHeaders:
    """Factory function for creating EmailHeaders."""
    return EmailHeaders(
        subject=subject,
        from_addr=from_addr,
        to=to,
        date=date,
        message_id=message_id,
        **kwargs
    )


def create_email_body(
    plain_text: str = "",
    html_text: str = "",
    converted_text: str = "",
    **kwargs
) -> EmailBody:
    """Factory function for creating EmailBody."""
    final_text = converted_text or plain_text
    return EmailBody(
        plain_text=plain_text,
        html_text=html_text,
        converted_text=converted_text,
        final_text=final_text,
        has_html=bool(html_text),
        has_plain=bool(plain_text),
        **kwargs
    )


def create_url_info(url: str, source: str = "unknown", **kwargs) -> URLInfo:
    """Factory function for creating URLInfo."""
    return URLInfo(
        original_url=url,
        source=source,
        **kwargs
    )


def create_attachment_info(
    index: int,
    filename: str,
    content_type: str,
    size: int,
    **kwargs
) -> AttachmentInfo:
    """Factory function for creating AttachmentInfo."""
    return AttachmentInfo(
        index=index,
        filename=filename,
        content_type=content_type,
        size=size,
        **kwargs
    )


def create_image_info(
    index: int,
    filename: str,
    **kwargs
) -> ImageInfo:
    """Factory function for creating ImageInfo."""
    return ImageInfo(
        index=index,
        filename=filename,
        **kwargs
    )


def create_carrier_details(
    carrier_type: CarrierType,
    vendor: Optional[str] = None,
    **kwargs
) -> CarrierDetails:
    """Factory function for creating CarrierDetails."""
    return CarrierDetails(
        carrier_type=carrier_type,
        vendor=vendor,
        **kwargs
    )


def create_email_layer(
    layer_depth: int,
    headers: EmailHeaders,
    body: EmailBody,
    is_carrier_email: bool = False,
    **kwargs
) -> EmailLayer:
    """Factory function for creating EmailLayer."""
    return EmailLayer(
        layer_depth=layer_depth,
        is_carrier_email=is_carrier_email,
        headers=headers,
        body=body,
        analysis_priority=AnalysisPriority.HIGH if not is_carrier_email else AnalysisPriority.LOW,
        carrier_summary="Direct email content" if not is_carrier_email else "Carrier email detected",
        **kwargs
    )


def create_parsing_result(
    message_layers: Optional[List[EmailLayer]] = None,
    **kwargs
) -> ParsingResult:
    """Factory function for creating ParsingResult."""
    layers = message_layers or []
    
    # Generate parser info
    parser_info = {
        "version": "2.0",
        "purpose": "phishing_email_analysis",
        "features": [
            "solid_architecture",
            "dependency_injection", 
            "enhanced_carrier_detection",
            "content_deduplication",
            "excel_image_extraction",
            "production_error_handling"
        ]
    }
    
    # Generate summary
    summary = ProcessingSummary(
        total_layers=len(layers),
        total_attachments=sum(len(layer.attachments) for layer in layers),
        total_images=sum(len(layer.images) for layer in layers),
        total_embedded_images=sum(
            len(att.embedded_images) for layer in layers for att in layer.attachments
        ),
        total_urls=sum(len(layer.urls) for layer in layers),
        has_nested_emails=any(layer.layer_depth > 0 for layer in layers),
        carrier_emails=[
            {
                "layer": layer.layer_depth,
                "vendor": layer.carrier_vendor,
                "type": layer.carrier_details.carrier_type.value if layer.carrier_details else "unknown",
                "priority": layer.analysis_priority.value
            }
            for layer in layers if layer.is_carrier_email
        ]
    )
    
    return ParsingResult(
        parser_info=parser_info,
        message_layers=layers,
        summary=summary,
        **kwargs
    )