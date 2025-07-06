# ============================================================================
# phishing_email_parser/data_models.py
# ============================================================================
"""
Typed data models for phishing email parser with pure structural representation.
Provides consolidated content tracking and provenance preservation.
"""

from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any, Union
from enum import Enum
from datetime import datetime


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
class ContentProvenance:
    """Tracks where content was found in the email structure."""
    layer: int
    source: str  # "body_text", "html_content", "image_ocr", "attachment_text", etc.
    attachment_filename: Optional[str] = None
    image_filename: Optional[str] = None
    parent_chain: List[str] = field(default_factory=list)
    context_snippet: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "layer": self.layer,
            "source": self.source,
            "attachment_filename": self.attachment_filename,
            "image_filename": self.image_filename,
            "parent_chain": self.parent_chain,
            "context_snippet": self.context_snippet
        }


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
    """Structured email body content with carrier analysis."""
    plain_text: str = ""
    html_text: str = ""
    converted_text: str = ""
    final_text: str = ""
    has_html: bool = False
    has_plain: bool = False
    # Enhanced fields for carrier content analysis
    wrapper_content: Optional[str] = None  # Carrier wrapper text (forwarding comments, etc.)
    quoted_content_preview: Optional[str] = None  # Preview of quoted/forwarded content
    content_summary: Optional[str] = None  # Brief description for token efficiency
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "plain_text": self.plain_text,
            "html_text": self.html_text,
            "converted_text": self.converted_text,
            "final_text": self.final_text,
            "has_html": self.has_html,
            "has_plain": self.has_plain,
            "wrapper_content": self.wrapper_content,
            "quoted_content_preview": self.quoted_content_preview,
            "content_summary": self.content_summary
        }


@dataclass
class URLInfo:
    """Information about extracted URLs with provenance."""
    original_url: str
    is_shortened: bool = False
    expanded_url: str = "Not Applicable"
    source: str = "unknown"  # body, attachment, ocr, etc.
    found_in: Optional[ContentProvenance] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "original_url": self.original_url,
            "is_shortened": self.is_shortened,
            "expanded_url": self.expanded_url,
            "source": self.source,
            "found_in": self.found_in.to_dict() if self.found_in else None
        }


@dataclass
class ImageInfo:
    """Information about extracted images with provenance."""
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
    found_in: Optional[ContentProvenance] = None
    
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
            "is_excel_embedded": self.is_excel_embedded,
            "found_in": self.found_in.to_dict() if self.found_in else None
        }


@dataclass  
class AttachmentInfo:
    """Information about email attachments with provenance."""
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
    leads_to_layer: Optional[int] = None  # For nested emails
    found_in: Optional[ContentProvenance] = None
    
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
            "error": self.error,
            "leads_to_layer": self.leads_to_layer,
            "found_in": self.found_in.to_dict() if self.found_in else None
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
class LayerReference:
    """Reference to how layers are connected."""
    layer_depth: int
    relationship: str  # "contains_nested_email", "attached_to_layer", "forwarded_content"
    via_attachment: Optional[str] = None
    via_mime_type: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "layer_depth": self.layer_depth,
            "relationship": self.relationship,
            "via_attachment": self.via_attachment,
            "via_mime_type": self.via_mime_type
        }


@dataclass
class EmailLayer:
    """Complete information for a single email layer with structural relationships."""
    layer_depth: int
    is_carrier_email: bool
    carrier_vendor: Optional[str]
    carrier_details: Optional[CarrierDetails]
    carrier_summary: str
    headers: EmailHeaders
    body: EmailBody
    attachments: List[AttachmentInfo] = field(default_factory=list)
    images: List[ImageInfo] = field(default_factory=list)
    urls: List[URLInfo] = field(default_factory=list)
    nested_email_references: List[LayerReference] = field(default_factory=list)
    parent_reference: Optional[LayerReference] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "layer_depth": self.layer_depth,
            "is_carrier_email": self.is_carrier_email,
            "carrier_vendor": self.carrier_vendor,
            "carrier_details": self.carrier_details.to_dict() if self.carrier_details else None,
            "carrier_summary": self.carrier_summary,
            "headers": self.headers.to_dict(),
            "body": self.body.to_dict(),
            "attachments": [att.to_dict() for att in self.attachments],
            "images": [img.to_dict() for img in self.images],
            "urls": [url.to_dict() for url in self.urls],
            "nested_email_references": [ref.to_dict() for ref in self.nested_email_references],
            "parent_reference": self.parent_reference.to_dict() if self.parent_reference else None
        }


@dataclass
class StructuralSummary:
    """Summary of email structure without analysis judgments."""
    total_layers: int = 0
    total_attachments: int = 0
    total_images: int = 0
    total_urls: int = 0
    has_nested_emails: bool = False
    nesting_chain: List[str] = field(default_factory=list)  # ["carrier_email", "nested_eml", "excel_attachment"]
    layer_types: List[Dict[str, Any]] = field(default_factory=list)  # Basic layer descriptions
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_layers": self.total_layers,
            "total_attachments": self.total_attachments,
            "total_images": self.total_images,
            "total_urls": self.total_urls,
            "has_nested_emails": self.has_nested_emails,
            "nesting_chain": self.nesting_chain,
            "layer_types": self.layer_types
        }


@dataclass
class ConsolidatedContent:
    """All content consolidated with provenance tracking."""
    all_urls: List[URLInfo] = field(default_factory=list)
    all_images: List[ImageInfo] = field(default_factory=list)
    all_attachments: List[AttachmentInfo] = field(default_factory=list)
    content_chains: List[Dict[str, Any]] = field(default_factory=list)  # Track content relationships
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "all_urls": [url.to_dict() for url in self.all_urls],
            "all_images": [img.to_dict() for img in self.all_images],
            "all_attachments": [att.to_dict() for att in self.all_attachments],
            "content_chains": self.content_chains
        }


@dataclass
class CarrierAnalysis:
    """Analysis of carrier detection across all layers (pure detection, no judgments)."""
    total_carriers: int = 0
    carrier_details: List[Dict[str, Any]] = field(default_factory=list)
    non_carrier_layers: List[int] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_carriers": self.total_carriers,
            "carrier_details": self.carrier_details,
            "non_carrier_layers": self.non_carrier_layers
        }


@dataclass
class ParsingResult:
    """Complete parsing result with pure structural representation."""
    parser_info: Dict[str, Any] = field(default_factory=dict)
    layers: List[EmailLayer] = field(default_factory=list)
    structural_summary: StructuralSummary = field(default_factory=StructuralSummary)
    consolidated_content: ConsolidatedContent = field(default_factory=ConsolidatedContent)
    carrier_analysis: CarrierAnalysis = field(default_factory=CarrierAnalysis)
    processing_metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "parser_info": self.parser_info,
            "layers": [layer.to_dict() for layer in self.layers],
            "structural_summary": self.structural_summary.to_dict(),
            "consolidated_content": self.consolidated_content.to_dict(),
            "carrier_analysis": self.carrier_analysis.to_dict(),
            "processing_metadata": self.processing_metadata
        }


# ============================================================================
# Factory Functions
# ============================================================================

def create_content_provenance(
    layer: int,
    source: str,
    attachment_filename: Optional[str] = None,
    image_filename: Optional[str] = None,
    parent_chain: Optional[List[str]] = None,
    context_snippet: Optional[str] = None
) -> ContentProvenance:
    """Factory function for creating ContentProvenance."""
    return ContentProvenance(
        layer=layer,
        source=source,
        attachment_filename=attachment_filename,
        image_filename=image_filename,
        parent_chain=parent_chain or [],
        context_snippet=context_snippet
    )


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


def create_url_info(
    url: str, 
    source: str = "unknown", 
    layer: Optional[int] = None,
    **kwargs
) -> URLInfo:
    """Factory function for creating URLInfo with optional provenance."""
    provenance = None
    if layer is not None:
        provenance = create_content_provenance(layer=layer, source=source, **kwargs)
    
    return URLInfo(
        original_url=url,
        source=source,
        found_in=provenance,
        **{k: v for k, v in kwargs.items() if k not in ['attachment_filename', 'image_filename', 'parent_chain', 'context_snippet']}
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


def create_layer_reference(
    layer_depth: int,
    relationship: str,
    via_attachment: Optional[str] = None,
    via_mime_type: Optional[str] = None
) -> LayerReference:
    """Factory function for creating LayerReference."""
    return LayerReference(
        layer_depth=layer_depth,
        relationship=relationship,
        via_attachment=via_attachment,
        via_mime_type=via_mime_type
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
        carrier_summary="Carrier email detected" if is_carrier_email else "Direct email content",
        **kwargs
    )


def create_parsing_result(
    layers: Optional[List[EmailLayer]] = None,
    **kwargs
) -> ParsingResult:
    """Factory function for creating ParsingResult."""
    layers = layers or []
    
    # Generate parser info
    parser_info = {
        "version": "2.0",
        "purpose": "structural_email_analysis",
        "features": [
            "pure_structural_representation",
            "consolidated_content_tracking",
            "provenance_preservation",
            "no_analytical_judgments"
        ]
    }
    
    # Generate structural summary
    structural_summary = StructuralSummary(
        total_layers=len(layers),
        total_attachments=sum(len(layer.attachments) for layer in layers),
        total_images=sum(len(layer.images) for layer in layers),
        total_urls=sum(len(layer.urls) for layer in layers),
        has_nested_emails=any(layer.layer_depth > 0 for layer in layers),
        layer_types=[
            {
                "layer": layer.layer_depth,
                "type": "carrier" if layer.is_carrier_email else "content",
                "vendor": layer.carrier_vendor,
                "has_nested_refs": len(layer.nested_email_references) > 0,
                "has_parent_ref": layer.parent_reference is not None
            }
            for layer in layers
        ]
    )
    
    # Generate carrier analysis
    carrier_analysis = CarrierAnalysis(
        total_carriers=sum(1 for layer in layers if layer.is_carrier_email),
        carrier_details=[
            {
                "layer": layer.layer_depth,
                "vendor": layer.carrier_vendor,
                "type": layer.carrier_details.carrier_type.value if layer.carrier_details else "unknown",
                "detection_method": layer.carrier_details.detection_method if layer.carrier_details else "unknown"
            }
            for layer in layers if layer.is_carrier_email
        ],
        non_carrier_layers=[layer.layer_depth for layer in layers if not layer.is_carrier_email]
    )
    
    return ParsingResult(
        parser_info=parser_info,
        layers=layers,
        structural_summary=structural_summary,
        carrier_analysis=carrier_analysis,
        **kwargs
    )