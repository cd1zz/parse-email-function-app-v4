# ============================================================================
# phishing_email_parser/content_consolidator.py
# ============================================================================
"""
Content consolidator that tracks provenance and eliminates duplication.
Follows existing codebase patterns with dependency injection and error handling.
"""

import logging
import re
from typing import List, Dict, Any, Set, Optional
from dataclasses import dataclass

from .interfaces import IContentValidator
from .data_models import (
    EmailLayer, ConsolidatedContent, URLInfo, ImageInfo, AttachmentInfo,
    ContentProvenance, LayerReference, create_content_provenance, 
    create_layer_reference, create_url_info, create_image_info,
    create_attachment_info
)
from .exceptions import handle_processing_errors, DataValidationError

logger = logging.getLogger(__name__)


class ContentConsolidator:
    """
    Consolidates content across all layers with provenance tracking.
    Eliminates duplication while preserving structural relationships.
    """
    
    def __init__(self):
        self.seen_urls: Set[str] = set()
        self.seen_attachments: Set[str] = set()  # By SHA256
        self.seen_images: Set[str] = set()  # By filename + size
        self.content_chains: List[Dict[str, Any]] = []
    
    @handle_processing_errors("content consolidation")
    def consolidate_all_content(self, layers: List[EmailLayer]) -> ConsolidatedContent:
        """
        Consolidate all content from layers with provenance tracking.
        
        Args:
            layers: List of processed email layers
            
        Returns:
            ConsolidatedContent with all URLs, images, attachments and their provenance
        """
        logger.debug(f"Consolidating content from {len(layers)} layers")
        
        consolidated = ConsolidatedContent()
        
        # Process each layer in order
        for layer in layers:
            self._process_layer_content(layer, consolidated)
        
        # Build content chains showing relationships
        consolidated.content_chains = self._build_content_chains(layers)
        
        logger.info(
            f"Consolidated: {len(consolidated.all_urls)} URLs, "
            f"{len(consolidated.all_images)} images, "
            f"{len(consolidated.all_attachments)} attachments"
        )
        
        return consolidated
    
    def _process_layer_content(self, layer: EmailLayer, consolidated: ConsolidatedContent) -> None:
        """Process all content from a single layer."""
        
        # Process URLs from this layer
        self._process_layer_urls(layer, consolidated)
        
        # Process images from this layer
        self._process_layer_images(layer, consolidated)
        
        # Process attachments from this layer
        self._process_layer_attachments(layer, consolidated)
    
    def _process_layer_urls(self, layer: EmailLayer, consolidated: ConsolidatedContent) -> None:
        """Process URLs found in this layer."""
        
        # URLs from body content
        for url_info in layer.urls:
            if isinstance(url_info, dict):
                url = url_info.get('original_url', '')
                source = url_info.get('source', 'body_text')
            else:
                url = url_info.original_url
                source = getattr(url_info, 'source', 'body_text')
            
            if url and url not in self.seen_urls:
                self.seen_urls.add(url)
                
                provenance = create_content_provenance(
                    layer=layer.layer_depth,
                    source=source,
                    context_snippet=self._extract_url_context(layer.body.final_text, url)
                )
                
                consolidated_url = create_url_info(
                    url=url,
                    source=source,
                    layer=layer.layer_depth,
                    is_shortened=self._is_url_shortened(url)
                )
                consolidated_url.found_in = provenance
                consolidated.all_urls.append(consolidated_url)
        
        # URLs from images (OCR)
        for image in layer.images:
            image_dict = image.to_dict() if hasattr(image, 'to_dict') else image
            ocr_text = image_dict.get('ocr_text', '')
            if ocr_text:
                ocr_urls = self._extract_urls_from_text(ocr_text)
                for url in ocr_urls:
                    if url and url not in self.seen_urls:
                        self.seen_urls.add(url)
                        
                        provenance = create_content_provenance(
                            layer=layer.layer_depth,
                            source="image_ocr",
                            image_filename=image_dict.get('filename'),
                            context_snippet=ocr_text[:100] + "..." if len(ocr_text) > 100 else ocr_text
                        )
                        
                        consolidated_url = create_url_info(
                            url=url,
                            source="image_ocr",
                            layer=layer.layer_depth,
                            is_shortened=self._is_url_shortened(url)
                        )
                        consolidated_url.found_in = provenance
                        consolidated.all_urls.append(consolidated_url)
        
        # URLs from attachments
        for attachment in layer.attachments:
            att_dict = attachment.to_dict() if hasattr(attachment, 'to_dict') else attachment
            attachment_urls = att_dict.get('urls', [])
            for url in attachment_urls:
                if url and url not in self.seen_urls:
                    self.seen_urls.add(url)
                    
                    provenance = create_content_provenance(
                        layer=layer.layer_depth,
                        source="attachment_text",
                        attachment_filename=att_dict.get('filename'),
                        context_snippet=f"Found in {att_dict.get('content_type', 'unknown')} attachment"
                    )
                    
                    consolidated_url = create_url_info(
                        url=url,
                        source="attachment_text",
                        layer=layer.layer_depth,
                        is_shortened=self._is_url_shortened(url)
                    )
                    consolidated_url.found_in = provenance
                    consolidated.all_urls.append(consolidated_url)
    
    def _process_layer_images(self, layer: EmailLayer, consolidated: ConsolidatedContent) -> None:
        """Process images found in this layer."""
        
        for image in layer.images:
            image_dict = image.to_dict() if hasattr(image, 'to_dict') else image
            
            # Create unique identifier for deduplication
            image_id = f"{image_dict.get('filename', '')}_{image_dict.get('size', 0)}"
            
            if image_id not in self.seen_images:
                self.seen_images.add(image_id)
                
                # Extract URLs from OCR text
                ocr_urls = []
                ocr_text = image_dict.get('ocr_text', '')
                if ocr_text:
                    ocr_urls = self._extract_urls_from_text(ocr_text)
                
                provenance = create_content_provenance(
                    layer=layer.layer_depth,
                    source="direct_image"
                )
                
                consolidated_image = create_image_info(
                    index=image_dict.get('index', 0),
                    filename=image_dict.get('filename', ''),
                    content_type=image_dict.get('content_type', ''),
                    size=image_dict.get('size', 0),
                    ocr_text=ocr_text,
                    urls_from_ocr=ocr_urls,
                    disk_path=image_dict.get('disk_path')
                )
                consolidated_image.found_in = provenance
                consolidated.all_images.append(consolidated_image)
        
        # Also process images embedded in attachments
        for attachment in layer.attachments:
            att_dict = attachment.to_dict() if hasattr(attachment, 'to_dict') else attachment
            embedded_images = att_dict.get('embedded_images', [])
            
            for embedded_img in embedded_images:
                img_dict = embedded_img.to_dict() if hasattr(embedded_img, 'to_dict') else embedded_img
                image_id = f"{img_dict.get('filename', '')}_{img_dict.get('size', 0)}"
                
                if image_id not in self.seen_images:
                    self.seen_images.add(image_id)
                    
                    # Extract URLs from OCR text
                    ocr_urls = []
                    ocr_text = img_dict.get('ocr_text', '')
                    if ocr_text:
                        ocr_urls = self._extract_urls_from_text(ocr_text)
                    
                    provenance = create_content_provenance(
                        layer=layer.layer_depth,
                        source="embedded_image",
                        attachment_filename=att_dict.get('filename'),
                        image_filename=img_dict.get('filename'),
                        parent_chain=[
                            f"layer_{layer.layer_depth}_attachment",
                            att_dict.get('filename', 'unknown'),
                            "embedded_image"
                        ]
                    )
                    
                    consolidated_image = create_image_info(
                        index=img_dict.get('index', 0),
                        filename=img_dict.get('filename', ''),
                        content_type=img_dict.get('content_type', ''),
                        size=img_dict.get('size', 0),
                        ocr_text=ocr_text,
                        urls_from_ocr=ocr_urls,
                        disk_path=img_dict.get('disk_path')
                    )
                    consolidated_image.found_in = provenance
                    consolidated.all_images.append(consolidated_image)
    
    def _process_layer_attachments(self, layer: EmailLayer, consolidated: ConsolidatedContent) -> None:
        """Process attachments found in this layer."""
        
        for attachment in layer.attachments:
            att_dict = attachment.to_dict() if hasattr(attachment, 'to_dict') else attachment
            
            sha256 = att_dict.get('sha256', '')
            if sha256 and sha256 not in self.seen_attachments:
                self.seen_attachments.add(sha256)
                
                # Extract URLs from attachment text
                attachment_urls = att_dict.get('urls', [])
                
                # Process embedded images
                embedded_images = []
                for img in att_dict.get('embedded_images', []):
                    img_dict = img.to_dict() if hasattr(img, 'to_dict') else img
                    
                    # Extract URLs from image OCR
                    ocr_urls = []
                    ocr_text = img_dict.get('ocr_text', '')
                    if ocr_text:
                        ocr_urls = self._extract_urls_from_text(ocr_text)
                    
                    embedded_image = create_image_info(
                        index=img_dict.get('index', 0),
                        filename=img_dict.get('filename', ''),
                        content_type=img_dict.get('content_type', ''),
                        size=img_dict.get('size', 0),
                        ocr_text=ocr_text,
                        urls_from_ocr=ocr_urls,
                        disk_path=img_dict.get('disk_path')
                    )
                    embedded_image.found_in = create_content_provenance(
                        layer=layer.layer_depth,
                        source="embedded_in_attachment",
                        attachment_filename=att_dict.get('filename'),
                        image_filename=img_dict.get('filename')
                    )
                    embedded_images.append(embedded_image)
                
                # Determine if this leads to another layer
                leads_to_layer = None
                if att_dict.get('is_nested_email', False):
                    # Find the layer this attachment leads to
                    leads_to_layer = self._find_nested_layer_for_attachment(
                        att_dict.get('filename', ''), layer.layer_depth
                    )
                
                provenance = create_content_provenance(
                    layer=layer.layer_depth,
                    source="direct_attachment"
                )
                
                consolidated_attachment = create_attachment_info(
                    index=att_dict.get('index', 0),
                    filename=att_dict.get('filename', ''),
                    content_type=att_dict.get('content_type', ''),
                    size=att_dict.get('size', 0),
                    sha256=sha256,
                    text_content=att_dict.get('text_content'),
                    urls=attachment_urls,
                    embedded_images=embedded_images,
                    is_nested_email=att_dict.get('is_nested_email', False),
                    leads_to_layer=leads_to_layer
                )
                consolidated_attachment.found_in = provenance
                consolidated.all_attachments.append(consolidated_attachment)
    
    def _build_content_chains(self, layers: List[EmailLayer]) -> List[Dict[str, Any]]:
        """Build content relationship chains for complex nesting scenarios."""
        chains = []
        
        # Example: carrier → phishing email → nested .eml → excel → image → URL
        for layer in layers:
            if layer.parent_reference:
                # This layer comes from an attachment in a parent layer
                for attachment in layer.attachments:
                    att_dict = attachment.to_dict() if hasattr(attachment, 'to_dict') else attachment
                    
                    for embedded_img in att_dict.get('embedded_images', []):
                        img_dict = embedded_img.to_dict() if hasattr(embedded_img, 'to_dict') else embedded_img
                        
                        if img_dict.get('urls_from_ocr'):
                            for url in img_dict['urls_from_ocr']:
                                chain = {
                                    "type": "url_in_image_in_attachment_in_nested_email",
                                    "chain": [
                                        {"type": "layer", "depth": layer.parent_reference.layer_depth if layer.parent_reference else None},
                                        {"type": "attachment", "filename": layer.parent_reference.via_attachment if layer.parent_reference else None},
                                        {"type": "nested_email", "depth": layer.layer_depth},
                                        {"type": "attachment", "filename": att_dict.get('filename')},
                                        {"type": "embedded_image", "filename": img_dict.get('filename')},
                                        {"type": "url", "value": url}
                                    ],
                                    "complexity_indicators": [
                                        "deeply_nested_content",
                                        "url_in_image_in_excel",
                                        "multi_layer_obfuscation"
                                    ]
                                }
                                chains.append(chain)
        
        return chains
    
    def _find_nested_layer_for_attachment(self, attachment_filename: str, parent_layer: int) -> Optional[int]:
        """Find which layer corresponds to a nested email attachment."""
        # This would be implemented based on the layer processing logic
        # For now, return the next layer depth as a reasonable guess
        return parent_layer + 1
    
    def _extract_urls_from_text(self, text: str) -> List[str]:
        """Extract URLs from text content."""
        if not text:
            return []
        
        url_pattern = re.compile(
            r'https?://[^\s<>"{}|\\^`\[\]]+|www\.[^\s<>"{}|\\^`\[\]]+', 
            re.IGNORECASE
        )
        urls = url_pattern.findall(text)
        return [url.rstrip(".,;:!?)]}") for url in urls]
    
    def _extract_url_context(self, text: str, url: str, context_length: int = 50) -> str:
        """Extract context around a URL for provenance."""
        if not text or not url:
            return ""
        
        try:
            url_pos = text.find(url)
            if url_pos == -1:
                return ""
            
            start = max(0, url_pos - context_length)
            end = min(len(text), url_pos + len(url) + context_length)
            
            context = text[start:end].strip()
            return f"...{context}..." if start > 0 or end < len(text) else context
        except Exception:
            return ""
    
    def _is_url_shortened(self, url: str) -> bool:
        """Check if URL appears to be shortened."""
        shortener_domains = [
            "bit.ly", "t.co", "goo.gl", "ow.ly", "tinyurl.com", "is.gd",
            "tiny.cc", "rb.gy", "short.io", "aka.ms"
        ]
        
        try:
            import urllib.parse
            parsed = urllib.parse.urlparse(url)
            domain = parsed.netloc.lower()
            return any(domain == shortener or domain.endswith('.' + shortener)
                      for shortener in shortener_domains)
        except Exception:
            return False


class LayerRelationshipBuilder:
    """
    Builds relationships between layers for structural representation.
    """
    
    @staticmethod
    def build_layer_relationships(layers: List[EmailLayer]) -> None:
        """
        Build and populate layer relationships.
        
        Modifies layers in-place to add nested_email_references and parent_reference.
        """
        logger.debug("Building layer relationships")
        
        # Sort layers by depth for processing
        sorted_layers = sorted(layers, key=lambda l: l.layer_depth)
        
        for i, layer in enumerate(sorted_layers):
            # Find attachments that lead to nested emails
            for attachment in layer.attachments:
                att_dict = attachment.to_dict() if hasattr(attachment, 'to_dict') else attachment
                
                if att_dict.get('is_nested_email', False):
                    # Find the next layer that corresponds to this attachment
                    nested_layer = LayerRelationshipBuilder._find_nested_layer(
                        sorted_layers, layer.layer_depth, att_dict.get('filename', '')
                    )
                    
                    if nested_layer:
                        # Add reference from parent to child
                        layer_ref = create_layer_reference(
                            layer_depth=nested_layer.layer_depth,
                            relationship="contains_nested_email",
                            via_attachment=att_dict.get('filename'),
                            via_mime_type=att_dict.get('content_type')
                        )
                        layer.nested_email_references.append(layer_ref)
                        
                        # Add reference from child to parent
                        parent_ref = create_layer_reference(
                            layer_depth=layer.layer_depth,
                            relationship="attached_to_layer",
                            via_attachment=att_dict.get('filename'),
                            via_mime_type=att_dict.get('content_type')
                        )
                        nested_layer.parent_reference = parent_ref
    
    @staticmethod
    def _find_nested_layer(layers: List[EmailLayer], parent_depth: int, 
                          attachment_filename: str) -> Optional[EmailLayer]:
        """Find the layer that corresponds to a nested email attachment."""
        # Look for the next layer after parent_depth
        for layer in layers:
            if layer.layer_depth > parent_depth:
                # Check if this layer has metadata indicating it came from the attachment
                # This would be set during parsing based on temp file names or other tracking
                return layer
        return None


# Factory function following existing patterns
def create_content_consolidator() -> ContentConsolidator:
    """Create content consolidator instance."""
    return ContentConsolidator()