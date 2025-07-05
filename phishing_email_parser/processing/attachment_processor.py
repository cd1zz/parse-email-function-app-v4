"""
Email attachment processor for phishing analysis.

Handles extraction, analysis, and text content extraction from email attachments.
Enhanced with Excel image extraction and OCR capabilities.
"""

import email
import hashlib
import logging
import os
import re
from email import policy
from email.message import Message
from pathlib import Path
from typing import Any, Dict, List, Optional

from .pdf_utils import extract_text_from_pdf
from .excel_utils import extract_text_from_excel, extract_excel_with_images

logger = logging.getLogger(__name__)


class AttachmentProcessor:
    """Process email attachments for phishing analysis."""
    
    # File types that commonly contain text content
    TEXT_EXTRACTABLE_TYPES = {
        'application/pdf',
        'text/plain',
        'text/html',
        'text/csv',
        'application/rtf',
        'application/msword',
        'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
        'application/vnd.ms-excel',
        'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
    }
    
    # Suspicious file extensions to flag
    SUSPICIOUS_EXTENSIONS = {
        '.exe', '.scr', '.bat', '.cmd', '.com', '.pif', '.vbs', '.js', '.jar',
        '.zip', '.rar', '.7z', '.ace', '.arj', '.cab', '.lzh', '.tar', '.gz'
    }
    
    def __init__(self, temp_dir: str):
        """Initialize with temporary directory for file extraction."""
        self.temp_dir = temp_dir
        os.makedirs(temp_dir, exist_ok=True)
        
    def process_attachments(self, msg: Message, output_dir: str) -> List[Dict[str, Any]]:
        """Process all attachments in an email message."""
        logger.debug("Processing attachments to %s", output_dir)
        attachments = []
        attachment_idx = 1
        
        for part in msg.iter_attachments():
            try:
                content_type = part.get_content_type()
                logger.debug(
                    "Handling attachment %d with content type %s",
                    attachment_idx,
                    content_type,
                )

                if content_type.startswith("message/"):
                    nested_obj = (
                        part.get_payload(0) if part.is_multipart() else part.get_payload()
                    )
                    if isinstance(nested_obj, email.message.Message):
                        raw_bytes = nested_obj.as_bytes(policy=policy.default)
                    else:
                        raw_bytes = nested_obj

                    filename = part.get_filename() or f"nested_{attachment_idx}.eml"
                    disk_path = os.path.join(output_dir, filename)
                    with open(disk_path, "wb") as fh:
                        fh.write(raw_bytes)

                    attachments.append(
                        {
                            "index": attachment_idx,
                            "filename": filename,
                            "content_type": content_type,
                            "disk_path": disk_path,
                            "size": len(raw_bytes),
                            "is_nested_email": True,
                        }
                    )
                    attachment_idx += 1
                    continue

                attachment_data = self._process_single_attachment(
                    part, attachment_idx, output_dir
                )
                if attachment_data:
                    attachments.append(attachment_data)
                    attachment_idx += 1
            except Exception as e:
                logger.error(f"Error processing attachment {attachment_idx}: {e}")
                # Create minimal error entry
                attachments.append({
                    "index": attachment_idx,
                    "filename": f"attachment_{attachment_idx}_error",
                    "error": str(e),
                    "processed": False
                })
                attachment_idx += 1

        logger.debug("Finished processing attachments: %d found", len(attachments))
        return attachments
    
    def _process_single_attachment(self, part: Message, index: int,
                                 output_dir: str) -> Optional[Dict[str, Any]]:
        """Process a single email attachment."""
        filename = part.get_filename()
        if not filename:
            filename = f"attachment_{index}"
        else:
            # Strip null terminators and other problematic characters
            filename = filename.rstrip('\x00').strip()

        # FIXED: Clean content type to remove null bytes
        content_type = part.get_content_type()
        if content_type:
            content_type = content_type.rstrip('\x00').strip()

        logger.debug("Processing attachment %d: %s (%s)", index, filename, content_type)
            
        payload = part.get_payload(decode=True)
        
        if not payload:
            return None
            
        # Save attachment to disk
        file_path = os.path.join(output_dir, filename)
        try:
            with open(file_path, 'wb') as f:
                f.write(payload)
            logger.debug("Attachment %s written to %s", filename, file_path)
        except Exception as e:
            logger.error(f"Error saving attachment {filename}: {e}")
            file_path = None
        
        # Basic file analysis
        file_size = len(payload)
        file_hash = hashlib.sha256(payload).hexdigest()
        file_extension = Path(filename).suffix.lower()
        
        attachment_info = {
            "index": index,
            "filename": filename,
            "content_type": content_type,
            "size": file_size,
            "sha256": file_hash,
            "extension": file_extension,
            "disk_path": file_path,
            "is_suspicious_extension": file_extension in self.SUSPICIOUS_EXTENSIONS,
            "text_content": None,
            "urls": [],
            "processed": True,
            "embedded_images": []  # NEW: Track images extracted from this attachment
        }
        
        # Extract text content and images if possible
        if content_type in self.TEXT_EXTRACTABLE_TYPES:
            # ENHANCED: Use new Excel processing for Excel files
            if content_type in [
                'application/vnd.ms-excel',
                'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
            ]:
                text_content, extracted_images = self._extract_from_excel_with_images(
                    payload, filename, output_dir
                )
                attachment_info["text_content"] = text_content
                attachment_info["embedded_images"] = extracted_images
                
                # Collect URLs from text content and extracted images
                if text_content:
                    attachment_info["urls"].extend(self._extract_urls_from_text(text_content))
                
                # Add URLs from embedded images
                for img in extracted_images:
                    if img.get("urls_from_ocr"):
                        attachment_info["urls"].extend(img["urls_from_ocr"])
                    if img.get("hyperlinks"):
                        attachment_info["urls"].extend(img["hyperlinks"])
                
                # Log image extraction results
                if extracted_images:
                    logger.info(f"Extracted {len(extracted_images)} images from Excel file {filename}")
                    
            else:
                # Use standard text extraction for other file types
                text_content = self._extract_text_from_attachment(payload, content_type, filename)
                if text_content:
                    attachment_info["text_content"] = text_content
                    # Extract URLs from text content
                    urls = self._extract_urls_from_text(text_content)
                    attachment_info["urls"] = urls
        
        # Remove duplicate URLs
        attachment_info["urls"] = list(set(attachment_info["urls"]))
        
        # ENHANCED: Detect nested emails using multiple criteria
        # BUT exclude message/rfc822 since those are handled by walk_layers
        is_nested_email = (
            (filename.lower().endswith('.eml') or self._is_email_content_heuristic(payload)) and
            content_type != "message/rfc822"  # FIXED: Exclude MIME parts handled by walk_layers
        )
        
        attachment_info["is_nested_email"] = is_nested_email
        
        if is_nested_email:
            logger.info(f"Detected attachment-based nested email: {filename} (content_type: {content_type})")

        logger.debug(
            "Attachment %s processed: size=%d, nested_email=%s, content_type=%s, images=%d",
            filename,
            file_size,
            is_nested_email,
            content_type,
            len(attachment_info["embedded_images"])
        )

        return attachment_info
    
    def _extract_from_excel_with_images(self, payload: bytes, filename: str, 
                                      output_dir: str) -> tuple[Optional[str], List[Dict]]:
        """Extract text and images from Excel files."""
        try:
            logger.debug(f"Extracting text and images from Excel file: {filename}")
            
            # Create subdirectory for this Excel file's images
            excel_image_dir = os.path.join(output_dir, f"{Path(filename).stem}_images")
            os.makedirs(excel_image_dir, exist_ok=True)
            
            # Use enhanced extraction
            text_content, extracted_images = extract_excel_with_images(payload, excel_image_dir)
            
            logger.debug(f"Excel extraction results: {len(text_content) if text_content else 0} chars text, {len(extracted_images)} images")
            
            return text_content, extracted_images
            
        except Exception as e:
            logger.warning(f"Error extracting from Excel file {filename}: {e}")
            # Fallback to basic text extraction
            try:
                text_content = extract_text_from_excel(payload)
                return text_content, []
            except Exception as fallback_e:
                logger.error(f"Fallback Excel extraction also failed for {filename}: {fallback_e}")
                return f"[Error extracting Excel content: {e}]", []
    
    def _extract_text_from_attachment(self, payload: bytes, content_type: str, 
                                    filename: str) -> Optional[str]:
        """Extract text content from attachment based on content type."""
        try:
            if content_type == 'application/pdf':
                return extract_text_from_pdf(payload)
            elif content_type.startswith('text/'):
                # Try to decode as text
                for encoding in ['utf-8', 'utf-16', 'iso-8859-1', 'cp1252']:
                    try:
                        return payload.decode(encoding)
                    except UnicodeDecodeError:
                        continue
                return payload.decode('utf-8', errors='replace')
            elif content_type == 'text/html':
                # Import here to avoid circular import
                from ..core.html_cleaner import PhishingEmailHtmlCleaner
                html_text = payload.decode('utf-8', errors='replace')
                return PhishingEmailHtmlCleaner.clean_html(html_text)
            elif content_type in [
                'application/vnd.ms-excel',
                'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
            ]:
                # This case is now handled by _extract_from_excel_with_images
                # But keep for backwards compatibility
                logger.debug(f"Using basic Excel extraction for: {filename}")
                return extract_text_from_excel(payload)
            elif content_type in [
                'application/msword',
                'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
            ]:
                return self._extract_from_office_doc(payload, filename)
            else:
                # Try to extract as plain text for other types
                try:
                    # Check if it looks like text first
                    if self._is_likely_text_content(payload):
                        return payload.decode('utf-8', errors='replace')[:1000]  # Limit size
                    else:
                        return f"[Binary file: {content_type}]"
                except Exception:
                    return f"[Could not extract text from {content_type}]"
        except Exception as e:
            logger.warning(f"Error extracting text from {filename}: {e}")
            return f"[Error extracting text: {e}]"
    
    def _is_likely_text_content(self, payload: bytes) -> bool:
        """Check if binary payload is likely to contain text."""
        if not payload:
            return False
        
        # Sample first 1000 bytes
        sample = payload[:1000]
        
        # Count printable ASCII characters
        printable_count = sum(1 for b in sample if 32 <= b <= 126 or b in [9, 10, 13])
        ratio = printable_count / len(sample)
        
        # If more than 70% printable ASCII, likely text
        return ratio > 0.7
    
    def _extract_from_office_doc(self, payload: bytes, filename: str) -> Optional[str]:
        """Extract text from Office documents."""
        try:
            # Try to use python-docx for Word documents
            if filename.lower().endswith('.docx'):
                try:
                    from io import BytesIO

                    import docx
                    doc = docx.Document(BytesIO(payload))
                    return '\n'.join([paragraph.text for paragraph in doc.paragraphs])
                except ImportError:
                    logger.warning("python-docx not available for .docx extraction")
                except Exception as e:
                    logger.warning(f"Error with docx extraction: {e}")
            
            # For other Office formats or fallback, try basic text extraction
            text = payload.decode('utf-8', errors='replace')
            # Filter out binary noise, keep only printable text
            import string
            printable = set(string.printable)
            filtered_text = ''.join(filter(lambda x: x in printable, text))
            if len(filtered_text) > 50:  # Only return if we got substantial text
                return filtered_text[:2000]  # Limit size
            return None
        except Exception as e:
            logger.warning(f"Error extracting from Office document {filename}: {e}")
            return None
    
    def _extract_urls_from_text(self, text: str) -> List[str]:
        """Extract URLs from text content."""
        if not text:
            return []
            
        # Pattern to match URLs
        url_pattern = re.compile(
            r'https?://[^\s<>"{}|\\^`\[\]]+|www\.[^\s<>"{}|\\^`\[\]]+',
            re.IGNORECASE
        )
        
        urls = url_pattern.findall(text)
        # Clean up URLs (remove trailing punctuation)
        cleaned_urls = []
        for url in urls:
            cleaned = url.rstrip('.,;:!?)]}')
            if cleaned:
                cleaned_urls.append(cleaned)
        
        return list(set(cleaned_urls))  # Remove duplicates

    def _is_email_content_heuristic(self, data: bytes) -> bool:
        """Enhanced heuristic to detect if attachment content is an email."""
        try:
            # Try to decode as text and look for email headers
            if isinstance(data, bytes):
                text_data = data.decode('utf-8', errors='replace')[:2000]  # Check first 2000 chars
            else:
                text_data = str(data)[:2000]
            
            # Look for common email headers (more comprehensive list)
            email_indicators = [
                'Received:', 'From:', 'To:', 'Subject:', 'Date:', 'Message-ID:', 
                'Return-Path:', 'X-Mailer:', 'MIME-Version:', 'Content-Type:',
                'Delivered-To:', 'X-Originating-IP:', 'Authentication-Results:',
                'DKIM-Signature:', 'Authentication-Results:'
            ]
            
            found_headers = sum(1 for indicator in email_indicators if indicator in text_data)
            
            # Also check for typical email structure patterns
            has_header_block = bool(re.search(r'^[A-Za-z-]+:\s+.+$', text_data, re.MULTILINE))
            has_mime_boundary = 'boundary=' in text_data
            
            # If we find multiple email headers or typical email structure, it's likely an email
            is_email = (found_headers >= 3) or (found_headers >= 2 and (has_header_block or has_mime_boundary))
            
            if is_email:
                logger.debug(f"Content analysis detected email: {found_headers} headers found")
            
            return is_email
            
        except Exception as e:
            logger.debug(f"Error in email content heuristic: {e}")
            return False