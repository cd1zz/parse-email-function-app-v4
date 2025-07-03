"""
MSG to EML converter for phishing email analysis.

Converts Microsoft Outlook .msg files to standard .eml format with
enhanced MIME attachment detection for embedded HTML content.
"""

import os
import logging
import mimetypes
import re
import base64
import binascii
import textwrap
import email
import html
from email import policy
from pathlib import Path
from typing import Tuple, List, Optional, Dict, Any
from email.message import EmailMessage

logger = logging.getLogger(__name__)

# new, looser detector: any big block of base-64, try to decode it
_BASE64_BLOB = re.compile(r'(?:^|\n)([A-Za-z0-9+/=\r\n]{800,})', re.DOTALL)


def _pull_inline_emls(text: str):
    """Detect & strip inline base-64 messages even when headers are encoded."""
    nested = []
    for m in _BASE64_BLOB.finditer(text):
        blob = re.sub(r'\s+', '', m.group(1))  # trim newlines / spaces
        try:
            payload = base64.b64decode(blob, validate=True)
        except binascii.Error:
            continue  # not valid base-64
        msg = email.message_from_bytes(payload, policy=policy.default)
        if msg.get('From') or msg.get('Subject'):
            nested.append(msg)
            text = text.replace(m.group(0), '')
    return text, nested


def extract_mime_attachments_from_html(html_content: str, output_dir: str) -> List[Dict[str, Any]]:
    """
    Extract MIME-structured attachments from HTML content.
    
    This handles cases where HTML contains embedded MIME structure with
    proper boundaries, headers, and base64 content.
    """
    attachments = []
    
    if not html_content:
        return attachments
    
    logger.debug(f"Analyzing HTML content of {len(html_content)} chars for MIME structure")
    
    # Look for MIME boundary patterns
    boundary_pattern = re.compile(r'--([a-zA-Z0-9_\-]+)', re.MULTILINE)
    boundaries = boundary_pattern.findall(html_content)
    
    if not boundaries:
        logger.debug("No MIME boundaries found in HTML")
        return attachments
    
    logger.debug(f"Found {len(set(boundaries))} unique MIME boundaries")
    
    # For each boundary, try to parse MIME parts
    for boundary in set(boundaries):
        try:
            parts = extract_mime_parts_by_boundary(html_content, boundary, output_dir)
            attachments.extend(parts)
        except Exception as e:
            logger.debug(f"Error processing boundary {boundary}: {e}")
    
    return attachments


def extract_mime_parts_by_boundary(content: str, boundary: str, output_dir: str) -> List[Dict[str, Any]]:
    """Extract MIME parts using a specific boundary."""
    parts = []
    
    # Split content by boundary
    boundary_marker = f"--{boundary}"
    sections = content.split(boundary_marker)
    
    logger.debug(f"Boundary {boundary} splits content into {len(sections)} sections")
    
    for idx, section in enumerate(sections):
        if not section.strip():
            continue
            
        # Skip end markers
        if section.strip() == "--":
            continue
        
        try:
            attachment_info = parse_mime_section(section, idx, output_dir, boundary)
            if attachment_info:
                parts.append(attachment_info)
        except Exception as e:
            logger.debug(f"Error parsing MIME section {idx}: {e}")
    
    return parts


def parse_mime_section(section: str, section_idx: int, output_dir: str, boundary: str) -> Optional[Dict[str, Any]]:
    """Parse a single MIME section and extract attachment if present."""
    
    # Look for Content-Type header
    content_type_match = re.search(r'Content-Type:\s*([^;\r\n]+)', section, re.IGNORECASE)
    if not content_type_match:
        return None
    
    content_type = content_type_match.group(1).strip()
    
    # Look for filename
    filename_match = re.search(r'(?:filename|name)=["\']?([^"\';\r\n]+)["\']?', section, re.IGNORECASE)
    filename = filename_match.group(1).strip() if filename_match else f"mime_attachment_{boundary}_{section_idx}"
    
    # Look for Content-Transfer-Encoding
    encoding_match = re.search(r'Content-Transfer-Encoding:\s*([^\r\n]+)', section, re.IGNORECASE)
    encoding = encoding_match.group(1).strip() if encoding_match else None
    
    # Only process base64 encoded content for now
    if not encoding or encoding.lower() != 'base64':
        return None
    
    logger.debug(f"MIME section {section_idx}: {content_type}, filename={filename}, encoding={encoding}")
    
    # Extract the actual content (after headers)
    # Find where headers end and base64 content starts
    content_start = None
    lines = section.split('\n')
    
    for i, line in enumerate(lines):
        # Look for start of base64 content
        if re.match(r'^[A-Za-z0-9+/=]{50,}', line.strip()):
            content_start = i
            break
        # Or empty line after headers
        elif line.strip() == "" and i + 1 < len(lines) and re.match(r'^[A-Za-z0-9+/=]{50,}', lines[i + 1].strip()):
            content_start = i + 1
            break
    
    if content_start is None:
        logger.debug(f"Could not find content start in section {section_idx}")
        return None
    
    # Extract content from that point
    content_lines = lines[content_start:]
    content_data = '\n'.join(content_lines).strip()
    
    # Remove any HTML tags that might be in the content
    content_data = re.sub(r'<[^>]+>', '', content_data)
    content_data = html.unescape(content_data)
    
    # Clean base64 content
    clean_b64 = re.sub(r'[^A-Za-z0-9+/=]', '', content_data)
    
    # Ensure proper padding
    while len(clean_b64) % 4:
        clean_b64 += '='
    
    if len(clean_b64) < 100:  # Too short to be meaningful
        return None
    
    try:
        decoded_content = base64.b64decode(clean_b64, validate=True)
        logger.info(f"Successfully decoded base64 content: {len(decoded_content)} bytes")
    except Exception as e:
        logger.warning(f"Failed to decode base64 content: {e}")
        return None
    
    # Save to disk
    os.makedirs(output_dir, exist_ok=True)
    file_path = os.path.join(output_dir, filename)
    
    try:
        with open(file_path, 'wb') as f:
            f.write(decoded_content)
        logger.info(f"Extracted MIME attachment: {filename} ({len(decoded_content)} bytes)")
    except Exception as e:
        logger.error(f"Failed to save attachment {filename}: {e}")
        file_path = None
    
    attachment_info = {
        "filename": filename,
        "content_type": content_type,
        "size": len(decoded_content),
        "encoding": encoding,
        "disk_path": file_path,
        "is_mime_attachment": True,
        "section_index": section_idx,
        "boundary": boundary
    }
    
    # If this looks like an email file, try to parse it
    if (filename.lower().endswith('.eml') or 
        content_type.lower().startswith('message/') or
        decoded_content.startswith(b'Received:')):
        
        try:
            # Parse as email message
            email_msg = email.message_from_bytes(decoded_content, policy=policy.default)
            if email_msg.get('From') or email_msg.get('Subject'):
                attachment_info["is_email"] = True
                attachment_info["email_subject"] = email_msg.get('Subject', 'No Subject')
                attachment_info["email_from"] = email_msg.get('From', 'No From')
                attachment_info["email_date"] = email_msg.get('Date', 'No Date')
                logger.info(f"Extracted email attachment: {attachment_info['email_subject']}")
        except Exception as e:
            logger.debug(f"Could not parse as email: {e}")
    
    return attachment_info


class MSGConverter:
    """Convert .msg files to .eml format."""
    
    def __init__(self):
        """Initialize the converter."""
        self._extract_msg = None
        self._import_extract_msg()
    
    def _import_extract_msg(self):
        """Safely import extract_msg library."""
        try:
            import extract_msg
            self._extract_msg = extract_msg
        except ImportError:
            logger.error("extract_msg library not available. Install with: pip install extract-msg")
            raise ImportError("extract_msg library required for .msg file processing")
    
    def convert_msg_to_eml(self, msg_path: str, output_dir: str) -> str:
        """
        Convert a .msg file to .eml format.
        
        Args:
            msg_path: Path to the .msg file
            output_dir: Directory to save the .eml file
            
        Returns:
            Path to the created .eml file
        """
        if not self._extract_msg:
            raise RuntimeError("extract_msg library not available")
            
        msg_path = Path(msg_path)
        if not msg_path.exists():
            raise FileNotFoundError(f"MSG file not found: {msg_path}")
            
        # Create output directory
        os.makedirs(output_dir, exist_ok=True)
        
        # Generate EML filename
        eml_filename = msg_path.stem + ".eml"
        eml_path = os.path.join(output_dir, eml_filename)
        
        try:
            # Load the MSG file
            msg = self._extract_msg.Message(str(msg_path))
            
            # Create EML message
            eml = self._create_eml_from_msg(msg, output_dir)
            
            # Save EML file
            with open(eml_path, 'wb') as f:
                f.write(eml.as_bytes())
                
            # Extract attachments to output directory
            self._extract_attachments(msg, output_dir)
            
            logger.info(f"Converted {msg_path} to {eml_path}")
            return eml_path
            
        except Exception as e:
            logger.error(f"Error converting MSG file {msg_path}: {e}")
            raise
    
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
    
    def _create_eml_from_msg(self, msg, output_dir: str) -> EmailMessage:
        """Create an EmailMessage from a MSG object."""
        eml = EmailMessage()
        
        # Handle body content first to detect nested emails
        body_text = msg.body or ""
        html_body = getattr(msg, 'htmlBody', None)
        nested_headers = {}

        body_text, inline_emls = _pull_inline_emls(body_text)
        
        # Clean body content
        if body_text:
            body_text = self._clean_header_value(body_text)
        
        # Convert HTML body to string if it's bytes and clean it
        if html_body:
            if isinstance(html_body, bytes):
                html_body = html_body.decode('utf-8', errors='replace')
            html_body = self._clean_header_value(html_body)
        
        # ENHANCED: Extract MIME attachments from HTML body
        mime_attachments = []
        if html_body:
            logger.info(f"Analyzing HTML body for MIME attachments ({len(html_body)} chars)")
            mime_attachments = extract_mime_attachments_from_html(html_body, output_dir)
            
            # Clean HTML by removing MIME content for better readability
            if mime_attachments:
                # Remove MIME boundaries and large base64 blocks
                cleaned_html = re.sub(r'--[a-zA-Z0-9_\-]+.*?(?=--[a-zA-Z0-9_\-]+|$)', '[MIME content extracted as attachment]', html_body, flags=re.DOTALL)
                cleaned_html = re.sub(r'[A-Za-z0-9+/=\r\n\s]{200,}', '[Base64 content extracted]', cleaned_html)
                html_body = cleaned_html
        
        # Set basic headers with cleaning BEFORE setting content
        if msg.subject:
            eml['Subject'] = self._clean_header_value(msg.subject)
        if msg.sender:
            eml['From'] = self._clean_header_value(msg.sender)
        if msg.to:
            if isinstance(msg.to, list):
                eml['To'] = ', '.join([self._clean_header_value(addr) for addr in msg.to])
            else:
                eml['To'] = self._clean_header_value(msg.to)
        if msg.cc:
            if isinstance(msg.cc, list):
                eml['Cc'] = ', '.join([self._clean_header_value(addr) for addr in msg.cc])
            else:
                eml['Cc'] = self._clean_header_value(msg.cc)
        if msg.bcc:
            if isinstance(msg.bcc, list):
                eml['Bcc'] = ', '.join([self._clean_header_value(addr) for addr in msg.bcc])
            else:
                eml['Bcc'] = self._clean_header_value(msg.bcc)
        
        # Use nested email date if main MSG doesn't have one
        if msg.date:
            eml['Date'] = self._clean_header_value(str(msg.date))
        elif 'Date' in nested_headers:
            eml['Date'] = nested_headers['Date']
            
        if hasattr(msg, 'messageId') and msg.messageId:
            eml['Message-ID'] = self._clean_header_value(msg.messageId)
        
        # Set content based on what's available - MUST DO THIS BEFORE ADDING ATTACHMENTS
        if html_body and body_text:
            # Both HTML and text - create multipart/alternative
            eml.set_content(body_text, subtype='plain')
            eml.add_alternative(html_body, subtype='html')
        elif html_body:
            # HTML only
            eml.set_content(html_body, subtype='html')
        else:
            # Text only or no body
            eml.set_content(body_text or '(empty)', subtype='plain')

        # Add inline emails from basic base64 detection
        for idx, m in enumerate(inline_emls):
            eml.add_attachment(
                m.as_bytes(),
                maintype='message',
                subtype='rfc822',
                filename=f'inline_{idx}.eml'
            )
        
        # Add MIME-extracted attachments
        for attachment in mime_attachments:
            try:
                if attachment.get("disk_path") and os.path.exists(attachment["disk_path"]):
                    with open(attachment["disk_path"], 'rb') as f:
                        attachment_data = f.read()
                    
                    # Determine maintype and subtype
                    content_type = attachment.get("content_type", "application/octet-stream")
                    if '/' in content_type:
                        maintype, subtype = content_type.split('/', 1)
                    else:
                        maintype, subtype = "application", "octet-stream"
                    
                    eml.add_attachment(
                        attachment_data,
                        maintype=maintype,
                        subtype=subtype,
                        filename=attachment["filename"]
                    )
                    
                    logger.info(f"Added MIME attachment to EML: {attachment['filename']}")
                    
            except Exception as e:
                logger.error(f"Failed to add MIME attachment {attachment.get('filename', 'unknown')}: {e}")

        # Add regular attachments AFTER setting content
        if hasattr(msg, 'attachments') and msg.attachments:
            for idx, attachment in enumerate(msg.attachments):
                self._add_attachment_to_eml(eml, attachment, idx)
        
        logger.info(f"Created EML with {len(mime_attachments)} MIME attachments and {len(inline_emls)} inline emails")
        return eml
    
    def _add_attachment_to_eml(self, eml: EmailMessage, attachment, index: int):
        """Add an attachment to the EML message."""
        try:
            # Get attachment data
            filename = (
                getattr(attachment, 'longFilename', None) or
                getattr(attachment, 'shortFilename', None) or
                f"attachment_{index}"
            )
            
            # Strip null terminators and other problematic characters
            if filename:
                filename = self._clean_header_value(filename)
            
            data = getattr(attachment, 'data', None)
            if not data:
                logger.warning(f"No data found for attachment {filename}")
                return
            
            # Guess MIME type
            mime_type, _ = mimetypes.guess_type(filename)
            if not mime_type:
                mime_type = 'application/octet-stream'
            
            maintype, subtype = mime_type.split('/', 1)
            
            # Add attachment
            eml.add_attachment(
                data,
                maintype=maintype,
                subtype=subtype,
                filename=filename
            )
            
        except Exception as e:
            logger.warning(f"Error adding attachment {index} to EML: {e}")
    
    def _extract_attachments(self, msg, output_dir: str) -> List[Tuple[str, str]]:
        """Extract attachments from MSG to disk."""
        attachment_paths = []
        
        if not hasattr(msg, 'attachments') or not msg.attachments:
            return attachment_paths
        
        for idx, attachment in enumerate(msg.attachments):
            try:
                filename = (
                    getattr(attachment, 'longFilename', None) or
                    getattr(attachment, 'shortFilename', None) or
                    f"attachment_{idx}"
                )
                
                # Strip null terminators and other problematic characters
                if filename:
                    filename = self._clean_header_value(filename)
                
                data = getattr(attachment, 'data', None)
                if not data:
                    continue
                
                # Save to disk
                file_path = os.path.join(output_dir, filename)
                with open(file_path, 'wb') as f:
                    f.write(data)
                
                attachment_paths.append((filename, file_path))
                logger.debug(f"Extracted attachment: {filename}")
                
            except Exception as e:
                logger.warning(f"Error extracting attachment {idx}: {e}")
        
        return attachment_paths
    
    def get_msg_info(self, msg_path: str) -> dict:
        """Get basic information about a MSG file without full conversion."""
        if not self._extract_msg:
            raise RuntimeError("extract_msg library not available")
            
        try:
            msg = self._extract_msg.Message(msg_path)
            
            return {
                "subject": self._clean_header_value(getattr(msg, 'subject', '')),
                "sender": self._clean_header_value(getattr(msg, 'sender', '')),
                "to": getattr(msg, 'to', []),
                "cc": getattr(msg, 'cc', []),
                "date": self._clean_header_value(str(getattr(msg, 'date', ''))),
                "attachment_count": len(getattr(msg, 'attachments', [])),
                "has_html_body": bool(getattr(msg, 'htmlBody', None)),
                "has_text_body": bool(getattr(msg, 'body', None))
            }
        except Exception as e:
            logger.error(f"Error reading MSG info from {msg_path}: {e}")
            return {"error": str(e)}