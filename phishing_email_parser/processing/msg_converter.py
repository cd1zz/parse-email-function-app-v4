"""
MSG to EML converter for phishing email analysis.

Converts Microsoft Outlook .msg files to standard .eml format.
"""

import os
import logging
import mimetypes
from pathlib import Path
from typing import Tuple, List
from email.message import EmailMessage

logger = logging.getLogger(__name__)


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
            eml = self._create_eml_from_msg(msg)
            
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
    
    def _create_eml_from_msg(self, msg) -> EmailMessage:
        """Create an EmailMessage from a MSG object."""
        eml = EmailMessage()
        
        # Handle body content first to detect nested emails
        body_text = msg.body or ""
        html_body = getattr(msg, 'htmlBody', None)
        nested_headers = {}
        
        # Check if body_text looks like base64 encoded email (common issue with MSG files)
        if body_text and len(body_text) > 100:
            try:
                import base64
                import email
                from email import policy
                
                # Try to decode as base64 and parse as email
                if body_text.replace('\n', '').replace('\r', '').replace('=', '').isalnum() or '+' in body_text or '/' in body_text:
                    try:
                        decoded_bytes = base64.b64decode(body_text)
                        nested_msg = email.message_from_bytes(decoded_bytes, policy=policy.default)
                        
                        # If successful, extract the actual body from the nested email
                        if nested_msg.get('Subject') or nested_msg.get('From'):
                            logger.info("Found nested email in MSG body, extracting content")
                            
                            # Get body from nested email
                            if nested_msg.is_multipart():
                                for part in nested_msg.walk():
                                    if part.get_content_type() == "text/plain" and not part.get_filename():
                                        body_text = part.get_content()
                                        break
                                    elif part.get_content_type() == "text/html" and not part.get_filename():
                                        html_body = part.get_content()
                            else:
                                if nested_msg.get_content_type() == "text/plain":
                                    body_text = nested_msg.get_content()
                                elif nested_msg.get_content_type() == "text/html":
                                    html_body = nested_msg.get_content()
                                    
                            # Store headers from nested email for later use
                            if nested_msg.get('Date'):
                                nested_headers['Date'] = nested_msg.get('Date')
                            
                            # Store received headers
                            received_headers = nested_msg.get_all('Received')
                            if received_headers:
                                nested_headers['Received'] = received_headers
                            
                            # Store X-headers
                            for key, value in nested_msg.items():
                                if key.lower().startswith('x-'):
                                    nested_headers[key] = value
                                    
                    except Exception as decode_error:
                        logger.debug(f"Base64 decode attempt failed: {decode_error}")
            except ImportError:
                pass
        
        # Clean body content
        if body_text:
            body_text = self._clean_header_value(body_text)
        
        # Convert HTML body to string if it's bytes and clean it
        if html_body:
            if isinstance(html_body, bytes):
                html_body = html_body.decode('utf-8', errors='replace')
            html_body = self._clean_header_value(html_body)
        
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
        
        # Add received headers from nested email if available
        if 'Received' in nested_headers:
            for received in nested_headers['Received']:
                eml['Received'] = received
        
        # Add X-headers from nested email
        for key, value in nested_headers.items():
            if key.lower().startswith('x-') and key not in eml:
                eml[key] = value
        
        # Try to extract additional headers from the raw header data
        try:
            if hasattr(msg, 'header') and msg.header:
                header_dict = msg.header
                if isinstance(header_dict, dict):
                    for key, value in header_dict.items():
                        clean_key = self._clean_header_value(key)
                        clean_value = self._clean_header_value(value)
                        ignore_headers = [
                            'subject', 'from', 'to', 'cc', 'bcc', 'date',
                            'message-id', 'content-type', 'mime-version',
                            'content-transfer-encoding'
                        ]
                        if clean_key and clean_value and clean_key.lower() not in ignore_headers:
                            eml[clean_key] = clean_value
        except Exception as e:
            logger.debug(f"Could not extract additional headers: {e}")
        
        # Try to get raw header string and parse additional headers
        try:
            if hasattr(msg, 'headerDict') and msg.headerDict:
                for key, value in msg.headerDict.items():
                    clean_key = self._clean_header_value(key)
                    clean_value = self._clean_header_value(value)
                    if clean_key and clean_value:
                        # Avoid overwriting already set headers and ignore multipart indicators
                        if clean_key.lower() not in [h.lower() for h in eml.keys()] and clean_key.lower() not in ['content-type', 'mime-version', 'content-transfer-encoding']:
                            eml[clean_key] = clean_value
        except Exception as e:
            logger.debug(f"Could not extract header dict: {e}")
        
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
            eml.set_content(body_text, subtype='plain')
        
        # Add attachments AFTER setting content
        if hasattr(msg, 'attachments') and msg.attachments:
            for idx, attachment in enumerate(msg.attachments):
                self._add_attachment_to_eml(eml, attachment, idx)
        
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