"""
MSG to EML converter for phishing email analysis.

Converts Microsoft Outlook .msg files to standard .eml format.
"""

import os
import logging
import mimetypes
from pathlib import Path
from typing import Tuple, List, Optional
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
    
    def _create_eml_from_msg(self, msg) -> EmailMessage:
        """Create an EmailMessage from a MSG object."""
        eml = EmailMessage()
        
        # Set headers
        if msg.subject:
            eml['Subject'] = msg.subject
        if msg.sender:
            eml['From'] = msg.sender
        if msg.to:
            eml['To'] = ', '.join(msg.to) if isinstance(msg.to, list) else msg.to
        if msg.cc:
            eml['Cc'] = ', '.join(msg.cc) if isinstance(msg.cc, list) else msg.cc
        if msg.bcc:
            eml['Bcc'] = ', '.join(msg.bcc) if isinstance(msg.bcc, list) else msg.bcc
        if msg.date:
            eml['Date'] = str(msg.date)
        if hasattr(msg, 'messageId') and msg.messageId:
            eml['Message-ID'] = msg.messageId
        
        # Set body content
        body_text = msg.body or ""
        html_body = getattr(msg, 'htmlBody', None)
        
        if html_body and body_text:
            # Both HTML and text - create multipart
            eml.set_content(body_text)
            if isinstance(html_body, bytes):
                html_body = html_body.decode('utf-8', errors='replace')
            eml.add_alternative(html_body, subtype='html')
        elif html_body:
            # HTML only
            if isinstance(html_body, bytes):
                html_body = html_body.decode('utf-8', errors='replace')
            eml.add_alternative(html_body, subtype='html')
            eml.set_content("")  # Add empty text part
        else:
            # Text only or no body
            eml.set_content(body_text)
        
        # Add attachments
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
                "subject": getattr(msg, 'subject', ''),
                "sender": getattr(msg, 'sender', ''),
                "to": getattr(msg, 'to', []),
                "cc": getattr(msg, 'cc', []),
                "date": str(getattr(msg, 'date', '')),
                "attachment_count": len(getattr(msg, 'attachments', [])),
                "has_html_body": bool(getattr(msg, 'htmlBody', None)),
                "has_text_body": bool(getattr(msg, 'body', None))
            }
        except Exception as e:
            logger.error(f"Error reading MSG info from {msg_path}: {e}")
            return {"error": str(e)}