# ============================================================================
# phishing_email_parser/processing/msg_converter.py
# ============================================================================
"""MSG to EML converter for phishing email analysis."""

import logging
from pathlib import Path

logger = logging.getLogger(__name__)


class MSGConverter:
    """Convert .msg files to .eml format."""
    
    def __init__(self):
        self._extract_msg = None
        self._import_extract_msg()
    
    def _import_extract_msg(self):
        """Safely import extract_msg library."""
        try:
            import extract_msg
            self._extract_msg = extract_msg
        except ImportError:
            logger.error("extract_msg library not available. Install with: pip install extract-msg")
    
    def convert_msg_to_eml(self, msg_path: str, output_dir: str) -> str:
        """Convert a .msg file to .eml format."""
        if not self._extract_msg:
            raise RuntimeError("extract_msg library not available")

        msg_path = Path(msg_path)
        if not msg_path.exists():
            raise FileNotFoundError(f"MSG file not found: {msg_path}")

        # Generate EML filename
        eml_filename = msg_path.stem + ".eml"
        eml_path = Path(output_dir) / eml_filename
        
        try:
            # Load the MSG file
            msg = self._extract_msg.Message(str(msg_path))
            
            # Simple conversion - this is a basic implementation
            with eml_path.open('w', encoding='utf-8') as f:
                f.write(f"Subject: {getattr(msg, 'subject', '')}\n")
                f.write(f"From: {getattr(msg, 'sender', '')}\n")
                f.write(f"To: {getattr(msg, 'to', '')}\n")
                f.write(f"Date: {getattr(msg, 'date', '')}\n")
                f.write("\n")
                f.write(getattr(msg, 'body', '') or "")
            
            logger.info(f"Converted {msg_path} to {eml_path}")
            return str(eml_path)
            
        except Exception as e:
            logger.error(f"Error converting MSG file {msg_path}: {e}")
            raise