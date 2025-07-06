# ============================================================================
# phishing_email_parser/processing/pdf_utils.py
# ============================================================================
"""PDF text extraction utilities."""

import io
import logging

logger = logging.getLogger(__name__)


def extract_text_from_pdf(pdf_data: bytes) -> str:
    """Extract text content from PDF binary data."""
    try:
        from pdfminer.high_level import extract_text
        
        pdf_file = io.BytesIO(pdf_data)
        text = extract_text(pdf_file)
        return text.strip()
    except ImportError:
        logger.warning("pdfminer not available for PDF text extraction")
        return "[PDF content - pdfminer not available]"
    except Exception as e:
        logger.error(f"Error extracting text from PDF: {e}")
        return f"[Error extracting PDF text: {e}]"