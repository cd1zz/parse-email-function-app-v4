import io
import logging

from pdfminer.high_level import extract_text

logger = logging.getLogger(__name__)


def extract_text_from_pdf(pdf_data: bytes) -> str:
    """Extract text content from PDF binary data."""
    try:
        pdf_file = io.BytesIO(pdf_data)
        text = extract_text(pdf_file)
        return text.strip()
    except Exception as e:
        logger.error(f"Error extracting text from PDF: {e}")
        return f"[Error extracting PDF text: {e}]"
