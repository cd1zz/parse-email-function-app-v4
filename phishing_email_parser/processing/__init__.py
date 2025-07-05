# phishing_email_parser/processing/__init__.py
"""Email processing utilities."""
from .attachment_processor import AttachmentProcessor
from .msg_converter import MSGConverter
from .pdf_utils import extract_text_from_pdf
from .excel_utils import extract_text_from_excel

__all__ = ["AttachmentProcessor", "MSGConverter", "extract_text_from_pdf", "extract_text_from_excel"]