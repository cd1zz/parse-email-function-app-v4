# phishing_email_parser/processing/__init__.py
"""Email processing utilities."""
from .attachment_processor import AttachmentProcessor
from .msg_converter import MSGConverter
from .pdf_utils import extract_text_from_pdf

__all__ = ["AttachmentProcessor", "MSGConverter", "extract_text_from_pdf"]