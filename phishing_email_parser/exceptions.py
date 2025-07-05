"""Custom exceptions for the phishing email parser."""

from __future__ import annotations


class EmailParserError(Exception):
    """Base class for parser errors."""


class AttachmentProcessingError(EmailParserError):
    """Raised when attachment processing fails."""
