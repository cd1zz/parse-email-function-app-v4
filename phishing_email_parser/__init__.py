# ============================================================================
# phishing_email_parser/__init__.py
# ============================================================================
"""
Production Phishing Email Parser Package

A comprehensive, production-ready Python package for parsing and analyzing phishing emails
with SOLID architecture, dependency injection, and Azure Function integration.
"""

# Import core functionality for backward compatibility
try:

    from .config_manager import ParserConfiguration, get_default_config, get_azure_config
    from .data_models import ParsingResult, EmailLayer, StructuralSummary  # Updated import
    from .exceptions import PhishingParserError, EmailParsingError, SecurityViolationError
    PRODUCTION_AVAILABLE = True
except ImportError as e:
    print(f"Import error in phishing_email_parser: {e}")
    PRODUCTION_AVAILABLE = False

__version__ = "2.0.0"
__architecture__ = "solid_di_production"

__all__ = [
    "create_production_parser",
    "ProductionEmailParser", 
    "ParserConfiguration",
    "get_default_config",
    "get_azure_config",
    "ParsingResult",
    "EmailLayer",
    "PhishingParserError",
    "EmailParsingError",
    "SecurityViolationError"
]

# Remove the problematic function that's causing the NameError
# If you need this function, define it after the imports above

# ============================================================================
# phishing_email_parser/core/__init__.py
# ============================================================================
"""Core email processing modules."""
__all__ = ["html_cleaner", "mime_walker", "carrier_detector"]

# ============================================================================
# phishing_email_parser/processing/__init__.py
# ============================================================================
"""Email processing utilities."""
__all__ = ["attachment_processor", "msg_converter", "pdf_utils", "excel_utils"]

# ============================================================================
# phishing_email_parser/url_processing/__init__.py
# ============================================================================
"""URL processing utilities."""
__all__ = ["processor", "decoder", "validator"]

# ============================================================================
# phishing_email_parser/utils/__init__.py
# ============================================================================
"""Utility modules."""
__all__ = []