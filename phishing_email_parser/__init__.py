"""
Phishing Email Parser Package
"""
from .main_parser import PhishingEmailParser
from .core.carrier_detector import is_carrier, CARRIER_PATTERNS
from .core.html_cleaner import PhishingEmailHtmlCleaner

__version__ = "1.0.0"
__all__ = ["PhishingEmailParser", "is_carrier", "CARRIER_PATTERNS", "PhishingEmailHtmlCleaner"]
