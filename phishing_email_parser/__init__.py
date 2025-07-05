"""
Phishing Email Parser Package
"""
from .core.carrier_detector import CARRIER_PATTERNS, is_carrier
from .core.html_cleaner import PhishingEmailHtmlCleaner
from .main_parser import PhishingEmailParser

__version__ = "1.0.0"
__all__ = ["PhishingEmailParser", "is_carrier", "CARRIER_PATTERNS", "PhishingEmailHtmlCleaner"]
