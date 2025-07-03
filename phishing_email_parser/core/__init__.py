"""Core email processing modules."""
from .carrier_detector import is_carrier, CARRIER_PATTERNS, detect_vendor
from .html_cleaner import PhishingEmailHtmlCleaner
from .mime_walker import walk_layers

__all__ = ["is_carrier", "CARRIER_PATTERNS", "detect_vendor", "PhishingEmailHtmlCleaner", "walk_layers"]
