"""Core email processing modules."""
from .carrier_detector import CARRIER_PATTERNS, detect_vendor, is_carrier
from .html_cleaner import PhishingEmailHtmlCleaner
from .mime_walker import walk_layers

__all__ = ["is_carrier", "CARRIER_PATTERNS", "detect_vendor", "PhishingEmailHtmlCleaner", "walk_layers"]
