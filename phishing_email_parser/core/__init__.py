"""Core email processing modules."""
from .carrier_detector import is_carrier, CARRIER_PATTERNS
from .html_cleaner import PhishingEmailHtmlCleaner
from .mime_walker import walk_layers

__all__ = ["is_carrier", "CARRIER_PATTERNS", "PhishingEmailHtmlCleaner", "walk_layers"]
