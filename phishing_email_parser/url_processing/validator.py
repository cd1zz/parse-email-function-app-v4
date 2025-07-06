# ============================================================================
# phishing_email_parser/url_processing/validator.py
# ============================================================================
"""URL validator module for validating and cleaning URLs."""

import logging
import re
import urllib.parse

logger = logging.getLogger(__name__)


class UrlValidator:
    """Class for URL validation operations."""

    # List of known URL shortener domains
    URL_SHORTENER_PROVIDERS = [
        "bit.ly", "t.co", "goo.gl", "ow.ly", "tinyurl.com", "is.gd", "buff.ly",
        "rebrandly.com", "cutt.ly", "bl.ink", "snip.ly", "su.pr", "lnkd.in",
        "fb.me", "cli.gs", "sh.st", "mcaf.ee", "yourls.org", "v.gd", "s.id",
        "t.ly", "tiny.cc", "qlink.me", "po.st", "short.io", "shorturl.at",
        "aka.ms", "tr.im", "bit.do", "git.io", "adf.ly", "qr.ae", "tny.im"
    ]

    # Image file extensions
    IMAGE_EXTENSIONS = ['.jpg', '.jpeg', '.png', '.gif', '.bmp', '.svg', '.webp', '.tiff']

    @staticmethod
    def clean_url(url: str) -> str:
        """Clean a URL by removing trailing punctuation."""
        if not url:
            return url

        while url and url[-1] in '.,;:!?)]}\'"':
            url = url[:-1]

        try:
            parsed = urllib.parse.urlparse(url)
            if parsed.scheme and parsed.netloc:
                return urllib.parse.urlunparse(parsed)
        except Exception as e:
            logger.warning(f"Error normalizing URL {url}: {str(e)}")

        return url

    @staticmethod
    def is_url_shortened(url: str) -> bool:
        """Check if a URL is likely to be shortened."""
        if not url:
            return False

        try:
            parsed = urllib.parse.urlparse(url)
            domain = parsed.netloc.lower()

            if any(domain == shortener or domain.endswith('.' + shortener)
                   for shortener in UrlValidator.URL_SHORTENER_PROVIDERS):
                return True

            if parsed.path and len(parsed.path) <= 10 and re.match(r'^/[a-zA-Z0-9]+$', parsed.path):
                return True
        except Exception as e:
            logger.warning(f"Error checking if URL is shortened: {str(e)}")

        return False

    @staticmethod
    def is_image_url(url: str) -> bool:
        """Determine if a URL points to an image."""
        if not url:
            return False

        try:
            parsed = urllib.parse.urlparse(url)
            path = parsed.path.lower()
            return any(path.endswith(ext) for ext in UrlValidator.IMAGE_EXTENSIONS)
        except Exception as e:
            logger.warning(f"Error checking if URL is an image: {str(e)}")
            return False