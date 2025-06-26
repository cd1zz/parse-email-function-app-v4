"""Utilities for decoding wrapped URLs such as Microsoft SafeLinks and Proofpoint URLs."""

import logging
import urllib.parse

logger = logging.getLogger(__name__)

class UrlDecoder:
    """URL decoder utilities."""

    @staticmethod
    def decode_safelinks(url: str) -> str:
        """Decode Microsoft SafeLinks URLs."""
        if not url:
            return url
        try:
            parsed = urllib.parse.urlparse(url)
            query = urllib.parse.parse_qs(parsed.query)
            target = query.get('url') or query.get('target')
            if target:
                return target[0]
        except Exception as e:  # pragma: no cover - log warning
            logger.warning(f"Error decoding SafeLinks URL {url}: {str(e)}")
        return url

    @staticmethod
    def decode_proofpoint_urls(url: str) -> str:
        """Decode Proofpoint URL Defense links."""
        if not url:
            return url
        try:
            parsed = urllib.parse.urlparse(url)
            query = urllib.parse.parse_qs(parsed.query)
            if 'u' in query:
                encoded = query['u'][0]
                decoded = urllib.parse.unquote(encoded)
                return decoded
        except Exception as e:  # pragma: no cover - log warning
            logger.warning(f"Error decoding Proofpoint URL {url}: {str(e)}")
        return url
