# ============================================================================
# phishing_email_parser/url_processing/processor.py
# ============================================================================
"""URL processor module for high-level URL processing operations."""

import logging
import time
import urllib.parse

logger = logging.getLogger(__name__)


class UrlProcessor:
    """Class for high-level URL processing operations."""

    @staticmethod
    def expand_url(url: str, timeout: int = 5, max_redirects: int = 10) -> str:
        """Expand a shortened URL by following redirects."""
        try:
            import requests
            
            if not UrlProcessor._is_url_shortened(url):
                return url

            if not (url.startswith('http://') or url.startswith('https://')):
                url = 'http://' + url

            session = requests.Session()
            response = session.head(
                url,
                allow_redirects=True,
                timeout=timeout,
                headers={'User-Agent': 'Mozilla/5.0'}
            )
            return response.url
        except Exception as e:
            logger.warning(f"Error expanding URL {url}: {str(e)}")
            return url

    @staticmethod
    def batch_expand_urls(urls, delay: float = 0.5):
        """Expand a batch of shortened URLs."""
        expanded_urls = []
        for url_obj in urls:
            if isinstance(url_obj, dict) and 'original_url' in url_obj:
                expanded_url_obj = url_obj.copy()
                if expanded_url_obj.get('is_shortened', False):
                    expanded = UrlProcessor.expand_url(expanded_url_obj['original_url'])
                    if expanded and expanded != expanded_url_obj['original_url']:
                        expanded_url_obj['expanded_url'] = expanded
                    else:
                        expanded_url_obj['expanded_url'] = 'Not Applicable'
                else:
                    expanded_url_obj['expanded_url'] = 'Not Applicable'
                expanded_urls.append(expanded_url_obj)
                if delay > 0 and expanded_url_obj.get('is_shortened', False):
                    time.sleep(delay)
            else:
                expanded_urls.append(url_obj)
        return expanded_urls

    @staticmethod
    def process_urls(urls):
        """Process a list of URLs consistently."""
        if not urls:
            return []
            
        processed_urls = []
        seen_urls = set()

        for url in urls:
            url_str = url if isinstance(url, str) else url.get('original_url', '')
            if not url_str or url_str in seen_urls:
                continue
                
            seen_urls.add(url_str)
            url_obj = {
                'original_url': url_str,
                'is_shortened': UrlProcessor._is_url_shortened(url_str),
                'expanded_url': 'Not Applicable'
            }
            processed_urls.append(url_obj)
            
        return processed_urls

    @staticmethod
    def _is_url_shortened(url: str) -> bool:
        """Check if a URL is likely to be shortened."""
        shortener_domains = [
            "bit.ly", "t.co", "goo.gl", "ow.ly", "tinyurl.com", "is.gd",
            "tiny.cc", "rb.gy", "short.io", "aka.ms"
        ]
        
        try:
            parsed = urllib.parse.urlparse(url)
            domain = parsed.netloc.lower()
            return any(domain == shortener or domain.endswith('.' + shortener)
                      for shortener in shortener_domains)
        except Exception:
            return False

    @staticmethod
    def extract_urls_from_attachments(attachments):
        """Extract URLs from email attachments."""
        attachment_urls = []
        for attachment in attachments:
            if 'urls' in attachment:
                attachment_urls.extend(attachment['urls'])
        return attachment_urls


