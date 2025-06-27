"""URL processor module for high-level URL processing operations."""

import logging
import time
import urllib.parse

import requests  # type: ignore
from .validator import UrlValidator
from .decoder import UrlDecoder

logger = logging.getLogger(__name__)

class UrlProcessor:
    """Class for high-level URL processing operations including expansion,
    deduplication, and unified processing."""

    @staticmethod
    def expand_url(url: str, timeout: int = 5, max_redirects: int = 10) -> str:
        """Expand a shortened URL by following redirects."""
        if not url or not UrlValidator.is_url_shortened(url):
            return url

        logger.debug(f"Expanding shortened URL: {url}")

        try:
            if not (url.startswith('http://') or url.startswith('https://')):
                url = 'http://' + url

            session = requests.Session()
            response = session.head(
                url,
                allow_redirects=True,
                timeout=timeout,
                headers={'User-Agent': 'Mozilla/5.0'}
            )
            expanded_url = response.url
            logger.debug(f"URL expanded to: {expanded_url}")
            return expanded_url
        except Exception as e:  # pragma: no cover - network errors
            logger.warning(f"Error expanding URL {url}: {str(e)}")
            if isinstance(e, requests.exceptions.RequestException):
                if hasattr(e, 'response') and e.response is not None:
                    return e.response.url
                if hasattr(e, 'request'):
                    return e.request.url
                if url.startswith('https://'):
                    fallback_url = url.replace('https://', 'http://', 1)
                    logger.debug(f"Retrying with HTTP: {fallback_url}")
                    try:
                        response = session.head(fallback_url, allow_redirects=True, timeout=timeout)
                        return response.url
                    except Exception:
                        pass
            return url

    @staticmethod
    def batch_expand_urls(urls, delay: float = 0.5):
        """Expand a batch of shortened URLs to their final destinations."""
        if not urls:
            return urls

        logger.debug(f"Batch expanding {len(urls)} URLs")
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
        """Process a list of URLs consistently to deduplicate, decode wrapped links, and identify shortened URLs."""
        if not urls:
            return []
        logger.debug(f"Processing {len(urls)} URLs")
        processed_urls = []
        seen_urls = set()

        for url in urls:
            url_str = url if isinstance(url, str) else url.get('original_url', '')
            if not url_str:
                continue
            if url_str in seen_urls:
                continue
            if UrlValidator.is_image_url(url_str):
                logger.debug(f"Skipping image URL: {url_str}")
                continue
            if 'safelinks.protection.outlook.com' in url_str:
                decoded = UrlDecoder.decode_safelinks(url_str)
                logger.debug(f"Decoded SafeLink: {url_str} -> {decoded}")
                if decoded in seen_urls:
                    continue
                url_str = decoded
            elif 'urldefense.com' in url_str:
                decoded = UrlDecoder.decode_proofpoint_urls(url_str)
                logger.debug(f"Decoded Proofpoint URL: {url_str} -> {decoded}")
                if decoded in seen_urls:
                    continue
                url_str = decoded

            seen_urls.add(url_str)
            url_obj = {'original_url': url_str}
            if isinstance(url, dict):
                if 'is_shortened' in url:
                    url_obj['is_shortened'] = url['is_shortened']
                if 'expanded_url' in url and url['expanded_url'] != url_str:
                    url_obj['expanded_url'] = url['expanded_url']

            if 'is_shortened' not in url_obj:
                url_obj['is_shortened'] = UrlValidator.is_url_shortened(url_str)

            if not url_obj['is_shortened']:
                url_obj['expanded_url'] = 'Not Applicable'
            elif 'expanded_url' not in url_obj:
                url_obj['expanded_url'] = url_str

            processed_urls.append(url_obj)
        return processed_urls

    @staticmethod
    def dedupe_to_base_urls(url_list):
        """Deduplicate non-shortened URLs by their base domain, keeping shortened URLs intact."""
        logger.debug(f"Deduplicating {len(url_list)} URLs")
        seen_bases = set()
        deduped = []
        for url_obj in url_list:
            if not isinstance(url_obj, dict) or 'original_url' not in url_obj:
                continue
            if url_obj.get('is_shortened', False):
                deduped.append(url_obj)
                continue
            try:
                parsed = urllib.parse.urlparse(url_obj['original_url'])
                base = f"{parsed.scheme}://{parsed.netloc}"
                if base not in seen_bases:
                    seen_bases.add(base)
                    deduped.append({
                        'original_url': base,
                        'is_shortened': False,
                        'expanded_url': url_obj.get('expanded_url', 'Not Applicable')
                    })
            except Exception as e:
                logger.warning(f"Error deduplicating URL {url_obj['original_url']}: {str(e)}")
                deduped.append(url_obj)
        logger.debug(f"Final deduplicated URL count: {len(deduped)}")
        return deduped

    @staticmethod
    def fix_url_expansions(urls):
        """Ensure expanded_url is set only for shortened URLs."""
        fixed = []
        for url in urls:
            if isinstance(url, dict):
                fixed_url = url.copy()
                if not fixed_url.get('is_shortened', False):
                    fixed_url['expanded_url'] = 'Not Applicable'
                elif fixed_url.get('expanded_url') == fixed_url.get('original_url'):
                    fixed_url['expanded_url'] = 'Not Applicable'
                fixed.append(fixed_url)
            else:
                fixed.append(url)
        return fixed

    @staticmethod
    def extract_urls_from_attachments(attachments):
        """Extract URLs from email attachments."""
        attachment_urls = []
        for attachment in attachments:
            if 'urls' in attachment:
                attachment_urls.extend(attachment['urls'])
        logger.debug(f"Extracted {len(attachment_urls)} URLs from attachments")
        return attachment_urls
