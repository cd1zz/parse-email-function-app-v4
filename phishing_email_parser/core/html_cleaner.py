"""HTML to text cleaning using html2text for phishing analysis."""

from __future__ import annotations

import html2text
import html
import re
import unicodedata
from bs4 import BeautifulSoup


class PhishingEmailHtmlCleaner:
    """Convert HTML to plain text while preserving URLs."""

    # Unicode replacements for problematic characters
    UNICODE_REPLACEMENTS = {
        '\u2018': "'",
        '\u2019': "'",
        '\u201C': '"',
        '\u201D': '"',
        '\u201A': "'",
        '\u201E': '"',
        '\u2039': '<',
        '\u203A': '>',
        '\u00AB': '<<',
        '\u00BB': '>>',
        '\u2013': '-',
        '\u2014': '--',
        '\u2015': '--',
        '\u2212': '-',
        '\u00A0': ' ',
        '\u2002': ' ',
        '\u2003': ' ',
        '\u2009': ' ',
        '\u200A': ' ',
        '\u202F': ' ',
        '\u205F': ' ',
        '\u3000': ' ',
        '\u00A9': '(c)',
        '\u00AE': '(R)',
        '\u2122': '(TM)',
        '\u00B0': 'deg',
        '\u00B1': '+/-',
        '\u00B7': '*',
        '\u2022': '*',
        '\u2026': '...',
        '\u00D7': 'x',
        '\u00F7': '/',
        '\u20AC': 'EUR',
        '\u00A3': 'GBP',
        '\u00A5': 'JPY',
        '\u00A2': 'c',
        '\u00BC': '1/4',
        '\u00BD': '1/2',
        '\u00BE': '3/4',
        '\u2153': '1/3',
        '\u2154': '2/3',
        '\u2032': "'",
        '\u2033': '"',
        '\u2035': '`',
    }

    INVISIBLE_CHARS = {
        '\u00AD', '\u034F', '\u061C', '\u115F', '\u1160', '\u17B4', '\u17B5',
        '\u180E', '\u200B', '\u200C', '\u200D', '\u200E', '\u200F', '\u202A',
        '\u202B', '\u202C', '\u202D', '\u202E', '\u2060', '\u2061', '\u2062',
        '\u2063', '\u2064', '\u2066', '\u2067', '\u2068', '\u2069', '\u206A',
        '\u206B', '\u206C', '\u206D', '\u206E', '\u206F', '\u3164', '\uFEFF',
        '\uFFA0',
    }

    @classmethod
    def contains_html(cls, text: str) -> bool:
        """Heuristically determine if a string contains HTML tags."""
        if not text or '<' not in text:
            return False
        # Quick regex check for any HTML-like tags
        if re.search(r'<[^>]+>', text):
            try:
                soup = BeautifulSoup(text, "html.parser")
                return bool(soup.find())
            except Exception:
                return False
        return False

    CONTROL_CHAR_RANGES = [
        (0x0000, 0x001F),
        (0x007F, 0x009F),
    ]

    PRESERVE_CHARS = {'\t', '\n', '\r'}

    HIDDEN_STYLE_PATTERN = re.compile(
        r"display\s*:\s*none|visibility\s*:\s*hidden|opacity\s*:\s*0|font-size\s*:\s*0|height\s*:\s*0|width\s*:\s*0",
        re.IGNORECASE,
    )

    @classmethod
    def _strip_hidden_elements(cls, html_str: str) -> str:
        """Remove elements that are visually hidden."""
        soup = BeautifulSoup(html_str, "html.parser")
        for element in soup.find_all(style=cls.HIDDEN_STYLE_PATTERN):
            element.decompose()
        for element in soup.find_all(attrs={"hidden": True}):
            element.decompose()
        return str(soup)

    @classmethod
    def clean_html(cls, text: str, aggressive_cleaning: bool = True) -> str:
        """Convert HTML to plain text using html2text with URL preservation."""
        if not text:
            return ""

        # Remove hidden elements before converting
        stripped = cls._strip_hidden_elements(text)

        # html2text conversion
        converter = html2text.HTML2Text()
        converter.body_width = 0
        converter.protect_links = True
        converter.inline_links = True
        converter.ignore_images = True
        converted = converter.handle(stripped)

        # html.unescape to handle entities that html2text may leave
        converted = html.unescape(converted)

        if aggressive_cleaning:
            converted = cls._remove_invisible_chars_aggressive(converted)
        else:
            converted = cls._remove_invisible_chars_conservative(converted)

        # FIXED: Do normalization BEFORE unicode character replacements
        converted = unicodedata.normalize("NFKC", converted)
        
        # FIXED: Replace problematic unicode chars AFTER normalization
        converted = cls._replace_problematic_unicode_chars(converted)
        
        converted = cls._normalize_whitespace(converted)

        # Convert markdown links to plain text "text URL" and strip angle brackets
        converted = re.sub(r'\[([^\]]+)\]\(<(https?://[^)>]+)>\)', r'\1 \2', converted)
        converted = re.sub(r'\[([^\]]+)\]\((https?://[^)]+)\)', r'\1 \2', converted)
        converted = re.sub(r'<(https?://[^>]+)>', r'\1', converted)

        # Final validation to ensure no invisible characters remain
        if aggressive_cleaning:
            converted = cls._remove_invisible_chars_aggressive(converted)
        else:
            converted = cls._remove_invisible_chars_conservative(converted)

        # html2text in inline_links mode already preserves URLs inline. In
        # previous versions we appended all extracted URLs as separate lines,
        # which led to duplication when the parser also returns a dedicated URL
        # list. The caller now relies on the artifact extraction pipeline
        # instead, so no additional URL lines are added here.

        return converted.strip()

    @classmethod
    def _remove_invisible_chars_aggressive(cls, text: str) -> str:
        for char in cls.INVISIBLE_CHARS:
            text = text.replace(char, '')
        cleaned = []
        for ch in text:
            if ch in cls.PRESERVE_CHARS:
                cleaned.append(ch)
                continue
            code = ord(ch)
            if any(start <= code <= end for start, end in cls.CONTROL_CHAR_RANGES):
                continue
            category = unicodedata.category(ch)
            if category.startswith(('Cf', 'Cc', 'Cs', 'Co')):
                continue
            if category.startswith('M') and unicodedata.combining(ch):
                continue
            cleaned.append(ch)
        return ''.join(cleaned)

    @classmethod
    def _remove_invisible_chars_conservative(cls, text: str) -> str:
        common = {'\u200B', '\u200C', '\u200D', '\u200E', '\u200F', '\uFEFF', '\u00AD'}
        for c in common:
            text = text.replace(c, '')
        cleaned = []
        for ch in text:
            if ch in cls.PRESERVE_CHARS:
                cleaned.append(ch)
            elif ord(ch) < 32 and ch not in cls.PRESERVE_CHARS:
                continue
            else:
                cleaned.append(ch)
        return ''.join(cleaned)

    @classmethod
    def _replace_problematic_unicode_chars(cls, text: str) -> str:
        for uni, replacement in cls.UNICODE_REPLACEMENTS.items():
            text = text.replace(uni, replacement)
        return text

    @classmethod
    def _normalize_whitespace(cls, text: str) -> str:
        if not text:
            return ""
        text = re.sub(r'\r\n|\r', '\n', text)
        text = re.sub(r'[ \t\u00A0\u2000-\u200A\u2028\u2029\u202F\u205F\u3000]+', ' ', text)
        lines = text.split('\n')
        cleaned_lines = []
        empty_count = 0
        for line in lines:
            line = line.strip()
            if line:
                cleaned_lines.append(line)
                empty_count = 0
            else:
                if empty_count < 1:
                    cleaned_lines.append('')
                empty_count += 1
        result = '\n'.join(cleaned_lines).strip()
        result = re.sub(r'\n{3,}', '\n\n', result)
        return result
