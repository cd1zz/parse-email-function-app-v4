"""Enhanced HTML cleaning utilities."""

from __future__ import annotations

import html
import re
import unicodedata
from bs4 import BeautifulSoup


class EnhancedHtmlCleaner:
    """HTML cleaner with invisible character removal."""

    INVISIBLE_CHARS = {
        '\u00A0',  # Non-breaking space
        '\u00AD',  # Soft hyphen
        '\u034F',  # Combining grapheme joiner
        '\u061C',  # Arabic letter mark
        '\u115F',  # Hangul choseong filler
        '\u1160',  # Hangul jungseong filler
        '\u17B4',  # Khmer vowel inherent AQ
        '\u17B5',  # Khmer vowel inherent AA
        '\u180E',  # Mongolian vowel separator
        '\u200B',  # Zero width space
        '\u200C',  # Zero width non-joiner
        '\u200D',  # Zero width joiner
        '\u200E',  # Left-to-right mark
        '\u200F',  # Right-to-left mark
        '\u202A',  # Left-to-right embedding
        '\u202B',  # Right-to-left embedding
        '\u202C',  # Pop directional formatting
        '\u202D',  # Left-to-right override
        '\u202E',  # Right-to-left override
        '\u2060',  # Word joiner
        '\u2061',  # Function application
        '\u2062',  # Invisible times
        '\u2063',  # Invisible separator
        '\u2064',  # Invisible plus
        '\u2066',  # Left-to-right isolate
        '\u2067',  # Right-to-left isolate
        '\u2068',  # First strong isolate
        '\u2069',  # Pop directional isolate
        '\u206A',  # Inhibit symmetric swapping
        '\u206B',  # Activate symmetric swapping
        '\u206C',  # Inhibit Arabic form shaping
        '\u206D',  # Activate Arabic form shaping
        '\u206E',  # National digit shapes
        '\u206F',  # Nominal digit shapes
        '\u3164',  # Hangul filler
        '\uFEFF',  # Zero width no-break space
        '\uFFA0',  # Halfwidth hangul filler
    }

    CONTROL_CHAR_RANGES = [
        (0x0000, 0x001F),
        (0x007F, 0x009F),
    ]

    PRESERVE_CHARS = {'\t', '\n', '\r'}

    @classmethod
    def clean_html(cls, text: str, aggressive_cleaning: bool = True) -> str:
        """Clean HTML and remove invisible characters."""
        if not text:
            return ""

        soup = BeautifulSoup(text, "html.parser")
        for element in soup(["script", "style", "head", "meta", "link"]):
            element.decompose()
        text = soup.get_text(separator="\n")

        text = html.unescape(text)

        if aggressive_cleaning:
            text = cls._remove_invisible_chars_aggressive(text)
        else:
            text = cls._remove_invisible_chars_conservative(text)

        text = cls._normalize_whitespace(text)
        text = unicodedata.normalize("NFKC", text)
        return text.strip()

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
            if category.startswith('M') and not unicodedata.combining(ch):
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
