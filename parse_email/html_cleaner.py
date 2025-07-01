"""Enhanced HTML cleaning utilities."""

from __future__ import annotations

import html
import re
import unicodedata
from bs4 import BeautifulSoup


class EnhancedHtmlCleaner:
    """HTML cleaner with invisible character removal."""

    # Unicode character replacements for common problematic characters
    UNICODE_REPLACEMENTS = {
        '\u2018': "'",    # Left single quotation mark
        '\u2019': "'",    # Right single quotation mark
        '\u201C': '"',    # Left double quotation mark
        '\u201D': '"',    # Right double quotation mark
        '\u201A': "'",    # Single low-9 quotation mark
        '\u201E': '"',    # Double low-9 quotation mark
        '\u2039': '<',    # Single left-pointing angle quotation mark
        '\u203A': '>',    # Single right-pointing angle quotation mark
        '\u00AB': '<<',   # Left-pointing double angle quotation mark
        '\u00BB': '>>',   # Right-pointing double angle quotation mark

        # Dashes and hyphens
        '\u2013': '-',    # En dash
        '\u2014': '--',   # Em dash
        '\u2015': '--',   # Horizontal bar
        '\u2212': '-',    # Minus sign

        # Spaces (these will be handled by both replacement and removal)
        '\u00A0': ' ',    # Non-breaking space
        '\u2002': ' ',    # En space
        '\u2003': ' ',    # Em space
        '\u2009': ' ',    # Thin space
        '\u200A': ' ',    # Hair space
        '\u202F': ' ',    # Narrow no-break space
        '\u205F': ' ',    # Medium mathematical space
        '\u3000': ' ',    # Ideographic space

        # Symbols
        '\u00A9': '(c)',  # Copyright sign
        '\u00AE': '(R)',  # Registered sign
        '\u2122': '(TM)', # Trade mark sign
        '\u00B0': 'deg',  # Degree sign
        '\u00B1': '+/-',  # Plus-minus sign
        '\u00B7': '*',    # Middle dot
        '\u2022': '*',    # Bullet
        '\u2026': '...',  # Horizontal ellipsis
        '\u00D7': 'x',    # Multiplication sign
        '\u00F7': '/',    # Division sign

        # Currency (convert to text abbreviations)
        '\u20AC': 'EUR',  # Euro sign
        '\u00A3': 'GBP',  # Pound sign
        '\u00A5': 'JPY',  # Yen sign
        '\u00A2': 'c',    # Cent sign

        # Fractions
        '\u00BC': '1/4',  # Vulgar fraction one quarter
        '\u00BD': '1/2',  # Vulgar fraction one half
        '\u00BE': '3/4',  # Vulgar fraction three quarters
        '\u2153': '1/3',  # Vulgar fraction one third
        '\u2154': '2/3',  # Vulgar fraction two thirds

        # Additional punctuation
        '\u2032': "'",    # Prime (feet/minutes)
        '\u2033': '"',    # Double prime (inches/seconds)
        '\u2035': '`',    # Reversed prime
    }

    INVISIBLE_CHARS = {
        '\u00AD',  # Soft hyphen (not in replacements since it should be removed)
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

        # Replace problematic but visible Unicode characters
        text = cls._replace_problematic_unicode_chars(text)

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
