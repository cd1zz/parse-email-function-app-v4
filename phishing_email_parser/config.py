from __future__ import annotations

"""Configuration for the phishing email parser."""

from dataclasses import dataclass, field
from typing import Tuple


@dataclass(frozen=True)
class ParserConfig:
    """Configuration options for :class:`PhishingEmailParser`."""

    suspicious_extensions: Tuple[str, ...] = (
        ".exe",
        ".scr",
        ".bat",
        ".cmd",
        ".com",
        ".pif",
        ".vbs",
        ".js",
        ".jar",
        ".zip",
        ".rar",
        ".7z",
        ".ace",
        ".arj",
        ".cab",
        ".lzh",
        ".tar",
        ".gz",
    )
    text_extractable_types: Tuple[str, ...] = (
        "application/pdf",
        "text/plain",
        "text/html",
        "text/csv",
        "application/rtf",
        "application/msword",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "application/vnd.ms-excel",
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    )


DEFAULT_CONFIG = ParserConfig()
