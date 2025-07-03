# =============================================================
# mime_walker.py
# =============================================================
"""Depth-first traversal of nested ``message/rfc822`` parts.

This module provides :func:`walk_layers` which yields ``(depth, msg, vendor_tag)``
for every message layer.  The top level has ``depth`` 0.  ``vendor_tag`` is
``None`` unless :func:`detect_vendor` matched the message.
"""
from __future__ import annotations

from email import policy
from email.message import Message
from email.parser import BytesParser
from typing import Generator, Optional, Tuple
import logging

from .carrier_detector import detect_vendor

log = logging.getLogger(__name__)


def _as_message(payload) -> Message | None:
    """Return a :class:`Message` from ``payload`` if possible."""
    if isinstance(payload, Message):
        return payload
    # ``message/rfc822`` parts created by the stdlib are often a single-item list
    if isinstance(payload, list) and payload and isinstance(payload[0], Message):
        return payload[0]
    if isinstance(payload, (bytes, bytearray)):
        try:
            return BytesParser(policy=policy.default).parsebytes(payload)
        except Exception as exc:  # malformed content – just skip
            log.debug("unable to parse nested rfc822 bytes: %s", exc)
    return None


def walk_layers(msg: Message, depth: int = 0) -> Generator[Tuple[int, Message, Optional[str]], None, None]:
    """Yield ``(depth, Message, vendor_tag)`` for every layer."""
    vendor_tag = detect_vendor(msg)
    yield depth, msg, vendor_tag

    for part in msg.walk():
        if part.get_content_type() != "message/rfc822":
            continue
        nested = _as_message(part.get_payload(decode=True) or part.get_payload())
        if nested is None:
            continue
        log.debug(
            "Recurse into part due to content type message/rfc822 (depth %d)",
            depth + 1,
        )
        yield from walk_layers(nested, depth + 1)
