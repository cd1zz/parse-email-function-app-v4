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
import logging, re

from .carrier_detector import detect_vendor

log = logging.getLogger(__name__)


def _parse_bytes(b: bytes) -> Message | None:
    try:
        return BytesParser(policy=policy.default).parsebytes(b)
    except Exception as exc:  # truly malformed
        log.debug("parsebytes failed: %s", exc)
        return None


def _as_message(payload) -> Message | None:
    if isinstance(payload, Message):
        return payload
    if isinstance(payload, list) and payload and isinstance(payload[0], Message):
        return payload[0]
    if not isinstance(payload, (bytes, bytearray)):
        return None

    msg = _parse_bytes(payload)
    if msg and msg.keys():
        return msg

    # ── fallback: Outlook / OWA sometimes left-pads every header ──
    m = re.search(rb"\r?\n\r?\n", payload)
    if not m:
        return msg
    head, body = payload[:m.start()], payload[m.end():]

    cleaned = re.sub(rb"(?m)^[ \t]+(?=\S)", b"", head)
    cleaned += b"\r\n\r\n" + body
    msg2 = _parse_bytes(cleaned)
    return msg2 if msg2 and msg2.keys() else msg


def walk_layers(msg: Message, depth: int = 0) -> Generator[Tuple[int, Message, Optional[str]], None, None]:
    """Yield ``(depth, Message, vendor_tag)`` for every layer."""
    vendor_tag = detect_vendor(msg)
    yield depth, msg, vendor_tag

    for part in msg.walk():
        if part.get_content_type() != "message/rfc822":
            continue

        # raw bytes or Message object
        payload = part.get_payload(decode=True) or part.get_payload()

        # ── TEMP DEBUG: dump first 120 bytes ───────────────────────
        if isinstance(payload, (bytes, bytearray)):
            log.debug(
                "↓↓ first 120 bytes of nested payload ↓↓\n%s",
                (payload[:120])
                .replace(b"\r", b"\\r")
                .replace(b"\n", b"\\n")
            )
        # ───────────────────────────────────────────────────────────

        nested = _as_message(payload)
        if nested is None:
            continue

        log.debug(
            "Recurse into part due to content type message/rfc822 (depth %d)",
            depth + 1,
        )
        yield from walk_layers(nested, depth + 1)
