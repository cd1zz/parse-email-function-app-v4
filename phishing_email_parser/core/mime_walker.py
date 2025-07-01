# =============================================================
# mime_walker.py
# =============================================================
"""Depth‑first traversal of nested ``message/rfc822`` / *.eml* / *.msg* parts.

Yields ``(depth, msg, vendor_tag)`` where *depth* == 0 for the outer
 message and *vendor_tag* is ``None`` unless :pyfunc:`is_carrier` matched.
"""
from __future__ import annotations
import email
from email.message import Message
from typing import Generator, Tuple, Optional

from .carrier_detector import is_carrier

_nested_cts = {"message/rfc822", "application/vnd.ms‑outlook"}  # .msg OLE shell


def _should_recurse(part: Message) -> bool:
    ct = part.get_content_type().lower()
    fn = part.get_filename("") or ""
    if ct in _nested_cts:
        return True
    if fn.lower().endswith((".eml", ".msg")):
        return True
    if ct == "application/octet-stream":
        # Heuristic: if filename suggests email or content decodes to a valid email
        if fn.lower().endswith((".eml", ".msg")):
            return True
        try:
            payload = part.get_payload(decode=True)
            if payload:
                msg = email.message_from_bytes(payload)
                if msg.get("From") or msg.get("Subject"):
                    return True
        except Exception:
            pass
    return False



def walk_layers(root: Message) -> Generator[Tuple[int, Message, Optional[str]], None, None]:
    """Yield *(depth, msg, vendor_tag)* for each nested message."""
    stack: list[tuple[int, Message]] = [(0, root)]

    while stack:
        depth, msg = stack.pop()
        flag, vendor = is_carrier(msg)
        yield depth, msg, vendor if flag else None

        for p in msg.iter_attachments():
            if _should_recurse(p):
                try:
                    nested = email.message_from_bytes(p.get_payload(decode=True))
                except Exception:
                    # corruption or password‑protected zip; skip
                    continue
                stack.append((depth + 1, nested))
