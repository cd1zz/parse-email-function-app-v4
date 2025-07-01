from email import message_from_bytes
from email.message import EmailMessage
from typing import Iterator, Tuple

from .carrier_detector import is_carrier


def walk_layers(root: EmailMessage) -> Iterator[Tuple[int, EmailMessage, bool, str | None]]:
    """Depth-first walk of nested email layers."""
    stack = [(0, root)]
    while stack:
        depth, msg = stack.pop()
        flag, vendor = is_carrier(msg)
        yield depth, msg, flag, vendor
        for part in msg.iter_attachments():
            ctype = part.get_content_type()
            filename = part.get_filename("") or ""
            if ctype == "message/rfc822" or filename.lower().endswith((".eml", ".msg")):
                payload = part.get_payload(decode=True) or b""
                try:
                    nested = message_from_bytes(payload)
                except Exception:
                    continue
                stack.append((depth + 1, nested))

        if msg.get_content_type() == "message/rfc822" and msg.is_multipart():
            nested_msg = msg.get_payload()[0] if msg.get_payload() else None
            if isinstance(nested_msg, EmailMessage):
                stack.append((depth + 1, nested_msg))
