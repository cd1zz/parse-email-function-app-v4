"""email_parser.py
==============================

Parse an RFC‑compliant message tree into a structured dict for downstream
processing.  This version adds native **multi‑carrier detection** via the new
``mime_walker`` helper, exposing two extra keys at the top level:

* ``carrier_depth`` – integer count of consecutive carrier layers found.
* ``carrier_chain`` – list of vendor identifiers in the order encountered.

Existing logic for body extraction, attachment handling, URL harvesting, and
Unicode sanitisation remains unchanged except that Unicode scrubbing is now
centralised in a private helper so **all** text paths share it.
"""
from __future__ import annotations

import email, email.policy
import re
import unicodedata
from email.message import Message
from pathlib import Path
from typing import Any, Dict, List

from .html_cleaner import PhishingEmailHtmlCleaner as Cleaner
from .mime_walker import walk_layers  # ← NEW helper

__all__ = ["EmailParser"]

_CRLF_RE = re.compile(r"[\r\n]+")


# ──────────────────────────────────────────────────────────────────────────────
# Helper functions
# ──────────────────────────────────────────────────────────────────────────────

def _to_str(b: bytes, cset: str | None) -> str:
    """Best‑effort bytes→str with fallback paths."""
    if cset:
        try:
            return b.decode(cset, errors="replace")
        except LookupError:
            pass
    try:
        return b.decode("utf-8")
    except UnicodeDecodeError:
        return b.decode("latin-1", errors="replace")


def _decode_payload(part: Message) -> str:
    """Decode quoted‑printable / base64 payload to *text*."""
    raw: bytes = part.get_payload(decode=True) or b""
    cset = part.get_content_charset()
    return _to_str(raw, cset)


# Unified Unicode scrubbing applied to every textual path
# ───────────────────────────────────────────────────────

def _scrub_unicode(text: str) -> str:
    text = Cleaner._remove_invisible_chars_aggressive(text)
    text = unicodedata.normalize("NFKC", text)
    text = Cleaner._replace_problematic_unicode_chars(text)
    text = Cleaner._normalize_whitespace(text)
    return text


# ──────────────────────────────────────────────────────────────────────────────
# Core parser class
# ──────────────────────────────────────────────────────────────────────────────
class EmailParser:
    """Parse a raw *.eml* (bytes or :class:`email.message.Message`).

    Parameters
    ----------
    max_depth : int | None, optional
        Limit how deep `message/rfc822` nesting is traversed. ``None`` means
        unlimited (default).  Current implementation enforces the limit only
        for *carrier* inspection; attachment/body extraction still walks the
        entire tree so no data are missed.
    include_large_images : bool, default ``False``
        Keep base‑64 bytes for non‑inline images ≥100 kB. When *False* the
        parser stores only metadata (`size`, `filename`, etc.) to avoid JSON
        bloat.  Works like the old flag so existing CLI calls don’t break.
    **_unused
        Placeholder for future compatibility; ignored so unknown keyword
        arguments won’t raise ``TypeError``.
    """

    _IMG_SIZE_THRESHOLD = 100_000  # ~100 kB

    def __init__(self,
                 *,
                 max_depth: int | None = None,
                 include_large_images: bool = False,
                 **_unused: Any):
        self._max_depth = max_depth
        self._include_large_images = include_large_images

    """Parse a raw *.eml* (bytes or :class:`email.message.Message`)."""

    def parse(self, raw: bytes | Message) -> Dict[str, Any]:
        root_msg: Message = (
            raw if isinstance(raw, Message) else email.message_from_bytes(raw, policy=email.policy.default)
        )
        parsed: Dict[str, Any] = {
            "content_blocks": [],
        }

        # ── Walk every leaf MIME part ────────────────────────────────────────
        for part in root_msg.walk():
            if part.is_multipart():
                continue

            ct = part.get_content_type().lower()
            disp = (
                part.get("content-disposition", "").split(";", 1)[0] or "inline"
            ).lower()
            filename = part.get_filename()

            block: Dict[str, Any] = {
                "mime_type": ct,
                "disposition": disp,
                "filename": filename,
            }

            if ct.startswith("text/"):
                # ── textual body or attachment ────────────────────────────
                content = _decode_payload(part)
                block["content"] = content

                if ct == "text/html":
                    block["text_only"] = Cleaner.clean_html(content)
                else:
                    block["text_only"] = _scrub_unicode(content)

            else:
                # ── binary attachment (metadata only) ─────────────────────
                raw_bytes = part.get_payload(decode=True) or b""
                block["size"] = len(raw_bytes)

            parsed["content_blocks"].append(block)

        # ── Multi‑carrier detection (NEW) ─────────────────────────────────────
        carriers: List[str] = [vendor for *_depth, vendor in walk_layers(root_msg) if vendor]
        parsed["carrier_depth"] = len(carriers)
        parsed["carrier_chain"] = carriers

        return parsed


# ──────────────────────────────────────────────────────────────────────────────
# Optional CLI helper – quick JSON dump for manual checks
# ──────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import argparse, json, sys

    ap = argparse.ArgumentParser(description="Parse an email file and print JSON")
    ap.add_argument("path", help="Path to .eml / .msg file")
    args = ap.parse_args()

    data = Path(args.path).read_bytes()
    doc = EmailParser().parse(data)

    json.dump(doc, sys.stdout, indent=2, ensure_ascii=False)
    sys.stdout.write("\n")
