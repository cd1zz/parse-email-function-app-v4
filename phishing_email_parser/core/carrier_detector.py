# =============================================================
# carrier_detector.py
# =============================================================
"""Identify whether a MIME message is a *carrier* e‑mail produced by a
 security appliance (Proofpoint, Mimecast, Microsoft 365 Defender, …).

`is_carrier(msg)` returns ``(True, vendor_tag)`` or ``(False, None)`` where
 ``vendor_tag`` is a short identifier such as ``"proofpoint"``.

Extend *CARRIER_PATTERNS* as you encounter new products.  Regular
 expressions are case‑insensitive.
"""
from __future__ import annotations
import re
from email.message import Message
from typing import Tuple, Optional

CARRIER_PATTERNS: dict[str, tuple[str, str]] = {
    #  vendor_tag   (subject regex,            X‑header regex)
    "proofpoint": (r"\bProofpoint\b",         r"^X‑Proofpoint‑"),
    "mimecast":   (r"\bMimecast\b",           r"^X‑MC‑"),
    "o365quar":   (r"\bquarantine\b",         r"^X‑Microsoft‑Antispam"),
    "ironport":   (r"\b(IronPort|ESA)\b",     r"^X‑IronPort‑"),
}

_re_flags = re.I | re.S  # ignore‑case, dot‑matches‑newline


def is_carrier(msg: Message) -> Tuple[bool, Optional[str]]:  # noqa: D401 – not a property
    """Return *(True, vendor_tag)* if *msg* looks like a carrier e‑mail."""
    subj: str = msg.get("subject", "")
    hdr_blob: str = "\n".join(f"{k}:{v}" for k, v in msg.items())

    for vendor, (pat_subj, pat_hdr) in CARRIER_PATTERNS.items():
        if re.search(pat_subj, subj, _re_flags) or re.search(pat_hdr, hdr_blob, _re_flags):
            return True, vendor
    return False, None


def detect_vendor(msg: Message) -> Optional[str]:
    """Return vendor tag if *msg* is a carrier email, otherwise ``None``."""
    flag, vendor = is_carrier(msg)
    return vendor if flag else None
