import re
from email.message import EmailMessage

CARRIER_PATTERNS = {
    "proofpoint": (r"\bProofpoint\b", r"^X-Proofpoint-"),
    "mimecast": (r"\bMimecast\b", r"^X-MC-"),
    "o365quar": (r"\bquarantine\b", r"^X-Microsoft-Antispam"),
    "ironport": (r"\bIronPort\b|\bESA\b", r"^X-IronPort-")
}


def is_carrier(msg: EmailMessage) -> tuple[bool, str | None]:
    """Detect whether this message is a carrier email."""
    hdr_blob = "\n".join(f"{k}:{v}" for k, v in msg.items())
    subj = msg.get("subject", "")
    for tag, (pat_subj, pat_hdr) in CARRIER_PATTERNS.items():
        if re.search(pat_subj, subj, re.I) or re.search(pat_hdr, hdr_blob, re.I | re.M):
            return True, tag
    return False, None
