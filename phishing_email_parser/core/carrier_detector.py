# ============================================================================
# phishing_email_parser/core/carrier_detector.py
# ============================================================================
"""Basic carrier detection patterns for security appliances."""

from __future__ import annotations

import re
from email.message import Message
from typing import Any, Dict, List, Optional, Tuple

# Security appliance patterns
CARRIER_PATTERNS: dict[str, tuple[str, str]] = {
    #  vendor_tag   (subject regex,            X‑header regex)
    "proofpoint": (r"\bProofpoint\b",         r"^X‑Proofpoint‑"),
    "mimecast":   (r"\bMimecast\b",           r"^X‑MC‑"),
    "o365quar":   (r"\bquarantine\b",         r"^X‑Microsoft‑Antispam"),
    "ironport":   (r"\b(IronPort|ESA)\b",     r"^X‑IronPort‑"),
    "barracuda":  (r"\bBarracuda\b",          r"^X‑Barracuda‑"),
    "fortimail":  (r"\bFortiMail\b",          r"^X‑Fortimail‑"),
    "trend_micro": (r"\bTrend\s*Micro\b",     r"^X‑TMASE‑"),
}

# User submission patterns
USER_SUBMISSION_PATTERNS: Dict[str, Dict[str, List[str]]] = {
    "user_forward": {
        "subject_patterns": [
            r"^(FW|Fwd|Forwarded?):\s*",
            r"\b(phishing|suspicious|malware|spam)\b",
            r"\b(analysis|review|investigate)\b",
            r"\b(please\s+(check|analyze|review))\b",
            r"\b(potential\s+(threat|phishing|scam))\b",
            r"\b(flagged|reported)\s+(as\s+)?(suspicious|phishing)\b"
        ],
        "body_patterns": [
            r"forwarded\s+message",
            r"please\s+(analyze|check|review|investigate)",
            r"suspicious\s+email",
            r"potential\s+(phishing|scam|malware)",
            r"received\s+this\s+(suspicious|odd|strange)",
            r"flagged\s+as\s+(suspicious|phishing)",
            r"asking\s+for\s+(credentials|password|login)",
            r"user\s+reported",
            r"employee\s+(received|forwarded)"
        ]
    },
    "security_submission": {
        "subject_patterns": [
            r"\b(phishing|security|incident)\b.*\b(report|submission|alert)\b",
            r"\b(suspicious|malicious)\s+(email|message)\b",
            r"\b(security\s+team|IT\s+security)\b",
            r"^\[?(EXTERNAL|SPAM|PHISHING)\]?",
            r"\b(quarantine|held|blocked)\b",
            r"^(Phishing|Security|Alert):",
            r"\b(threat|malware)\s+(detected|found|analysis)\b"
        ],
        "from_patterns": [
            r"security@",
            r"phishing@", 
            r"noreply@",
            r"system@",
            r"admin@",
            r"it-security@",
            r"securityteam@"
        ],
        "body_patterns": [
            r"security\s+team\s+analysis",
            r"automated\s+(analysis|scan|review)",
            r"threat\s+(assessment|analysis)",
            r"email\s+security\s+(alert|notification)",
            r"submitted\s+for\s+(analysis|review)",
            r"please\s+investigate"
        ]
    }
}

_re_flags = re.I | re.S  # ignore‑case, dot‑matches‑newline


def is_carrier(msg: Message) -> Tuple[bool, Optional[str]]:
    """Return *(True, vendor_tag)* if *msg* looks like a carrier e‑mail."""
    subject = msg.get("subject", "")
    hdr_blob = "\n".join(f"{k}:{v}" for k, v in msg.items())
    
    for vendor, (pat_subj, pat_hdr) in CARRIER_PATTERNS.items():
        if re.search(pat_subj, subject, _re_flags) or re.search(pat_hdr, hdr_blob, _re_flags):
            return True, vendor
    
    return False, None


def detect_vendor(msg: Message) -> Optional[str]:
    """Return vendor tag if *msg* is a carrier email, otherwise ``None``."""
    flag, vendor = is_carrier(msg)
    return vendor if flag else None


def enhanced_is_carrier(msg: Message) -> Tuple[bool, Optional[str], Optional[Dict]]:
    """
    Enhanced carrier detection combining security appliances and user submissions.
    
    Returns:
        (is_carrier, vendor_tag, detection_details)
    """
    # First check for security appliances
    is_carrier_flag, vendor_tag = is_carrier(msg)
    
    if is_carrier_flag:
        return True, vendor_tag, {
            "type": "security_appliance", 
            "vendor": vendor_tag,
            "detection_method": "pattern_match"
        }
    
    # Check for user-submitted carriers (simplified version)
    subject = msg.get("subject", "")
    from_addr = msg.get("from", "")
    
    # Simple user submission check
    user_indicators = [
        r"^(FW|Fwd):",
        r"\b(phishing|suspicious)\b",
        r"\b(please\s+(check|review))\b"
    ]
    
    for pattern in user_indicators:
        if re.search(pattern, subject, _re_flags):
            return True, "user_forward", {
                "type": "user_submission",
                "evidence": {
                    "subject_matches": [pattern],
                    "confidence_score": 3
                }
            }
    
    return False, None, None


def get_carrier_analysis_priority(vendor_tag: Optional[str]) -> str:
    """Get analysis priority based on carrier type."""
    if not vendor_tag:
        return "HIGH"  # Not a carrier = actual threat content
    
    if vendor_tag.startswith("user_"):
        return "LOW"   # User submissions = focus on nested content
    
    # Security appliances
    security_appliances = ["proofpoint", "mimecast", "o365quar", "ironport", "barracuda", "fortimail", "trend_micro"]
    if vendor_tag in security_appliances:
        return "LOW"   # Security appliance = focus on nested content
    
    return "MEDIUM"  # Unknown carrier type


def format_carrier_summary(vendor_tag: Optional[str], details: Optional[Dict]) -> str:
    """Format a human-readable summary of carrier detection."""
    if not vendor_tag:
        return "Direct email content (not a carrier)"
    
    if not details:
        return f"Carrier detected: {vendor_tag}"
    
    if details.get("type") == "security_appliance":
        return f"Security appliance: {vendor_tag}"
    
    elif details.get("type") == "user_submission":
        return f"User submission: {vendor_tag}"
    
    return f"Carrier: {vendor_tag}"