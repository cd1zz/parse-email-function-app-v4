# =============================================================
# carrier_detector.py
# =============================================================
"""Identify whether a MIME message is a *carrier* e‑mail produced by a
 security appliance (Proofpoint, Mimecast, Microsoft 365 Defender, …) or
 user-submitted carrier (forwarded/submitted for analysis).

`is_carrier(msg)` returns ``(True, vendor_tag)`` or ``(False, None)`` where
 ``vendor_tag`` is a short identifier such as ``"proofpoint"`` or ``"user_forward"``.

`enhanced_is_carrier(msg)` returns ``(True, vendor_tag, details)`` with additional
 context about the detection.

Extend *CARRIER_PATTERNS* as you encounter new products.  Regular
 expressions are case‑insensitive.
"""
from __future__ import annotations

import re
from email.message import Message
from typing import Any, Dict, List, Optional, Tuple

# Security appliance patterns (original functionality)
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

# User submission patterns (new functionality)
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
    },
    "helpdesk_submission": {
        "subject_patterns": [
            r"\b(help\s*desk|support)\b.*\b(ticket|request)\b",
            r"\b(user\s+report|ticket|incident)\b",
            r"^\[?(TICKET|HD|SUPPORT)\]?",
            r"\b(assistance\s+requested|help\s+needed)\b"
        ],
        "from_patterns": [
            r"helpdesk@",
            r"support@",
            r"servicedesk@",
            r"tickets@"
        ],
        "body_patterns": [
            r"user\s+(reported|contacted|called)",
            r"ticket\s+(created|opened|submitted)",
            r"assistance\s+(requested|needed)",
            r"help\s+with\s+(suspicious|email)"
        ]
    }
}

_re_flags = re.I | re.S  # ignore‑case, dot‑matches‑newline


class EnhancedCarrierDetector:
    """Enhanced carrier detection including user submissions and detailed analysis."""
    
    @staticmethod
    def detect_user_submission_carrier(msg: Message) -> Tuple[bool, Optional[str], Dict[str, Any]]:
        """
        Detect if this is a user-submitted carrier email.
        
        Returns:
            (is_carrier, carrier_type, evidence_details)
        """
        subject = msg.get("subject", "")
        from_addr = msg.get("from", "")
        body_text = EnhancedCarrierDetector._extract_body_text(msg)
        
        evidence = {
            "subject_matches": [],
            "body_matches": [],
            "from_matches": [],
            "structural_indicators": [],
            "confidence_score": 0,
            "submission_type": None
        }
        
        best_score = 0
        
        # Check each user submission type
        for submission_type, patterns in USER_SUBMISSION_PATTERNS.items():
            type_evidence = EnhancedCarrierDetector._check_submission_type(
                msg, subject, from_addr, body_text, patterns
            )
            
            if type_evidence["confidence_score"] > best_score:
                best_score = type_evidence["confidence_score"]
                evidence = type_evidence
                evidence["submission_type"] = submission_type
        
        # Determine if this qualifies as a user carrier
        is_carrier = evidence["confidence_score"] >= 3  # Threshold for detection
        carrier_type = f"user_{evidence.get('submission_type', 'unknown')}" if is_carrier else None
        
        return is_carrier, carrier_type, evidence
    
    @staticmethod
    def _check_submission_type(msg: Message, subject: str, from_addr: str, 
                              body_text: str, patterns: Dict) -> Dict:
        """Check if email matches a specific submission type."""
        evidence = {
            "subject_matches": [],
            "body_matches": [],
            "from_matches": [],
            "structural_indicators": [],
            "confidence_score": 0
        }
        
        # Check subject patterns
        for pattern in patterns.get("subject_patterns", []):
            if re.search(pattern, subject, _re_flags):
                evidence["subject_matches"].append(pattern)
                evidence["confidence_score"] += 2
        
        # Check body patterns  
        for pattern in patterns.get("body_patterns", []):
            if re.search(pattern, body_text, _re_flags):
                evidence["body_matches"].append(pattern)
                evidence["confidence_score"] += 1
        
        # Check from patterns
        for pattern in patterns.get("from_patterns", []):
            if re.search(pattern, from_addr, _re_flags):
                evidence["from_matches"].append(pattern)
                evidence["confidence_score"] += 1
        
        # Check structural indicators
        structural_score = EnhancedCarrierDetector._check_structural_indicators(msg, evidence)
        evidence["confidence_score"] += structural_score
        
        return evidence
    
    @staticmethod
    def _check_structural_indicators(msg: Message, evidence: Dict) -> int:
        """Check structural indicators of user-submitted carriers."""
        score = 0
        
        # Check for .eml attachments (strong indicator)
        if EnhancedCarrierDetector._has_eml_attachments(msg):
            evidence["structural_indicators"].append("has_eml_attachments")
            score += 3  # Strong indicator
        
        # Check for message/rfc822 attachments
        if EnhancedCarrierDetector._has_message_attachments(msg):
            evidence["structural_indicators"].append("has_message_attachments")
            score += 3  # Strong indicator
        
        # Check for forwarding headers in body
        body_text = EnhancedCarrierDetector._extract_body_text(msg)
        if EnhancedCarrierDetector._has_forwarding_headers(body_text):
            evidence["structural_indicators"].append("has_forwarding_headers")
            score += 2
        
        # Check for email headers in body text
        if EnhancedCarrierDetector._has_email_headers_in_body(body_text):
            evidence["structural_indicators"].append("contains_email_headers_in_body")
            score += 2
        
        # Check if sender appears internal (heuristic)
        from_addr = msg.get("from", "")
        if EnhancedCarrierDetector._appears_internal_sender(from_addr, body_text):
            evidence["structural_indicators"].append("internal_domain_sender") 
            score += 1
        
        # Check for multiple attachments (often indicates forwarded content)
        attachment_count = EnhancedCarrierDetector._count_attachments(msg)
        if attachment_count > 1:
            evidence["structural_indicators"].append(f"multiple_attachments:{attachment_count}")
            score += 1
        
        return score
    
    @staticmethod
    def _extract_body_text(msg: Message) -> str:
        """Extract text content from email body."""
        body_text = ""
        if msg.is_multipart():
            for part in msg.walk():
                if part.get_content_type() == "text/plain" and not part.get_filename():
                    try:
                        content = part.get_content()
                        if content:
                            body_text += content + "\n"
                    except Exception:
                        continue
                elif part.get_content_type() == "text/html" and not part.get_filename() and not body_text:
                    # Fall back to HTML if no plain text
                    try:
                        content = part.get_content()
                        if content:
                            # Basic HTML stripping for pattern matching
                            import re
                            content = re.sub(r'<[^>]+>', ' ', content)
                            body_text = content
                    except Exception:
                        continue
        else:
            try:
                content = msg.get_content()
                if content:
                    body_text = content
            except Exception:
                pass
        return body_text[:3000]  # Limit for performance
    
    @staticmethod
    def _has_eml_attachments(msg: Message) -> bool:
        """Check if email has .eml attachments."""
        for part in msg.iter_attachments():
            filename = part.get_filename() or ""
            if filename.lower().endswith('.eml'):
                return True
        return False
    
    @staticmethod
    def _has_message_attachments(msg: Message) -> bool:
        """Check if email has message/rfc822 attachments."""
        for part in msg.walk():
            if part.get_content_type() == "message/rfc822":
                return True
        return False
    
    @staticmethod
    def _count_attachments(msg: Message) -> int:
        """Count total attachments."""
        return sum(1 for _ in msg.iter_attachments())
    
    @staticmethod
    def _has_forwarding_headers(body_text: str) -> bool:
        """Check for typical email forwarding headers in body."""
        forwarding_patterns = [
            r"^From:\s*.+@.+",
            r"^Sent:\s*.+",
            r"^To:\s*.+@.+", 
            r"^Subject:\s*.+",
            r"-----Original Message-----",
            r"Begin forwarded message:",
            r"^Date:\s*.+",
            r"^Received:\s*.+",
            r"^Message-ID:\s*.+"
        ]
        
        matches = 0
        for pattern in forwarding_patterns:
            if re.search(pattern, body_text, re.MULTILINE | re.IGNORECASE):
                matches += 1
        
        return matches >= 3  # Need multiple header-like patterns
    
    @staticmethod
    def _has_email_headers_in_body(body_text: str) -> bool:
        """Check for email headers embedded in body text."""
        header_patterns = [
            r"Message-ID:\s*<.+@.+>",
            r"Received:\s*from\s+.+",
            r"X-\w+:\s*.+",
            r"Content-Type:\s*text/",
            r"MIME-Version:\s*1\.0",
            r"Return-Path:\s*.+@.+"
        ]
        
        matches = 0
        for pattern in header_patterns:
            if re.search(pattern, body_text, re.IGNORECASE):
                matches += 1
        
        return matches >= 2
    
    @staticmethod
    def _appears_internal_sender(from_addr: str, body_text: str) -> bool:
        """Heuristic to detect internal/legitimate senders."""
        # Look for signs this is internal forwarding
        internal_indicators = [
            r"please\s+(review|analyze|check)",
            r"forwarding\s+for\s+(analysis|review)",
            r"flagged\s+by\s+(user|employee)",
            r"reported\s+by\s+.+@.+\..+",
            r"our\s+(user|employee|team)",
            r"internal\s+(review|analysis)",
            r"company\s+(policy|security)"
        ]
        
        for pattern in internal_indicators:
            if re.search(pattern, body_text, re.IGNORECASE):
                return True
        
        # Check if domain appears to be organizational
        if '@' in from_addr:
            domain = from_addr.split('@')[-1].lower()
            # Common organizational domain patterns
            org_patterns = [
                r'\.com$', r'\.org$', r'\.edu$', r'\.gov$',
                r'\.co\.', r'\.inc$', r'\.corp$', r'\.llc$'
            ]
            for pattern in org_patterns:
                if re.search(pattern, domain):
                    return True
        
        return False


def enhanced_is_carrier(msg: Message) -> Tuple[bool, Optional[str], Optional[Dict]]:
    """
    Enhanced carrier detection combining security appliances and user submissions.
    
    Returns:
        (is_carrier, vendor_tag, detection_details)
    """
    # First check for security appliances (original logic)
    subject = msg.get("subject", "")
    hdr_blob = "\n".join(f"{k}:{v}" for k, v in msg.items())
    
    for vendor, (pat_subj, pat_hdr) in CARRIER_PATTERNS.items():
        if re.search(pat_subj, subject, _re_flags) or re.search(pat_hdr, hdr_blob, _re_flags):
            return True, vendor, {
                "type": "security_appliance", 
                "vendor": vendor,
                "detection_method": "header_pattern" if re.search(pat_hdr, hdr_blob, _re_flags) else "subject_pattern"
            }
    
    # Check for user-submitted carriers
    is_user_carrier, user_carrier_type, evidence = EnhancedCarrierDetector.detect_user_submission_carrier(msg)
    
    if is_user_carrier:
        return True, user_carrier_type, {
            "type": "user_submission",
            "evidence": evidence
        }
    
    return False, None, None


# Backward compatibility functions (original interface)
def is_carrier(msg: Message) -> Tuple[bool, Optional[str]]:  # noqa: D401 – not a property
    """Return *(True, vendor_tag)* if *msg* looks like a carrier e‑mail."""
    is_carrier_flag, vendor_tag, _ = enhanced_is_carrier(msg)
    return is_carrier_flag, vendor_tag


def detect_vendor(msg: Message) -> Optional[str]:
    """Return vendor tag if *msg* is a carrier email, otherwise ``None``."""
    flag, vendor = is_carrier(msg)
    return vendor if flag else None


# Enhanced interface
def detect_vendor_enhanced(msg: Message) -> Tuple[Optional[str], Optional[Dict]]:
    """Enhanced vendor detection with additional context."""
    is_carrier_flag, vendor_tag, details = enhanced_is_carrier(msg)
    return vendor_tag if is_carrier_flag else None, details


def get_carrier_analysis_priority(vendor_tag: Optional[str]) -> str:
    """
    Get analysis priority based on carrier type.
    
    Returns:
        "LOW", "MEDIUM", or "HIGH" - indicating where LLM should focus analysis
    """
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
        return f"Security appliance: {vendor_tag} (detected via {details.get('detection_method', 'unknown')})"
    
    elif details.get("type") == "user_submission":
        evidence = details.get("evidence", {})
        submission_type = evidence.get("submission_type", "unknown")
        score = evidence.get("confidence_score", 0)
        indicators = len(evidence.get("structural_indicators", []))
        
        return f"User submission: {submission_type} (confidence: {score}, indicators: {indicators})"
    
    return f"Carrier: {vendor_tag}"


# Debugging and analysis functions
def analyze_potential_carrier(msg: Message) -> Dict[str, Any]:
    """
    Detailed analysis of potential carrier characteristics.
    Useful for debugging detection and understanding email structure.
    """
    subject = msg.get("subject", "")
    from_addr = msg.get("from", "")
    body_text = EnhancedCarrierDetector._extract_body_text(msg)
    
    analysis = {
        "basic_info": {
            "subject": subject,
            "from": from_addr,
            "body_length": len(body_text)
        },
        "security_appliance_check": {},
        "user_submission_check": {},
        "structural_analysis": {},
        "final_assessment": {}
    }
    
    # Check security appliance patterns
    hdr_blob = "\n".join(f"{k}:{v}" for k, v in msg.items())
    for vendor, (pat_subj, pat_hdr) in CARRIER_PATTERNS.items():
        subj_match = bool(re.search(pat_subj, subject, _re_flags))
        hdr_match = bool(re.search(pat_hdr, hdr_blob, _re_flags))
        analysis["security_appliance_check"][vendor] = {
            "subject_match": subj_match,
            "header_match": hdr_match,
            "detected": subj_match or hdr_match
        }
    
    # Check user submission patterns
    is_user_carrier, user_type, evidence = EnhancedCarrierDetector.detect_user_submission_carrier(msg)
    analysis["user_submission_check"] = {
        "detected": is_user_carrier,
        "type": user_type,
        "evidence": evidence
    }
    
    # Structural analysis
    analysis["structural_analysis"] = {
        "has_eml_attachments": EnhancedCarrierDetector._has_eml_attachments(msg),
        "has_message_attachments": EnhancedCarrierDetector._has_message_attachments(msg),
        "attachment_count": EnhancedCarrierDetector._count_attachments(msg),
        "has_forwarding_headers": EnhancedCarrierDetector._has_forwarding_headers(body_text),
        "has_email_headers_in_body": EnhancedCarrierDetector._has_email_headers_in_body(body_text),
        "appears_internal": EnhancedCarrierDetector._appears_internal_sender(from_addr, body_text)
    }
    
    # Final assessment
    is_carrier_flag, vendor_tag, details = enhanced_is_carrier(msg)
    analysis["final_assessment"] = {
        "is_carrier": is_carrier_flag,
        "vendor_tag": vendor_tag,
        "analysis_priority": get_carrier_analysis_priority(vendor_tag),
        "summary": format_carrier_summary(vendor_tag, details)
    }
    
    return analysis