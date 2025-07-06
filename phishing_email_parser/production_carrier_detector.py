# ============================================================================
# phishing_email_parser/production_carrier_detector.py
# ============================================================================
"""
Production carrier detector with enhanced user submission detection.

PRESERVES: All original security appliance patterns from core/carrier_detector.py
ENHANCES: Adds user submission detection with confidence scoring and evidence tracking
"""

import logging
import re
from email.message import Message
from typing import Dict, Any, List, Optional, Tuple

from .interfaces import ICarrierDetector
from .data_models import (
    CarrierDetails, CarrierDetectionEvidence, CarrierType, create_carrier_details
)
from .exceptions import handle_processing_errors, CarrierDetectionError

# Import original patterns to ensure compatibility
from .core.carrier_detector import (
    CARRIER_PATTERNS, USER_SUBMISSION_PATTERNS, enhanced_is_carrier,
     format_carrier_summary
)

logger = logging.getLogger(__name__)

_re_flags = re.I | re.S  # ignore-case, dot-matches-newline


class ProductionCarrierDetector(ICarrierDetector):
    """
    Production-ready carrier detector implementing enhanced detection with confidence scoring.
    
    PRESERVES: All original security appliance detection patterns
    ENHANCES: User submission detection, confidence scoring, evidence tracking
    """
    
    def __init__(self, confidence_threshold: float = 3.0):
        """
        Initialize carrier detector with configurable confidence threshold.
        
        Args:
            confidence_threshold: Minimum confidence score for user submission detection
        """
        self.confidence_threshold = confidence_threshold
        
    @handle_processing_errors("carrier detection")
    def detect_carrier(self, msg: Message) -> Tuple[bool, Optional[str], Optional[CarrierDetails]]:
        """
        Enhanced carrier detection combining security appliances and user submissions.
        
        PRESERVES: All original security appliance detection logic
        ENHANCES: Structured return with CarrierDetails and evidence
        
        Returns:
            (is_carrier, vendor_tag, carrier_details)
        """
        try:
            # Use existing enhanced detection logic which preserves all original patterns
            is_carrier_flag, vendor_tag, raw_details = enhanced_is_carrier(msg)
            
            if not is_carrier_flag:
                return False, None, None
            
            # Convert raw details to structured CarrierDetails
            carrier_details = self._create_structured_details(vendor_tag, raw_details)
            
            logger.debug(f"Carrier detected: {vendor_tag} (type: {carrier_details.carrier_type.value})")
            
            return True, vendor_tag, carrier_details
            
        except Exception as e:
            logger.error(f"Carrier detection failed: {e}")
            raise CarrierDetectionError(f"Failed to detect carrier: {e}")
    
  
    def format_carrier_summary(self, vendor_tag: Optional[str], details: Optional[CarrierDetails]) -> str:
        """
        Format human-readable carrier summary.
        
        PRESERVES: Original formatting logic
        ENHANCES: Uses structured CarrierDetails
        """
        if details:
            raw_details = self._convert_to_raw_details(details)
            return format_carrier_summary(vendor_tag, raw_details)
        else:
            return format_carrier_summary(vendor_tag, None)
    
    def _create_structured_details(self, vendor_tag: str, raw_details: Optional[Dict]) -> CarrierDetails:
        """Convert raw detection details to structured CarrierDetails object."""
        if not raw_details:
            return create_carrier_details(
                carrier_type=CarrierType.UNKNOWN,
                vendor=vendor_tag,
                confidence=1.0,
                detection_method="unknown"
            )
        
        detection_type = raw_details.get("type", "unknown")
        
        if detection_type == "security_appliance":
            return create_carrier_details(
                carrier_type=CarrierType.SECURITY_APPLIANCE,
                vendor=vendor_tag,
                confidence=1.0,  # Security appliances have high confidence
                detection_method=raw_details.get("detection_method", "pattern_match")
            )
        
        elif detection_type == "user_submission":
            evidence_data = raw_details.get("evidence", {})
            
            # Map submission types to CarrierType enum
            submission_type = evidence_data.get("submission_type", "unknown")
            carrier_type_map = {
                "user_forward": CarrierType.USER_FORWARD,
                "security_submission": CarrierType.SECURITY_SUBMISSION,
                "helpdesk_submission": CarrierType.HELPDESK_SUBMISSION
            }
            carrier_type = carrier_type_map.get(submission_type, CarrierType.UNKNOWN)
            
            # Create structured evidence
            evidence = CarrierDetectionEvidence(
                subject_matches=evidence_data.get("subject_matches", []),
                body_matches=evidence_data.get("body_matches", []),
                from_matches=evidence_data.get("from_matches", []),
                structural_indicators=evidence_data.get("structural_indicators", []),
                confidence_score=evidence_data.get("confidence_score", 0),
                submission_type=submission_type
            )
            
            return create_carrier_details(
                carrier_type=carrier_type,
                vendor=vendor_tag,
                confidence=evidence_data.get("confidence_score", 0) / 10.0,  # Normalize to 0-1
                detection_method="user_submission_analysis",
                evidence=evidence
            )
        
        else:
            return create_carrier_details(
                carrier_type=CarrierType.UNKNOWN,
                vendor=vendor_tag,
                confidence=0.5,
                detection_method="unknown"
            )
    
    def _convert_to_raw_details(self, details: CarrierDetails) -> Dict[str, Any]:
        """Convert structured CarrierDetails back to raw format for compatibility."""
        raw_details = {
            "type": "security_appliance" if details.carrier_type == CarrierType.SECURITY_APPLIANCE else "user_submission",
            "vendor": details.vendor,
            "detection_method": details.detection_method
        }
        
        if details.evidence:
            raw_details["evidence"] = details.evidence.to_dict()
        
        return raw_details


class EnhancedUserSubmissionDetector:
    """
    Enhanced detector specifically for user-submitted carrier emails.
    
    PRESERVES: All patterns from USER_SUBMISSION_PATTERNS in core/carrier_detector.py
    ENHANCES: Better confidence scoring and evidence collection
    """
    
    def __init__(self, confidence_threshold: float = 3.0):
        self.confidence_threshold = confidence_threshold
    
    def detect_user_submission(self, msg: Message) -> Tuple[bool, Optional[str], CarrierDetectionEvidence]:
        """
        Detect user-submitted carrier emails with enhanced analysis.
        
        PRESERVES: All original detection logic from EnhancedCarrierDetector.detect_user_submission_carrier
        ENHANCES: Better evidence structure and confidence scoring
        """
        subject = msg.get("subject", "")
        from_addr = msg.get("from", "")
        body_text = self._extract_body_text(msg)
        
        evidence = CarrierDetectionEvidence(confidence_score=0)
        best_score = 0
        best_submission_type = None
        
        # Check each user submission type using original patterns
        for submission_type, patterns in USER_SUBMISSION_PATTERNS.items():
            type_evidence = self._check_submission_type(
                msg, subject, from_addr, body_text, patterns
            )
            
            if type_evidence.confidence_score > best_score:
                best_score = type_evidence.confidence_score
                evidence = type_evidence
                evidence.submission_type = submission_type
                best_submission_type = submission_type
        
        # Determine if this qualifies as a user carrier
        is_carrier = evidence.confidence_score >= self.confidence_threshold
        carrier_type = f"user_{evidence.submission_type}" if is_carrier else None
        
        return is_carrier, carrier_type, evidence
    
    def _check_submission_type(self, msg: Message, subject: str, from_addr: str,
                              body_text: str, patterns: Dict) -> CarrierDetectionEvidence:
        """
        Check if email matches a specific submission type.
        
        PRESERVES: Original pattern matching logic from core/carrier_detector.py
        """
        evidence = CarrierDetectionEvidence(confidence_score=0)
        
        # Check subject patterns (original logic)
        for pattern in patterns.get("subject_patterns", []):
            if re.search(pattern, subject, _re_flags):
                evidence.subject_matches.append(pattern)
                evidence.confidence_score += 2
        
        # Check body patterns (original logic)
        for pattern in patterns.get("body_patterns", []):
            if re.search(pattern, body_text, _re_flags):
                evidence.body_matches.append(pattern)
                evidence.confidence_score += 1
        
        # Check from patterns (original logic)
        for pattern in patterns.get("from_patterns", []):
            if re.search(pattern, from_addr, _re_flags):
                evidence.from_matches.append(pattern)
                evidence.confidence_score += 1
        
        # Check structural indicators (original logic)
        structural_score = self._check_structural_indicators(msg, evidence)
        evidence.confidence_score += structural_score
        
        return evidence
    
    def _check_structural_indicators(self, msg: Message, evidence: CarrierDetectionEvidence) -> int:
        """
        Check structural indicators of user-submitted carriers.
        
        PRESERVES: All original structural detection logic
        """
        score = 0
        
        # All the original structural checks from EnhancedCarrierDetector._check_structural_indicators
        
        # Check for .eml attachments (strong indicator)
        if self._has_eml_attachments(msg):
            evidence.structural_indicators.append("has_eml_attachments")
            score += 3  # Strong indicator
        
        # Check for message/rfc822 attachments
        if self._has_message_attachments(msg):
            evidence.structural_indicators.append("has_message_attachments")
            score += 3  # Strong indicator
        
        # Check for forwarding headers in body
        body_text = self._extract_body_text(msg)
        if self._has_forwarding_headers(body_text):
            evidence.structural_indicators.append("has_forwarding_headers")
            score += 2
        
        # Check for email headers in body text
        if self._has_email_headers_in_body(body_text):
            evidence.structural_indicators.append("contains_email_headers_in_body")
            score += 2
        
        # Check if sender appears internal (heuristic)
        from_addr = msg.get("from", "")
        if self._appears_internal_sender(from_addr, body_text):
            evidence.structural_indicators.append("internal_domain_sender")
            score += 1
        
        # Check for multiple attachments (often indicates forwarded content)
        attachment_count = self._count_attachments(msg)
        if attachment_count > 1:
            evidence.structural_indicators.append(f"multiple_attachments:{attachment_count}")
            score += 1
        
        return score
    
    def _extract_body_text(self, msg: Message) -> str:
        """
        Extract text content from email body.
        
        PRESERVES: Original body text extraction logic
        """
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
    
    def _has_eml_attachments(self, msg: Message) -> bool:
        """Check if email has .eml attachments."""
        for part in msg.iter_attachments():
            filename = part.get_filename() or ""
            if filename.lower().endswith('.eml'):
                return True
        return False
    
    def _has_message_attachments(self, msg: Message) -> bool:
        """Check if email has message/rfc822 attachments."""
        for part in msg.walk():
            if part.get_content_type() == "message/rfc822":
                return True
        return False
    
    def _count_attachments(self, msg: Message) -> int:
        """Count total attachments."""
        return sum(1 for _ in msg.iter_attachments())
    
    def _has_forwarding_headers(self, body_text: str) -> bool:
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
    
    def _has_email_headers_in_body(self, body_text: str) -> bool:
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
    
    def _appears_internal_sender(self, from_addr: str, body_text: str) -> bool:
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


# Factory function for dependency injection
def create_production_carrier_detector(confidence_threshold: float = 3.0) -> ICarrierDetector:
    """Create production carrier detector instance."""
    return ProductionCarrierDetector(confidence_threshold=confidence_threshold)