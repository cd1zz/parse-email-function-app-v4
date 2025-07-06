# ============================================================================
# phishing_email_parser/processing/attachment_processor.py
# ============================================================================
"""Basic attachment processor for email attachments."""

import hashlib
import logging
import mimetypes
import os
from email.message import Message
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class AttachmentProcessor:
    """Process email attachments for phishing analysis."""

    def __init__(self, temp_dir: str, config=None):
        self.temp_dir = temp_dir
        self.config = config
        os.makedirs(temp_dir, exist_ok=True)

    def process_attachments(self, msg: Message, output_dir: str) -> List[Dict[str, Any]]:
        """Process all attachments in an email message."""
        logger.debug("Processing attachments to %s", output_dir)
        attachments = []
        attachment_idx = 1

        for part in msg.iter_attachments():
            try:
                attachment_data = self._process_single_attachment(
                    part, attachment_idx, output_dir
                )
                if attachment_data:
                    attachments.append(attachment_data)
                    attachment_idx += 1
            except Exception as e:
                logger.error("Error processing attachment %s: %s", attachment_idx, e)
                attachment_idx += 1

        logger.debug("Finished processing attachments: %d found", len(attachments))
        return attachments

    def _process_single_attachment(
        self, part: Message, index: int, output_dir: str
    ) -> Optional[Dict[str, Any]]:
        """Process a single email attachment."""
        filename = part.get_filename()
        if not filename:
            filename = f"attachment_{index}"
        else:
            filename = filename.rstrip("\x00").strip()

        content_type = part.get_content_type()
        if content_type:
            content_type = content_type.rstrip("\x00").strip()

        logger.debug("Processing attachment %d: %s (%s)", index, filename, content_type)

        payload = part.get_payload(decode=True)
        if not payload:
            return None

        # Save attachment to disk
        file_path = os.path.join(output_dir, filename)
        try:
            with open(file_path, "wb") as f:
                f.write(payload)
        except Exception as e:
            logger.error(f"Error saving attachment {filename}: {e}")
            file_path = None

        # Basic file analysis
        file_size = len(payload)
        file_hash = hashlib.sha256(payload).hexdigest()
        file_extension = Path(filename).suffix.lower()

        attachment_info = {
            "index": index,
            "filename": filename,
            "content_type": content_type,
            "size": file_size,
            "sha256": file_hash,
            "extension": file_extension,
            "disk_path": file_path,
            "is_suspicious_extension": file_extension in [".exe", ".scr", ".bat", ".cmd"],
            "text_content": None,
            "urls": [],
            "processed": True,
            "embedded_images": [],
        }

        # Check if it's a nested email
        is_nested_email = (
            filename.lower().endswith(".eml")
            or content_type == "message/rfc822"
        )
        attachment_info["is_nested_email"] = is_nested_email

        return attachment_info
