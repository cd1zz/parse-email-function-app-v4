import os
import sys
import pytest

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, ROOT_DIR)

from parse_email.email_parser import EmailParser

SIMPLE_EMAIL = b"Subject: Hello\n\nWorld"


def test_content_truncated_without_forensics():
    parser = EmailParser()
    result = parser.parse(SIMPLE_EMAIL, forensics_mode=False)
    assert "World" in result["plain_text"]
    assert result["content"] == (
        "Original content truncated for brevity. Run with --forensics_mode to get full key value pairs."
    )


def test_content_preserved_with_forensics():
    parser = EmailParser()
    result = parser.parse(SIMPLE_EMAIL, forensics_mode=True)
    assert isinstance(result["content"], list)
    assert "World" in result["plain_text"]
