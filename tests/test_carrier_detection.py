import os
import sys
import pytest
from email import policy
from email.parser import BytesParser

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, ROOT_DIR)

from parse_email import EmailParser
from parse_email.carrier_detector import is_carrier


def parse(raw: bytes):
    return BytesParser(policy=policy.default).parsebytes(raw)


def test_is_carrier_proofpoint():
    msg = parse(b"Subject: hello\nX-Proofpoint-Test: 1\n\nBody")
    flag, vendor = is_carrier(msg)
    assert flag and vendor == "proofpoint"


def test_is_carrier_negative():
    msg = parse(b"Subject: hello\n\nBody")
    flag, vendor = is_carrier(msg)
    assert not flag and vendor is None


def test_carrier_depth_chain():
    inner = b"Subject: Quarantine\nX-Microsoft-Antispam: yes\n\nHi"
    outer = (
        b"Subject: Outer\nX-Proofpoint-Foo: 1\nContent-Type: message/rfc822\n\n" + inner
    )
    parser = EmailParser()
    result = parser.parse(outer)
    assert result["carrier_depth"] == 2
    assert result["carrier_chain"] == ["proofpoint", "o365quar"]


def test_carrier_none():
    parser = EmailParser()
    result = parser.parse(b"Subject: Hi\n\nBody")
    assert result["carrier_depth"] == 0
    assert result["carrier_chain"] == []
