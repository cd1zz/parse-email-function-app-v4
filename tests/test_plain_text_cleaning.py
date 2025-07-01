import pytest
from parse_email.email_parser import EmailParser


def test_plain_text_invisible_char_removed():
    parser = EmailParser()
    body = "A" * 80 + "\u034F" + "B" * 80
    email_str = "Subject: Test\nContent-Type: text/plain; charset=utf-8\n\n" + body
    result = parser.parse(email_str.encode("utf-8"))
    assert "\u034F" not in result["plain_text"]
    assert "A" * 80 in result["plain_text"]
    assert "B" * 80 in result["plain_text"]
