import os
import importlib.util
import pytest

MODULE_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'parse_email', 'html_cleaner.py'))
spec = importlib.util.spec_from_file_location('html_cleaner', MODULE_PATH)
html_cleaner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(html_cleaner)
PhishingEmailHtmlCleaner = html_cleaner.PhishingEmailHtmlCleaner


@pytest.mark.parametrize("input_html,expected", [
    ("<p>Hello\u200dWorld</p>", "HelloWorld"),
    ("<div>Te\u200bst\u200c\u200d</div>", "Test"),
    ("<p>\u2018quotes\u2019</p>", "'quotes'"),
    ("<p>\u201Cdouble\u201D</p>", '"double"'),
])
def test_unicode_cleaning(input_html, expected):
    assert PhishingEmailHtmlCleaner.clean_html(input_html) == expected


def test_hidden_div_removed():
    hidden_chars = "\u2007\u034f\u00ad" * 60
    html = f'<div style="display:none">{hidden_chars}</div><p>Visible</p>'
    assert PhishingEmailHtmlCleaner.clean_html(html) == "Visible"


def test_combining_mark_removed():
    html = "<p>A\u034fB</p>"
    assert PhishingEmailHtmlCleaner.clean_html(html) == "AB"
