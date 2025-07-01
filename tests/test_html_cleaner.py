import os
import importlib.util
import pytest

MODULE_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'parse_email', 'html_cleaner.py'))
spec = importlib.util.spec_from_file_location('html_cleaner', MODULE_PATH)
html_cleaner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(html_cleaner)
EnhancedHtmlCleaner = html_cleaner.EnhancedHtmlCleaner


@pytest.mark.parametrize("input_html,expected", [
    ("<p>Hello\u200dWorld</p>", "HelloWorld"),
    ("<div>Te\u200bst\u200c\u200d</div>", "Test"),
    ("<p>\u2018quotes\u2019</p>", "'quotes'"),
    ("<p>\u201Cdouble\u201D</p>", '"double"'),
])
def test_unicode_cleaning(input_html, expected):
    assert EnhancedHtmlCleaner.clean_html(input_html) == expected
