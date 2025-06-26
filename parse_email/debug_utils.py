#!/usr/bin/env python3
"""
Quick debugging script to identify what's missing in email parsing
"""

def debug_email_structure(file_path):
    """Quick analysis of email structure"""
    
    with open(file_path, 'rb') as f:
        content = f.read()
    
    print(f"Total email size: {len(content):,} bytes")
    print("=" * 60)
    
    # Find all MIME boundaries
    import re
    
    # Method 1: Find boundary declarations
    boundary_declarations = re.findall(rb'boundary=(["\']?)([^"\'\s;]+)\1', content, re.IGNORECASE)
    print(f"Found {len(boundary_declarations)} boundary declarations:")
    for i, (quote, boundary) in enumerate(boundary_declarations):
        boundary_str = boundary.decode('utf-8', errors='ignore')
        print(f"  {i+1}: {boundary_str}")
        
        # Count actual usage of this boundary
        boundary_usage = len(re.findall(f'--{re.escape(boundary_str)}'.encode(), content))
        print(f"      Used {boundary_usage} times in email")
    
    print()
    
    # Method 2: Find Content-Type headers
    content_types = re.findall(rb'Content-Type:\s*([^;\r\n]+)', content, re.IGNORECASE)
    print(f"Found {len(content_types)} Content-Type headers:")
    type_counts = {}
    for ct in content_types:
        ct_str = ct.decode('utf-8', errors='ignore').strip().lower()
        type_counts[ct_str] = type_counts.get(ct_str, 0) + 1
    
    for ct, count in sorted(type_counts.items()):
        print(f"  {ct}: {count} times")
    
    print()
    
    # Method 3: Find nested message/rfc822
    nested_emails = re.findall(rb'Content-Type:\s*message/rfc822', content, re.IGNORECASE)
    print(f"Found {len(nested_emails)} nested emails (message/rfc822)")
    
    # Method 4: Find attachments
    attachments = re.findall(rb'Content-Disposition:\s*attachment', content, re.IGNORECASE)
    print(f"Found {len(attachments)} attachments")
    
    # Method 5: Check for different encodings
    encodings = re.findall(rb'Content-Transfer-Encoding:\s*([^\r\n]+)', content, re.IGNORECASE)
    print(f"Found {len(encodings)} encoding declarations:")
    encoding_counts = {}
    for enc in encodings:
        enc_str = enc.decode('utf-8', errors='ignore').strip().lower()
        encoding_counts[enc_str] = encoding_counts.get(enc_str, 0) + 1
    
    for enc, count in sorted(encoding_counts.items()):
        print(f"  {enc}: {count} times")
    
    print()
    
    # Method 6: Look for large data URLs (embedded content)
    data_urls = re.findall(rb'data:([^;,]+)(?:;([^,]*))?,([A-Za-z0-9+/=\s]{100,})', content)
    print(f"Found {len(data_urls)} large data URLs (embedded content)")
    for i, (mime_type, params, data) in enumerate(data_urls):
        mime_str = mime_type.decode('utf-8', errors='ignore')
        print(f"  {i+1}: {mime_str} ({len(data):,} bytes)")

if __name__ == "__main__":
    debug_email_structure("email.eml")
