import logging
import io
import re
import base64
import html
import email
from email import policy
from email.message import EmailMessage
import olefile  # Required for parsing .msg files
from parsers.email_parser import parse_email

logger = logging.getLogger(__name__)

def parse_msg(msg_content, max_depth=10):
    """
    Enhanced parse an Outlook .msg file and extract email information including base64 inline emails.
    
    Args:
        msg_content (bytes): Content of the .msg file
        max_depth (int): Maximum recursion depth for nested emails
        
    Returns:
        dict: Parsed email data
    """
    logger.debug("Parsing .msg file with enhanced base64 detection")
    
    try:
        # Write MSG content to a temporary BytesIO object to use with olefile
        msg_file = io.BytesIO(msg_content)
        
        # Open the MSG file using olefile
        ole = olefile.OleFile(msg_file)
        
        # Convert MSG to EML format with base64 extraction
        eml_content = convert_msg_to_eml_enhanced(ole)
        
        # Use the main email parser to parse the converted EML content
        parsed_data = parse_email(eml_content, max_depth=max_depth)
        
        # Close the OLE file
        ole.close()
        
        return parsed_data
        
    except ImportError:
        logger.error("olefile module not installed. Required for .msg parsing.")
        return {"error": "olefile module not installed. Required for .msg parsing."}
    except Exception as e:
        logger.error(f"Error parsing .msg file: {str(e)}")
        return {"error": f"Failed to parse .msg file: {str(e)}"}

def convert_msg_to_eml_enhanced(ole):
    """
    Enhanced convert an Outlook MSG file to EML format with base64 inline email extraction.
    
    Args:
        ole (olefile.OleFile): OLE file object of the MSG file
        
    Returns:
        bytes: Email content in EML format with inline emails as attachments
    """
    logger.debug("Converting MSG to EML format with base64 extraction")
    
    # Create a proper EmailMessage object instead of manual string building
    eml = EmailMessage()
    
    # Extract headers
    try:
        if ole.exists('__substg1.0_007D001E'):  # Subject
            subject = ole.openstream('__substg1.0_007D001E').read().decode('utf-8', errors='replace').strip('\x00')
            eml['Subject'] = subject
    except Exception as e:
        logger.debug(f"Could not extract subject: {e}")
    
    try:
        if ole.exists('__substg1.0_0C1A001E'):  # From
            sender = ole.openstream('__substg1.0_0C1A001E').read().decode('utf-8', errors='replace').strip('\x00')
            eml['From'] = sender
    except Exception as e:
        logger.debug(f"Could not extract sender: {e}")
    
    try:
        if ole.exists('__substg1.0_0E04001E'):  # To
            recipient = ole.openstream('__substg1.0_0E04001E').read().decode('utf-8', errors='replace').strip('\x00')
            eml['To'] = recipient
    except Exception as e:
        logger.debug(f"Could not extract recipient: {e}")
    
    try:
        if ole.exists('__substg1.0_0042001E'):  # In-Reply-To
            in_reply_to = ole.openstream('__substg1.0_0042001E').read().decode('utf-8', errors='replace').strip('\x00')
            eml['In-Reply-To'] = in_reply_to
    except Exception as e:
        logger.debug(f"Could not extract in-reply-to: {e}")
    
    # Extract date
    try:
        if ole.exists('__substg1.0_00390040'):  # Sent time (64-bit)
            sent_time = ole.openstream('__substg1.0_00390040').read()
            if len(sent_time) == 8:
                filetime = int.from_bytes(sent_time, byteorder='little')
                unix_time = (filetime - 116444736000000000) // 10000000
                from datetime import datetime, timezone
                date_str = datetime.fromtimestamp(unix_time, tz=timezone.utc).strftime('%a, %d %b %Y %H:%M:%S %z')
                eml['Date'] = date_str
    except Exception as e:
        logger.debug(f"Could not extract date: {e}")
    
    # Extract body content
    plain_body = ""
    html_body = ""
    
    try:
        if ole.exists('__substg1.0_1000001E'):  # Plain text body
            plain_body = ole.openstream('__substg1.0_1000001E').read().decode('utf-8', errors='replace')
    except Exception as e:
        logger.debug(f"Could not extract plain body: {e}")
    
    try:
        if ole.exists('__substg1.0_1013001E'):  # HTML body
            html_body = ole.openstream('__substg1.0_1013001E').read().decode('utf-8', errors='replace')
    except Exception as e:
        logger.debug(f"Could not extract HTML body: {e}")
    
    # ENHANCED: Extract base64 inline emails from HTML body
    inline_emails = []
    if html_body:
        logger.debug(f"Analyzing HTML body of {len(html_body)} characters for base64 content")
        inline_emails = extract_base64_emails_from_html(html_body)
        
        # Clean HTML body by removing large base64 blocks for better readability
        cleaned_html = clean_html_of_base64(html_body)
        html_body = cleaned_html
    
    # Set email content
    if html_body and plain_body:
        eml.set_content(plain_body, subtype='plain')
        eml.add_alternative(html_body, subtype='html')
    elif html_body:
        eml.set_content(html_body, subtype='html')
    elif plain_body:
        eml.set_content(plain_body, subtype='plain')
    else:
        eml.set_content('(empty)', subtype='plain')
    
    # Add extracted inline emails as message/rfc822 attachments
    for idx, email_data in enumerate(inline_emails):
        try:
            eml.add_attachment(
                email_data,
                maintype='message',
                subtype='rfc822',
                filename=f'inline_email_{idx + 1}.eml'
            )
            logger.info(f"Added inline email {idx + 1} as attachment")
        except Exception as e:
            logger.error(f"Failed to add inline email {idx + 1} as attachment: {e}")
    
    # Extract regular attachments from OLE structure
    try:
        extract_ole_attachments(ole, eml)
    except Exception as e:
        logger.warning(f"Error extracting OLE attachments: {e}")
    
    return eml.as_bytes()

def extract_base64_emails_from_html(html_content):
    """
    Extract base64 encoded emails from HTML content.
    
    Args:
        html_content (str): HTML content that may contain base64 emails
        
    Returns:
        list: List of decoded email bytes
    """
    inline_emails = []
    
    if not html_content:
        return inline_emails
    
    # Patterns for base64 content in HTML
    base64_patterns = [
        # CDATA sections
        r'<!\[CDATA\[(.*?)\]\]>',
        # PRE elements
        r'<pre[^>]*>(.*?)</pre>',
        # DIV elements with large base64 content
        r'<div[^>]*>([A-Za-z0-9+/=\r\n\s&;]{500,}?)</div>',
        # After Content-Type headers
        r'Content-Type:\s*message/rfc822[^<]*?([A-Za-z0-9+/=\r\n\s&;]{400,})',
        # Large base64 blocks
        r'([A-Za-z0-9+/=\r\n\s&;]{800,})',
        # After email headers
        r'(?:From:|To:|Subject:|Date:)[^<]*?([A-Za-z0-9+/=\r\n\s&;]{400,})'
    ]
    
    seen_hashes = set()  # Avoid duplicates
    
    for pattern_str in base64_patterns:
        try:
            pattern = re.compile(pattern_str, re.DOTALL | re.IGNORECASE)
            matches = pattern.findall(html_content)
            
            for match in matches:
                email_data = decode_html_base64_content(match)
                if email_data:
                    # Check for duplicates
                    import hashlib
                    content_hash = hashlib.sha256(email_data).hexdigest()
                    
                    if content_hash not in seen_hashes:
                        seen_hashes.add(content_hash)
                        
                        # Validate it's an email
                        if validate_email_content(email_data):
                            inline_emails.append(email_data)
                            logger.info(f"Extracted inline email from HTML ({len(email_data)} bytes)")
        
        except Exception as e:
            logger.debug(f"Error processing pattern: {e}")
    
    return inline_emails

def decode_html_base64_content(content):
    """
    Decode base64 content that may be HTML-encoded.
    
    Args:
        content (str): Potentially base64-encoded content
        
    Returns:
        bytes or None: Decoded email content
    """
    if not content or len(content) < 100:
        return None
    
    try:
        # Decode HTML entities
        cleaned = html.unescape(content)
        
        # Remove HTML tags
        cleaned = re.sub(r'<[^>]+>', '', cleaned)
        
        # Keep only base64 characters
        cleaned = re.sub(r'[^A-Za-z0-9+/=]', '', cleaned)
        
        # Ensure proper padding
        while len(cleaned) % 4:
            cleaned += '='
        
        if len(cleaned) < 100:
            return None
        
        # Decode base64
        decoded = base64.b64decode(cleaned, validate=True)
        
        return decoded
        
    except Exception as e:
        logger.debug(f"Failed to decode base64 content: {e}")
        return None

def validate_email_content(email_data):
    """
    Validate that decoded content is an email.
    
    Args:
        email_data (bytes): Decoded content
        
    Returns:
        bool: True if valid email
    """
    try:
        # Try to parse as email
        email_msg = email.message_from_bytes(email_data, policy=policy.default)
        
        # Check for email headers
        email_indicators = ['From', 'To', 'Subject', 'Date', 'Message-ID']
        found_headers = sum(1 for header in email_indicators if email_msg.get(header))
        
        # Need at least 2 email headers
        return found_headers >= 2
        
    except Exception:
        return False

def clean_html_of_base64(html_content):
    """
    Remove large base64 blocks from HTML for cleaner display.
    
    Args:
        html_content (str): HTML content
        
    Returns:
        str: Cleaned HTML content
    """
    # Replace large base64 blocks with placeholder
    cleaned = re.sub(
        r'[A-Za-z0-9+/=\r\n\s]{500,}', 
        '[Base64 content extracted as attachment]', 
        html_content
    )
    return cleaned

def extract_ole_attachments(ole, eml):
    """
    Extract regular attachments from OLE structure (basic implementation).
    
    Args:
        ole (olefile.OleFile): OLE file object
        eml (EmailMessage): Email message to add attachments to
    """
    # This is a simplified version - full attachment extraction from OLE is complex
    # For now, just log if attachments exist
    
    # Look for attachment directories
    attachment_dirs = [dirname for dirname in ole.listdir() if dirname.startswith('__attach_version1.0_')]
    
    if attachment_dirs:
        logger.info(f"Found {len(attachment_dirs)} regular attachments in MSG file")
        # TODO: Implement full attachment extraction
        # This would require parsing each attachment directory structure
    
    return

# Test function
def test_enhanced_msg_parser(msg_file_path):
    """Test the enhanced MSG parser."""
    try:
        with open(msg_file_path, 'rb') as f:
            msg_content = f.read()
        
        result = parse_msg(msg_content)
        
        print(f"✓ MSG parsing completed")
        print(f"✓ Result type: {type(result)}")
        
        if 'error' in result:
            print(f"✗ Error: {result['error']}")
        else:
            print(f"✓ Successfully parsed MSG file")
            
            # Count message layers
            if 'message_layers' in result:
                print(f"✓ Found {len(result['message_layers'])} message layers")
                
                # Count attachments across all layers
                total_attachments = 0
                for layer in result['message_layers']:
                    if 'attachments' in layer:
                        total_attachments += len(layer['attachments'])
                
                print(f"✓ Total attachments found: {total_attachments}")
        
        return result
        
    except Exception as e:
        print(f"✗ Test failed: {e}")
        return None

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        # Enable debug logging
        logging.basicConfig(level=logging.DEBUG)
        
        msg_file = sys.argv[1]
        print(f"Testing enhanced OLE-based MSG parser on: {msg_file}")
        test_enhanced_msg_parser(msg_file)
    else:
        print("Usage: python enhanced_olefile_parser.py <msg_file>")