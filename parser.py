#!/usr/bin/env python3
"""
Email Content Parser using Python's standard email library
Much more robust and simpler than manual regex parsing

KEY FEATURE: Binary format detection runs BEFORE MIME type filtering,
so .msg and TNEF files are detected even when mislabeled as 
'application/octet-stream' or other generic types.

NEW FEATURE: Extracts IP addresses, domains, and URLs from all text content
"""

import json
import argparse
import tempfile
import os
import re
import ipaddress
import html
from pathlib import Path
from typing import List, Dict, Any, Iterator, Optional, Set, Tuple
import base64

# Standard library email imports
from email import policy
from email.parser import BytesParser
from email.message import EmailMessage

class EmailParser:
    """Parser using standard library email package with artifact extraction"""
    
    # Image MIME types to skip
    IMAGE_MIME_TYPES = {
        'image/jpeg', 'image/jpg', 'image/png', 'image/gif', 
        'image/bmp', 'image/svg+xml', 'image/webp', 'image/tiff',
        'image/x-icon', 'image/vnd.microsoft.icon'
    }
    
    # Email MIME types that should be recursively parsed
    EMAIL_MIME_TYPES = {
        'message/rfc822',
        'application/vnd.ms-outlook',
        'application/x-ms-outlook',
        'application/ms-outlook',
        'application/ms-tnef',
        'message/partial',
        'message/external-body'
    }
    
    # Binary email format signatures
    OLE_SIGNATURE = b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1"     # .msg / CFBF
    TNEF_SIGNATURE = b"\x78\x9F\x3E\x22"                     # winmail.dat (TNEF)
    
    # Regex patterns for artifact extraction (permissive)
    URL_PATTERN = re.compile(
        r'(?i)\b(?:'
        r'(?:https?|ftp|ftps|sftp|file|mailto|tel|sms)://'  # Common schemes
        r'|(?:www\d{0,3}\.)'                                # www variants
        r'|(?:[a-z0-9.\-]+\.(?:com|org|net|edu|gov|mil|int|info|biz|name|museum|coop|aero|[a-z]{2}))'  # Domains
        r')'
        r'[^\s<>"\'{}|\\^`\[\]]*'                           # URL path/query (permissive)
        , re.IGNORECASE
    )
    
    IP_PATTERN = re.compile(
        r'\b(?:'
        r'(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'  # IPv4
        r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)'
        r'|'
        r'(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}'          # IPv6 full
        r'|'
        r'::1|::ffff:[0-9\.]+|::[0-9a-fA-F:]*'               # IPv6 abbreviated
        r')\b'
    )
    
    DOMAIN_PATTERN = re.compile(
        r'\b(?:'
        r'(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)*'      # Subdomains
        r'[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?'             # Domain
        r'\.(?:com|org|net|edu|gov|mil|int|info|biz|name|museum|coop|aero|[a-z]{2,})'  # TLD
        r')\b'
        , re.IGNORECASE
    )
    
    # HTML tag removal pattern
    HTML_TAG_PATTERN = re.compile(r'<[^>]+>')
    
    def __init__(self, max_depth: int = 10, include_raw: bool = False):
        self.max_depth = max_depth
        self.include_raw = include_raw
        self.reset()
    
    def reset(self):
        """Reset parser state"""
        self.raw_content = b''
        self.content_blocks = []
        self.current_depth = 0
        self.statistics = {}
        self.all_text_content = []  # Store all text for artifact extraction
    
    def parse_file(self, file_path: str) -> Dict[str, Any]:
        """Parse an email file"""
        file_path = Path(file_path)
        
        if not file_path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")
        
        with open(file_path, 'rb') as f:
            content = f.read()
        
        return self.parse(content, file_path.name)
    
    def parse(self, raw_content: bytes, source_name: str = "email", depth: int = 0) -> Dict[str, Any]:
        """Parse email content using std-lib email module."""
        self.reset()
        self.current_depth = depth
        self.raw_content = raw_content  # Keep for statistics
        
        # Check depth limit
        if depth > self.max_depth:
            return {
                'source': source_name,
                'error': f'Maximum depth ({self.max_depth}) exceeded',
                'depth': depth
            }
        
        try:
            # Parse email using standard library
            msg: EmailMessage = BytesParser(policy=policy.default).parsebytes(raw_content)
            
            # Walk the message tree and collect content blocks
            self.content_blocks = list(self._walk_message(msg, depth))
            
            # Build and return output (includes artifact extraction)
            return self._build_output(source_name, msg)
            
        except Exception as e:
            return {
                'source': source_name,
                'error': f'Email parsing failed: {str(e)}',
                'depth': depth,
                'size': len(raw_content)
            }
    
    def _clean_html(self, text: str) -> str:
        """Remove HTML tags and decode entities"""
        if not text:
            return ""
        
        # Remove HTML tags
        text = self.HTML_TAG_PATTERN.sub(' ', text)
        
        # Decode HTML entities
        text = html.unescape(text)
        
        # Clean up whitespace
        text = ' '.join(text.split())
        
        return text
    
    def _extract_artifacts_from_text(self, text: str) -> Dict[str, Set[str]]:
        """Extract URLs, IPs, and domains from text content"""
        if not text or len(text.strip()) < 3:
            return {'urls': set(), 'ips': set(), 'domains': set()}
        
        # Clean HTML if present
        clean_text = self._clean_html(text)
        
        # Extract URLs
        urls = set()
        for match in self.URL_PATTERN.finditer(clean_text):
            url = match.group().strip('.,;:!?')  # Remove trailing punctuation
            if len(url) > 3 and '.' in url:  # Basic sanity check
                urls.add(url.lower())
        
        # Extract IP addresses
        ips = set()
        for match in self.IP_PATTERN.finditer(clean_text):
            ip_str = match.group()
            try:
                # Validate IP address
                ip_obj = ipaddress.ip_address(ip_str)
                # Skip localhost and private IPs for noise reduction (but keep if user wants permissive)
                ips.add(str(ip_obj))
            except ValueError:
                # If validation fails, still add if it looks like IP (permissive mode)
                if re.match(r'^\d+\.\d+\.\d+\.\d+$', ip_str):
                    ips.add(ip_str)
        
        # Extract domains
        domains = set()
        for match in self.DOMAIN_PATTERN.finditer(clean_text):
            domain = match.group().lower().strip('.,;:!?')
            # Basic validation
            if (len(domain) > 3 and 
                domain.count('.') >= 1 and 
                not domain.startswith('.') and 
                not domain.endswith('.')):
                domains.add(domain)
        
        # Remove domains that are already captured in URLs
        filtered_domains = set()
        for domain in domains:
            # Check if this domain appears in any URL
            domain_in_url = any(domain in url for url in urls)
            if not domain_in_url:
                filtered_domains.add(domain)
        
        return {
            'urls': urls,
            'ips': ips, 
            'domains': filtered_domains
        }
    
    def _collect_text_content(self, content_block: Dict[str, Any]) -> None:
        """Collect text content from a content block for artifact extraction"""
        block_type = content_block.get('type', '')
        content = content_block.get('content', '')
        
        # Skip if no content or if it's binary
        if not content or content_block.get('encoding') == 'base64':
            return
        
        # Extract text based on block type
        if block_type in ['email_headers']:
            # Extract from headers
            headers = content_block.get('headers', {})
            for header_name, header_value in headers.items():
                if isinstance(header_value, str) and header_value:
                    self.all_text_content.append({
                        'text': header_value,
                        'source': f"header_{header_name.lower()}",
                        'block_type': block_type
                    })
        
        elif block_type in ['email_body', 'mime_part']:
            # Extract from body/content
            if isinstance(content, str) and content.strip():
                self.all_text_content.append({
                    'text': content,
                    'source': f"{block_type}_{content_block.get('mime_type', 'unknown')}",
                    'block_type': block_type
                })
        
        elif block_type == 'tnef_container':
            # Extract from TNEF attachments
            attachments = content_block.get('attachments', [])
            for i, attachment in enumerate(attachments):
                att_content = attachment.get('content', '')
                if isinstance(att_content, str) and att_content.strip():
                    # Only process if not base64 encoded
                    if attachment.get('encoding') != 'base64':
                        self.all_text_content.append({
                            'text': att_content,
                            'source': f"tnef_attachment_{i}",
                            'block_type': block_type
                        })
        
        # Handle nested content recursively
        nested_content = content_block.get('nested_content')
        if nested_content:
            if isinstance(nested_content, dict):
                nested_blocks = nested_content.get('content', [])
                if isinstance(nested_blocks, list):
                    for nested_block in nested_blocks:
                        self._collect_text_content(nested_block)

    def _parse_msg_file(self, payload: bytes, depth: int, part_id: str) -> dict:
        """Parse MSG file using extract_msg library"""
        try:
            import extract_msg
            
            # Create a temporary file to store the MSG data
            with tempfile.NamedTemporaryFile(suffix='.msg', delete=False) as tmp_file:
                tmp_file.write(payload)
                tmp_file_path = tmp_file.name
            
            try:
                # Parse the MSG file from the temporary file
                msg_obj = extract_msg.Message(tmp_file_path)
                
                # Extract the RFC822 representation
                # Note: extract_msg doesn't have as_bytes(), we need to construct RFC822 manually
                rfc822_content = self._msg_to_rfc822(msg_obj)
                
                # Parse the converted content recursively
                nested_parser = EmailParser(max_depth=self.max_depth, include_raw=self.include_raw)
                nested_result = nested_parser.parse(
                    rfc822_content, 
                    f"nested_msg_{part_id}", 
                    depth + 1
                )
                
                return {
                    'type': 'nested_msg',
                    'detected_format': 'outlook_msg',
                    'size': len(payload),
                    'converted_size': len(rfc822_content),
                    'nested_content': nested_result,
                    'depth': depth,
                    'msg_metadata': {
                        'subject': getattr(msg_obj, 'subject', ''),
                        'sender': getattr(msg_obj, 'sender', ''),
                        'to': getattr(msg_obj, 'to', ''),
                        'date': str(getattr(msg_obj, 'date', '')),
                        'message_id': getattr(msg_obj, 'messageId', ''),
                    }
                }
                
            finally:
                # Clean up the temporary file
                try:
                    os.unlink(tmp_file_path)
                except:
                    pass
                    
        except ImportError:
            return {
                'type': 'binary_msg',
                'detected_format': 'outlook_msg',
                'size': len(payload),
                'content': self._encode_content(payload),
                'encoding': 'base64',
                'note': 'Install extract_msg library to parse MSG files',
                'depth': depth
            }
        except Exception as e:
            return {
                'type': 'binary_msg',
                'detected_format': 'outlook_msg',
                'size': len(payload),
                'error': str(e),
                'content': self._encode_content(payload),
                'encoding': 'base64',
                'depth': depth
            }

    def _msg_to_rfc822(self, msg_obj) -> bytes:
        """Convert extract_msg Message object to RFC822 format"""
        try:
            # Build a basic RFC822 message from MSG properties
            lines = []
            
            # Add headers
            if hasattr(msg_obj, 'subject') and msg_obj.subject:
                lines.append(f"Subject: {msg_obj.subject}")
            
            if hasattr(msg_obj, 'sender') and msg_obj.sender:
                lines.append(f"From: {msg_obj.sender}")
                
            if hasattr(msg_obj, 'to') and msg_obj.to:
                lines.append(f"To: {msg_obj.to}")
                
            if hasattr(msg_obj, 'date') and msg_obj.date:
                lines.append(f"Date: {msg_obj.date}")
                
            if hasattr(msg_obj, 'messageId') and msg_obj.messageId:
                lines.append(f"Message-ID: {msg_obj.messageId}")
            
            # Add content type
            lines.append("Content-Type: text/plain; charset=utf-8")
            lines.append("Content-Transfer-Encoding: 8bit")
            
            # Empty line before body
            lines.append("")
            
            # Add body
            if hasattr(msg_obj, 'body') and msg_obj.body:
                lines.append(msg_obj.body)
            
            # Join with CRLF
            rfc822_content = "\r\n".join(lines)
            return rfc822_content.encode('utf-8')
            
        except Exception as e:
            # Fallback: create minimal RFC822 message
            fallback_content = f"Subject: [MSG Parse Error: {e}]\r\n\r\n[Could not convert MSG to RFC822 format]"
            return fallback_content.encode('utf-8')
    
    def _walk_message(self, msg: EmailMessage, depth: int) -> Iterator[Dict[str, Any]]:
        """Yield dictionaries describing each part, recurse on nested emails."""
        
        # Collect all headers for this message/part
        headers = dict(msg.items())
        
        # Always yield headers
        header_block = {
            'type': 'email_headers',
            'headers': headers,
            'depth': depth,
            'message_id': headers.get('Message-ID', ''),
            'subject': headers.get('Subject', ''),
            'from': headers.get('From', ''),
            'to': headers.get('To', ''),
            'date': headers.get('Date', '')
        }
        
        # Collect text content for artifact extraction
        self._collect_text_content(header_block)
        yield header_block
        
        # Handle multipart messages
        if msg.is_multipart():
            print(f"{'  ' * depth}Processing multipart message: {msg.get_content_type()}")
            
            for i, part in enumerate(msg.iter_parts()):
                content_type = part.get_content_type().lower()
                
                print(f"{'  ' * depth}  Part {i}: {content_type}")
                
                # Decode payload first for all processing
                payload = part.get_payload(decode=True) or b''
                
                # 1️⃣ Check for binary email formats FIRST (before MIME type filtering)
                binary_kind = self._detect_binary_email(payload)
                
                if binary_kind == "msg":
                    print(f"{'  ' * depth}    🔍 Detected .msg file by signature ({len(payload):,} bytes)")
                    result = self._parse_msg_file(payload, depth, str(id(part)))
                    result['mime_type'] = content_type
                    result['declared_type'] = content_type
                    result['filename'] = part.get_filename()
                    
                    # Collect text content for artifact extraction
                    self._collect_text_content(result)
                    yield result
                    continue
                
                elif binary_kind == "tnef":
                    print(f"{'  ' * depth}    🔍 Detected TNEF file by signature ({len(payload):,} bytes)")
                    try:
                        from tnefparse import TNEF
                        tnef_obj = TNEF(payload)
                        
                        # Extract attachment information
                        attachments = []
                        for attachment in tnef_obj.attachments:
                            att_info = {
                                'filename': attachment.name,
                                'size': len(attachment.data),
                                'long_filename': getattr(attachment, 'long_filename', None),
                                'created': str(getattr(attachment, 'created', None)),
                                'modified': str(getattr(attachment, 'modified', None))
                            }
                            
                            # Include small attachments, skip large ones
                            if len(attachment.data) < 100000:  # 100KB limit
                                att_info['content'] = self._encode_content(attachment.data)
                                att_info['encoding'] = self._determine_encoding(attachment.data)
                            else:
                                att_info['note'] = 'Content skipped due to size'
                            
                            attachments.append(att_info)
                        
                        tnef_block = {
                            'type': 'tnef_container',
                            'mime_type': content_type,
                            'declared_type': content_type,
                            'detected_format': 'tnef_winmail',
                            'size': len(payload),
                            'filename': part.get_filename(),
                            'attachment_count': len(attachments),
                            'attachments': attachments,
                            'depth': depth
                        }
                        
                        # Collect text content for artifact extraction
                        self._collect_text_content(tnef_block)
                        yield tnef_block
                        
                    except ImportError:
                        print(f"{'  ' * depth}        tnefparse library not available")
                        result = {
                            'type': 'binary_tnef',
                            'mime_type': content_type,
                            'declared_type': content_type,
                            'detected_format': 'tnef_winmail',
                            'size': len(payload),
                            'filename': part.get_filename(),
                            'content': self._encode_content(payload),
                            'encoding': 'base64',
                            'note': 'Install tnefparse library to extract TNEF attachments',
                            'depth': depth
                        }
                        self._collect_text_content(result)
                        yield result
                    except Exception as e:
                        print(f"{'  ' * depth}        Error parsing TNEF file: {e}")
                        result = {
                            'type': 'binary_tnef',
                            'mime_type': content_type,
                            'declared_type': content_type,
                            'detected_format': 'tnef_winmail',
                            'size': len(payload),
                            'filename': part.get_filename(),
                            'error': str(e),
                            'content': self._encode_content(payload),
                            'encoding': 'base64',
                            'depth': depth
                        }
                        self._collect_text_content(result)
                        yield result
                    continue
                
                # 2️⃣ Skip large image parts (after binary detection)
                if self._is_image_mime_type(content_type):
                    print(f"{'  ' * depth}    Skipping image part ({len(payload):,} bytes)")
                    
                    # Still record small images or provide metadata for large ones
                    if len(payload) < 10000:  # Include small images
                        yield {
                            'type': 'image_part',
                            'mime_type': content_type,
                            'filename': part.get_filename(),
                            'size': len(payload),
                            'content': self._encode_content(payload),
                            'encoding': self._determine_encoding(payload),
                            'depth': depth
                        }
                    else:
                        # Just metadata for large images
                        yield {
                            'type': 'large_image_part',
                            'mime_type': content_type,
                            'filename': part.get_filename(),
                            'size': len(payload),
                            'depth': depth,
                            'note': 'Content skipped due to size'
                        }
                    continue
                
                # 3️⃣ Handle nested email messages (RFC822, etc.)
                if content_type in self.EMAIL_MIME_TYPES:
                    print(f"{'  ' * depth}    Processing nested email/message format")
                    
                    try:
                        # For message/rfc822, the payload might already be an EmailMessage
                        if content_type == 'message/rfc822':
                            nested_msg = part.get_payload()[0] if part.get_payload() else None
                            if isinstance(nested_msg, EmailMessage):
                                # Recursively walk the nested message
                                result = {
                                    'type': 'nested_email',
                                    'mime_type': content_type,
                                    'nested_content': {
                                        'source': f"nested_email_{id(part)}",
                                        'content': list(self._walk_message(nested_msg, depth + 1)),
                                        'depth': depth + 1
                                    },
                                    'depth': depth
                                }
                                self._collect_text_content(result)
                                yield result
                                continue
                        
                        # Fallback: parse raw bytes as email
                        if payload:
                            nested_parser = EmailParser(max_depth=self.max_depth, include_raw=self.include_raw)
                            nested_result = nested_parser.parse(
                                payload,
                                source_name=f"nested_email_{id(part)}",
                                depth=depth + 1
                            )
                            result = {
                                'type': 'nested_email',
                                'mime_type': content_type,
                                'nested_content': nested_result,
                                'depth': depth
                            }
                            self._collect_text_content(result)
                            yield result
                        
                    except Exception as e:
                        print(f"{'  ' * depth}    Error parsing nested email: {e}")
                        yield {
                            'type': 'nested_email_error',
                            'mime_type': content_type,
                            'error': str(e),
                            'depth': depth
                        }
                    continue
                
                # 4️⃣ Handle regular MIME parts (everything else)
                try:
                    # Get additional metadata
                    disposition = part.get_content_disposition() or ''
                    filename = part.get_filename()
                    charset = part.get_content_charset()
                    
                    print(f"{'  ' * depth}    Processing {content_type} part ({len(payload):,} bytes)")
                    
                    # Use improved charset handling
                    text, encoding = self._to_str(payload, charset)
                    
                    mime_part_data = {
                        'type': 'mime_part',
                        'mime_type': content_type,
                        'disposition': disposition,
                        'filename': filename,
                        'charset': charset,
                        'size': len(payload),
                        'content': text,
                        'encoding': encoding,
                        'headers': dict(part.items()),
                        'depth': depth
                    }
                    
                    # Add raw content for forensics if requested
                    if self.include_raw:
                        mime_part_data['content_raw_b64'] = base64.b64encode(payload).decode()
                    
                    # Collect text content for artifact extraction
                    self._collect_text_content(mime_part_data)
                    yield mime_part_data
                    
                except Exception as e:
                    print(f"{'  ' * depth}    Error processing part: {e}")
                    yield {
                        'type': 'mime_part_error',
                        'mime_type': content_type,
                        'error': str(e),
                        'depth': depth
                    }
        
        # Handle single-part messages
        else:
            print(f"{'  ' * depth}Processing single-part message: {msg.get_content_type()}")
            
            try:
                payload = msg.get_payload(decode=True) or b''
                content_type = msg.get_content_type().lower()
                
                # 1️⃣ Check for binary email formats FIRST (same as multipart)
                binary_kind = self._detect_binary_email(payload)
                
                if binary_kind == "msg":
                    print(f"{'  ' * depth}  🔍 Detected .msg file by signature ({len(payload):,} bytes)")
                    result = self._parse_msg_file(payload, depth, "single")
                    result['mime_type'] = content_type
                    result['declared_type'] = content_type
                    self._collect_text_content(result)
                    yield result
                    return  # Don't process as regular body
                
                elif binary_kind == "tnef":
                    print(f"{'  ' * depth}  🔍 Detected TNEF file by signature ({len(payload):,} bytes)")
                    try:
                        from tnefparse import TNEF
                        tnef_obj = TNEF(payload)
                        
                        # Extract attachment information
                        attachments = []
                        for attachment in tnef_obj.attachments:
                            att_info = {
                                'filename': attachment.name,
                                'size': len(attachment.data),
                                'long_filename': getattr(attachment, 'long_filename', None),
                                'created': str(getattr(attachment, 'created', None)),
                                'modified': str(getattr(attachment, 'modified', None))
                            }
                            
                            # Include small attachments, skip large ones
                            if len(attachment.data) < 100000:  # 100KB limit
                                att_info['content'] = self._encode_content(attachment.data)
                                att_info['encoding'] = self._determine_encoding(attachment.data)
                            else:
                                att_info['note'] = 'Content skipped due to size'
                            
                            attachments.append(att_info)
                        
                        result = {
                            'type': 'tnef_container',
                            'mime_type': content_type,
                            'declared_type': content_type,
                            'detected_format': 'tnef_winmail',
                            'size': len(payload),
                            'attachment_count': len(attachments),
                            'attachments': attachments,
                            'depth': depth
                        }
                        self._collect_text_content(result)
                        yield result
                        return  # Don't process as regular body
                        
                    except ImportError:
                        print(f"{'  ' * depth}    tnefparse library not available")
                        result = {
                            'type': 'binary_tnef',
                            'mime_type': content_type,
                            'declared_type': content_type,
                            'detected_format': 'tnef_winmail',
                            'size': len(payload),
                            'content': self._encode_content(payload),
                            'encoding': 'base64',
                            'note': 'Install tnefparse library to extract TNEF attachments',
                            'depth': depth
                        }
                        self._collect_text_content(result)
                        yield result
                        return
                        
                    except Exception as e:
                        print(f"{'  ' * depth}    Error parsing TNEF file: {e}")
                        result = {
                            'type': 'binary_tnef',
                            'mime_type': content_type,
                            'declared_type': content_type,
                            'detected_format': 'tnef_winmail',
                            'size': len(payload),
                            'error': str(e),
                            'content': self._encode_content(payload),
                            'encoding': 'base64',
                            'depth': depth
                        }
                        self._collect_text_content(result)
                        yield result
                        return
                
                # 2️⃣ Not a binary format, treat as regular email body
                charset = msg.get_content_charset()
                text, encoding = self._to_str(payload, charset)
                
                email_body_data = {
                    'type': 'email_body',
                    'mime_type': content_type,
                    'charset': charset,
                    'size': len(payload),
                    'content': text,
                    'encoding': encoding,
                    'depth': depth
                }
                
                # Add raw content for forensics if requested
                if self.include_raw:
                    email_body_data['content_raw_b64'] = base64.b64encode(payload).decode()
                
                # Collect text content for artifact extraction
                self._collect_text_content(email_body_data)
                yield email_body_data
                
            except Exception as e:
                print(f"{'  ' * depth}Error processing email body: {e}")
                yield {
                    'type': 'email_body_error',
                    'error': str(e),
                    'depth': depth
                }
    
    def _is_image_mime_type(self, mime_type: str) -> bool:
        """Check if a MIME type is an image"""
        return (mime_type.lower() in self.IMAGE_MIME_TYPES or 
                mime_type.lower().startswith('image/'))
    
    def _detect_binary_email(self, buf: bytes) -> Optional[str]:
        """Detect binary email formats by signature"""
        if not buf:
            return None
        if buf.startswith(self.OLE_SIGNATURE):
            return "msg"
        if buf.startswith(self.TNEF_SIGNATURE):
            return "tnef"
        return None
    
    def _to_str(self, data: bytes, charset: str | None) -> tuple[str, str]:
        """
        Return (text, encoding_name) – text is always a str.
        If decoding fails we fall back to base64.
        """
        if not data:
            return "", "empty"

        try:
            # prefer part's charset, else utf-8
            text = data.decode(charset or "utf-8", errors="replace")
            return text, (charset or "utf-8").lower()
        except LookupError:           # unknown charset label
            pass
        except UnicodeDecodeError:    # declared charset wrong
            pass

        # Try charset detection if available
        try:
            import chardet
            detected = chardet.detect(data)
            if detected and detected['encoding'] and detected['confidence'] > 0.7:
                try:
                    text = data.decode(detected['encoding'], errors="replace")
                    return text, detected['encoding'].lower()
                except (LookupError, UnicodeDecodeError):
                    pass
        except ImportError:
            pass

        # last resort – keep as base64
        return base64.b64encode(data).decode("ascii"), "base64"
    
    def _encode_content(self, content: bytes) -> str:
        """Encode content for JSON storage (legacy method)"""
        text, _ = self._to_str(content, None)
        return text
    
    def _determine_encoding(self, content: bytes) -> str:
        """Determine how content was encoded for storage (legacy method)"""
        _, encoding = self._to_str(content, None)
        return encoding
    
    def _extract_all_artifacts(self) -> Dict[str, Any]:
        """Extract and deduplicate all artifacts from collected text content"""
        all_urls = set()
        all_ips = set()
        all_domains = set()
        
        # Source breakdown for detailed analysis
        sources_breakdown = {}
        
        print(f"\n🔍 Extracting artifacts from {len(self.all_text_content)} text blocks...")
        
        for text_block in self.all_text_content:
            text = text_block['text']
            source = text_block['source']
            
            # Extract artifacts from this text block
            artifacts = self._extract_artifacts_from_text(text)
            
            # Add to global sets
            all_urls.update(artifacts['urls'])
            all_ips.update(artifacts['ips'])
            all_domains.update(artifacts['domains'])
            
            # Track per-source statistics
            if artifacts['urls'] or artifacts['ips'] or artifacts['domains']:
                sources_breakdown[source] = {
                    'urls': len(artifacts['urls']),
                    'ips': len(artifacts['ips']),
                    'domains': len(artifacts['domains']),
                    'block_type': text_block['block_type']
                }
        
        # Convert sets to sorted lists for JSON serialization
        return {
            'urls': sorted(list(all_urls)),
            'ip_addresses': sorted(list(all_ips)),
            'domains': sorted(list(all_domains)),
            'statistics': {
                'total_urls': len(all_urls),
                'total_ips': len(all_ips),
                'total_domains': len(all_domains),
                'sources_with_artifacts': len(sources_breakdown),
                'text_blocks_processed': len(self.all_text_content)
            },
            'sources_breakdown': sources_breakdown
        }
    
    def _build_output(self, source_name: str, msg: EmailMessage = None) -> Dict[str, Any]:
        """Build the final output structure"""
        
        # Sort content blocks by depth and type for better organization
        sorted_blocks = sorted(self.content_blocks, 
                             key=lambda x: (x['depth'], x['type'], x.get('mime_type', '')))
        
        # Collect statistics
        type_counts = {}
        mime_type_counts = {}
        depth_counts = {}
        
        for block in sorted_blocks:
            # Count by type
            block_type = block['type']
            type_counts[block_type] = type_counts.get(block_type, 0) + 1
            
            # Count by MIME type
            mime_type = block.get('mime_type', 'unknown')
            if mime_type != 'unknown':
                mime_type_counts[mime_type] = mime_type_counts.get(mime_type, 0) + 1
            
            # Count by depth
            depth = block['depth']
            depth_counts[depth] = depth_counts.get(depth, 0) + 1
        
        # Build comprehensive statistics
        statistics = {
            'total_size': len(self.raw_content),
            'content_blocks': len(sorted_blocks),
            'max_depth': max(depth_counts.keys()) if depth_counts else 0,
            'type_counts': type_counts,
            'mime_type_counts': mime_type_counts,
            'depth_distribution': depth_counts,
            'has_nested_emails': any(b['type'] == 'nested_email' for b in sorted_blocks),
            'has_attachments': any(b.get('disposition', '').lower() == 'attachment' for b in sorted_blocks),
            'multipart': msg.is_multipart() if msg else False
        }
        
        # Add email-specific metadata if available
        email_metadata = {}
        if msg:
            email_metadata = {
                'subject': msg.get('Subject', ''),
                'from': msg.get('From', ''),
                'to': msg.get('To', ''),
                'date': msg.get('Date', ''),
                'message_id': msg.get('Message-ID', ''),
                'content_type': msg.get_content_type()
            }
        
        # Extract artifacts from all collected text content
        extracted_artifacts = self._extract_all_artifacts()
        
        return {
            'source': source_name,
            'size': len(self.raw_content),
            'depth': self.current_depth,
            'email_metadata': email_metadata,
            'content': sorted_blocks,
            'statistics': statistics,
            'extracted_artifacts': extracted_artifacts
        }

def main():
    parser = argparse.ArgumentParser(description='Email Content Parser (Standard Library + Binary Support + Artifact Extraction)')
    parser.add_argument('files', nargs='+', help='Email files to parse')
    parser.add_argument('-o', '--output', help='Output JSON file')
    parser.add_argument('--compact', action='store_true', help='Compact JSON output')
    parser.add_argument('--max-depth', type=int, default=10, help='Maximum recursion depth (default: 10)')
    parser.add_argument('--include-raw', action='store_true', 
                       help='Include raw base64 content for forensic analysis')
    parser.add_argument('--include-large-images', action='store_true', 
                       help='Include large images in output (may create very large files)')
    
    args = parser.parse_args()
    
    # Check for optional dependencies
    print("🔍 Checking optional dependencies:")
    try:
        import extract_msg
        print("  ✅ extract_msg: Available (can parse .msg files)")
    except ImportError:
        print("  ❌ extract_msg: Not available (install with: pip install extract_msg)")
    
    try:
        from tnefparse import TNEF
        print("  ✅ tnefparse: Available (can parse TNEF/winmail.dat files)")
    except ImportError:
        print("  ❌ tnefparse: Not available (install with: pip install tnefparse)")
    
    try:
        import chardet
        print("  ✅ chardet: Available (improves charset detection)")
    except ImportError:
        print("  ❌ chardet: Not available (install with: pip install chardet)")
    
    print("\n🎯 Features:")
    print("  • Detects .msg/.tnef files by signature (not MIME type)")
    print("  • Works even when attachments are mislabeled as 'application/octet-stream'")
    print("  • Gracefully falls back to raw binary if libraries unavailable")
    print("  • Improved charset handling with fallback detection")
    print("  • Optional raw content storage for forensic analysis")
    print("  • 🆕 Extracts URLs, IP addresses, and domains from all text content")
    print("  • 🆕 Handles HTML content and decodes entities")
    print("  • 🆕 Provides detailed artifact statistics and source breakdown")
    print()
    
    # Parse all files
    results = []
    email_parser = EmailParser(max_depth=args.max_depth, include_raw=args.include_raw)
    
    for file_path in args.files:
        try:
            print(f"\n📧 Parsing: {file_path}")
            print("=" * 60)
            
            result = email_parser.parse_file(file_path)
            results.append(result)
            
            if 'error' not in result:
                stats = result['statistics']
                artifacts = result['extracted_artifacts']
                
                print(f"\n✓ Successfully parsed: {file_path}")
                print(f"  📊 Content blocks: {stats['content_blocks']}")
                print(f"  📁 MIME types found: {len(stats['mime_type_counts'])}")
                print(f"  🔄 Max depth: {stats['max_depth']}")
                print(f"  📧 Nested emails: {stats['type_counts'].get('nested_email', 0)}")
                print(f"  📎 Attachments: {sum(1 for b in result['content'] if b.get('disposition') == 'attachment')}")
                
                # Show artifact extraction results
                print(f"\n🔍 Extracted Artifacts:")
                print(f"  🌐 URLs: {artifacts['statistics']['total_urls']}")
                print(f"  🌍 IP Addresses: {artifacts['statistics']['total_ips']}")
                print(f"  🏷️  Domains: {artifacts['statistics']['total_domains']}")
                print(f"  📝 Text blocks processed: {artifacts['statistics']['text_blocks_processed']}")
                
                # Show sample artifacts if found
                if artifacts['urls'][:3]:
                    print(f"    Sample URLs: {', '.join(artifacts['urls'][:3])}")
                if artifacts['ip_addresses'][:3]:
                    print(f"    Sample IPs: {', '.join(artifacts['ip_addresses'][:3])}")
                if artifacts['domains'][:3]:
                    print(f"    Sample domains: {', '.join(artifacts['domains'][:3])}")
                
                # Show binary format detection results
                binary_counts = {
                    'MSG files': stats['type_counts'].get('nested_msg', 0) + stats['type_counts'].get('binary_msg', 0),
                    'TNEF files': stats['type_counts'].get('tnef_container', 0) + stats['type_counts'].get('binary_tnef', 0)
                }
                
                if any(binary_counts.values()):
                    print(f"  🔒 Binary formats detected:")
                    for format_name, count in binary_counts.items():
                        if count > 0:
                            print(f"    - {format_name}: {count}")
                
                # Show MIME type breakdown
                if stats['mime_type_counts']:
                    print(f"  📄 MIME types:")
                    for mime_type, count in sorted(stats['mime_type_counts'].items()):
                        print(f"    - {mime_type}: {count}")
            else:
                print(f"✗ Error: {result['error']}")
                
        except Exception as e:
            print(f"✗ Error parsing {file_path}: {e}")
            results.append({
                'source': file_path,
                'error': str(e)
            })
    
    # Create output
    output = {
        'results': results,
        'total_files': len(results),
        'successful': len([r for r in results if 'error' not in r]),
        'parsing_method': 'standard_library_email_package_with_binary_support_and_artifact_extraction',
        'supported_binary_formats': ['outlook_msg', 'tnef_winmail'],
        'artifact_types': ['urls', 'ip_addresses', 'domains']
    }
    
    # Output results
    json_str = json.dumps(output, indent=None if args.compact else 2)
    
    if args.output:
        with open(args.output, 'w', encoding='utf-8') as f:
            f.write(json_str)
        print(f"\n💾 Results saved to: {args.output}")
    else:
        print("\n" + "="*60)
        print("📋 PARSING RESULTS:")
        print("="*60)
        # For console output, show summary instead of full JSON
        for result in results:
            if 'error' not in result:
                artifacts = result['extracted_artifacts']
                print(f"\n📧 {result['source']}:")
                print(f"  Size: {result['size']:,} bytes")
                print(f"  Content blocks: {result['statistics']['content_blocks']}")
                print(f"  MIME types: {list(result['statistics']['mime_type_counts'].keys())}")
                print(f"  🔍 Artifacts: {artifacts['statistics']['total_urls']} URLs, {artifacts['statistics']['total_ips']} IPs, {artifacts['statistics']['total_domains']} domains")
                
                # Show binary format summary
                binary_found = []
                for block in result['content']:
                    if block['type'] in ['nested_msg', 'binary_msg']:
                        binary_found.append('MSG')
                    elif block['type'] in ['tnef_container', 'binary_tnef']:
                        binary_found.append('TNEF')
                
                if binary_found:
                    print(f"  Binary formats: {', '.join(set(binary_found))}")
            else:
                print(f"\n❌ {result['source']}: {result['error']}")
        
        if args.output is None:
            print(f"\n💡 Tip: Use -o filename.json to save full results to a file")
            print(f"💡 To parse binary formats, install: pip install extract_msg tnefparse")


if __name__ == "__main__":
    main()