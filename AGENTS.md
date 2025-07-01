# AGENTS.md - Email Parser for Phishing Analysis

## Project Overview

This is an email parsing library designed specifically for **phishing email analysis** and **SOC (Security Operations Center) workflows**. The parser processes user-submitted emails to extract content and artifacts for LLM analysis, helping security analysts understand potential phishing campaigns.

**Primary Use Case**: Parse phishing emails submitted by users, extract all content (including nested emails and attachments), and prepare structured data for LLM-based threat analysis.

**Deployment Target**: Azure Function App (non-interactive, automated processing)

## Architecture Philosophy

### Core Design Principles

1. **Security-First Parsing**: Assume attackers will try to evade detection through mislabeling, encoding tricks, and complex nesting
2. **Comprehensive Artifact Extraction**: Extract URLs, IP addresses, and domains from ALL text content, including nested emails and attachments
3. **Carrier vs Payload Analysis**: Distinguish between the "carrier email" (delivery mechanism) and the actual phishing content (which may be in attachments or nested emails)
4. **Binary Format Detection**: Always check file signatures before trusting declared MIME types

### Key Architectural Decisions

**Binary Detection Before MIME Filtering**: The parser detects binary email formats (MSG, TNEF) by file signature BEFORE checking MIME types. This prevents evasion where attackers mislabel `.msg` files as `application/octet-stream` or other generic types.

**Shared Text Collection**: When parsing nested emails, all parsers share the same `all_text_content` list to ensure artifacts from deeply nested content are captured at the top level. This is critical for phishing emails that hide malicious URLs in attached emails.

**Depth-Limited Recursion**: Prevents infinite loops from maliciously crafted emails with excessive nesting.

## Module Responsibilities

### Core Parsing (`email_parser.py`)
- **Primary entry point**: `EmailParser.parse_file()` and `EmailParser.parse()`
- **Binary format detection**: Checks for MSG/TNEF signatures regardless of declared MIME type
- **Recursive parsing**: Handles nested emails and attachments
- **Text content aggregation**: Collects all text from headers, bodies, and attachments for artifact extraction

### Artifact Extraction
- **URL extraction**: Finds URLs in text, HTML attributes, and plain text with aggressive pattern matching
- **Domain/IP extraction**: Identifies domains and IP addresses with validation
- **URL expansion**: Expands shortened URLs (bit.ly, t.co, etc.) to reveal final destinations
- **Deduplication**: Removes duplicate artifacts while preserving important variations

### Binary Format Support
- **MSG files**: Uses `extract_msg` library to convert Outlook MSG files to RFC822 format
- **TNEF files**: Parses `winmail.dat` attachments using `tnefparse`
- **Signature detection**: Validates files by binary signatures, not just extensions

### HTML Processing (`html_cleaner.py`)
- **Aggressive cleaning**: Removes invisible characters, scripts, styles
- **Unicode normalization**: Handles problematic characters common in phishing emails
- **Text extraction**: Converts HTML to clean plain text while preserving URLs

## Common Development Tasks

### Adding New Binary Format Support

1. **Add signature detection** in `_detect_binary_email()`:
   ```python
   NEW_FORMAT_SIGNATURE = b"\x..."
   if buf.startswith(NEW_FORMAT_SIGNATURE):
       return "new_format"
   ```

2. **Add parser method** like `_parse_new_format_file()`:
   - Extract content using appropriate library
   - Convert to standard email format or extract text directly
   - Return structured block with `type: 'new_format'`

3. **Update `_walk_message()`** to handle the new format in both multipart and single-part sections

### Improving Nested Email Parsing

**Key Insight**: The "carrier email" vs "payload" distinction is crucial. The carrier is often legitimate (forwarded email, user submission) while the actual phishing content may be:
- Attached as `.msg` or `.eml` files
- Embedded as `message/rfc822` parts
- Hidden in TNEF containers

**Debugging Nested Parsing**:
1. Check `debug_email_structure()` output for boundary and Content-Type analysis
2. Verify `all_text_content` collection includes text from all nesting levels
3. Ensure artifact extraction processes content from nested parsers

### Handling Phishing Evasion Techniques

**Common Evasion Methods**:
- **Mislabeled attachments**: MSG files labeled as `application/octet-stream`
- **Unicode tricks**: Invisible characters, homograph attacks
- **URL obfuscation**: Multiple redirects, encoded parameters
- **Nested complexity**: Multiple levels of forwarding and attachments

**Parser Countermeasures**:
- Binary signature detection (already implemented)
- Aggressive HTML cleaning with Unicode normalization
- URL expansion for shortened links
- Deep recursion with shared text collection

## Testing Strategy

### Test Email Collection
The project uses a collection of real phishing email samples for testing. When adding new features:

1. **Test against known samples**: Ensure existing functionality isn't broken
2. **Add edge cases**: Test new binary formats, encoding issues, extreme nesting
3. **Validate artifact extraction**: Verify URLs, IPs, and domains are correctly extracted from new formats

### Debugging Workflow

When emails don't parse correctly:

1. **Run debug analysis**: Use `debug_email_structure()` to understand email structure
2. **Check logs**: Enable debug logging to trace parsing decisions
3. **Inspect text collection**: Verify `all_text_content` contains expected content
4. **Test artifact extraction**: Confirm URLs/IPs/domains are found in text blocks

## Performance Considerations

**Azure Function App Requirements**:
- **Memory efficiency**: Limit image inclusion, use streaming for large attachments
- **Timeout handling**: Complex nested emails may require processing time limits
- **Error resilience**: Individual parsing failures shouldn't crash entire pipeline

**Resource Management**:
- Images are skipped by default unless explicitly requested
- Large attachments are summarized rather than fully included
- Temporary files (for MSG processing) are properly cleaned up

## Security Considerations

**Malicious Content Handling**:
- **No code execution**: Parser only extracts content, never executes embedded scripts/macros
- **Sandbox assumptions**: Assume all input is potentially malicious
- **Resource limits**: Prevent DoS through excessive recursion or memory usage

**Data Sensitivity**:
- **PII awareness**: Email content may contain sensitive information
- **Artifact sanitization**: URLs and IPs are collected for analysis but should be handled securely

## Extension Points

### Adding New Artifact Types
To add new artifact extraction (phone numbers, crypto addresses, etc.):

1. **Add pattern in `EmailParser`**: Define regex pattern for new artifact type
2. **Update `_extract_artifacts_from_text()`**: Add extraction logic
3. **Modify `_extract_all_artifacts()`**: Include in deduplication and statistics
4. **Update output structure**: Add new artifact type to results

### Improving URL Processing
The URL processing pipeline (`url/` package) can be extended for:
- **New URL shorteners**: Add domains to `URL_SHORTENER_PROVIDERS`
- **Additional URL wrappers**: Extend `UrlDecoder` for new security products
- **Enhanced validation**: Improve domain validation and suspicious URL detection

## Common Gotchas

### Text Collection Issues
- **Shared state**: `parent_text_content` is shared across nested parsers - exceptions during parsing could leave inconsistent state
- **Memory growth**: Deep nesting with large text content can consume significant memory
- **Encoding problems**: Mixed encodings in nested emails may cause text corruption

### Binary Format Edge Cases
- **Corrupted files**: Partial or corrupted MSG/TNEF files may cause parser exceptions
- **Unknown signatures**: New binary formats won't be detected until signatures are added
- **Library limitations**: `extract_msg` and `tnefparse` have their own parsing limitations

### Artifact Extraction Challenges
- **False positives**: Aggressive URL extraction may capture non-URLs
- **Encoding issues**: URLs with special characters may not extract correctly
- **Nested context loss**: Artifacts from deeply nested content may lose source context

## Dependencies & Their Purposes

- **`extract_msg`**: Parse Microsoft Outlook MSG files
- **`tnefparse`**: Handle Microsoft TNEF (winmail.dat) attachments
- **`beautifulsoup4`**: Clean HTML content and extract text
- **`chardet`**: Detect character encodings in email content
- **`tldextract`**: Validate domain names and extract TLDs
- **`requests`**: Expand shortened URLs by following redirects
- **`pdfminer`**: Extract text content from PDF attachments

## AI Assistant Guidelines

When helping with this codebase:

1. **Understand the security context**: This is for phishing analysis - assume malicious intent in input
2. **Preserve parsing robustness**: Don't suggest changes that could break parsing of existing email formats
3. **Maintain artifact extraction**: Ensure changes don't prevent URL/IP/domain extraction from nested content
4. **Follow SOLID principles**: Respect the user's preference for clean, maintainable code
5. **Ask about existing libraries**: Before implementing new functionality, check if a library already exists
6. **Test suggestions**: Consider how changes would work with complex, nested phishing emails