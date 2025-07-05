# Phishing Email Parser

A comprehensive Python package for parsing and analyzing phishing emails, designed to extract structured data for LLM analysis and security research.

## Features

### 🔍 **Email Analysis**
- Parse both `.eml` and `.msg` email files
- Detect carrier emails from security appliances (Proofpoint, Mimecast, Microsoft 365 Defender, etc.)
- Recursively parse nested email structures with unlimited depth
- Extract and clean email headers, removing null terminators and control characters

### 📎 **Attachment Processing**
- Extract and analyze all attachment types
- Detect nested emails embedded as attachments
- Extract text content from PDFs, Office documents, and other formats
- Generate SHA256 hashes and metadata for all attachments
- Flag suspicious file extensions

### 🖼️ **Image Analysis**
- Extract embedded images from emails
- Perform OCR (Optical Character Recognition) on images
- Extract URLs and text from image content
- Support for multiple image formats

### 📊 **Enhanced Excel Processing**
- Extract text content from spreadsheet cells, formulas, and comments
- **NEW**: Extract and OCR embedded images within Excel files
- **NEW**: Detect hyperlinks associated with embedded images
- Identify VBA macros and suspicious code execution
- Extract URLs from cell content, formulas, and embedded images
- Support for both `.xlsx` and `.xls` formats with multiple parsing engines

#### Excel Image Processing
The parser now extracts and analyzes images embedded within Excel files:

```python
from phishing_email_parser.processing.excel_utils import extract_excel_with_images

# Extract both text and images from Excel file
text_content, images = extract_excel_with_images(excel_data, output_directory)

# Each image contains:
# - OCR text content
# - URLs found in the image
# - Hyperlinks associated with the image
# - Image metadata and disk location
```

Example Output Structure (Enhanced)

```json
{
  "attachments": [
    {
      "filename": "malicious.xlsx",
      "content_type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
      "text_content": "Extracted spreadsheet text...",
      "embedded_images": [
        {
          "filename": "xlsx_image_0_image1.png",
          "ocr_text": "Click here to verify your account",
          "urls_from_ocr": ["https://malicious-site.com"],
          "hyperlinks": ["https://phishing-redirect.com"],
          "size": 15420,
          "content_type": "image/png"
        }
      ],
      "urls": ["https://malicious-site.com", "https://phishing-redirect.com"]
    }
  ],
  "summary": {
    "total_images": 1,
    "total_embedded_images": 1
  }
}
```

### 🔗 **URL Processing**
- Extract URLs from email body, attachments, and OCR text
- Decode wrapped URLs (Microsoft SafeLinks, Proofpoint URL Defense)
- Identify and expand shortened URLs
- Deduplicate and validate URLs
- Skip image URLs to focus on actionable links

### 🧹 **Content Cleaning**
- Convert HTML to clean plain text using html2text
- Remove invisible Unicode characters and control sequences
- Normalize whitespace and handle problematic encodings
- Preserve URL structure while cleaning content

### 📊 **Structured Output**
- Generate comprehensive JSON output for each email layer
- Track analysis metadata and processing statistics
- Support for nested email hierarchies
- Designed for LLM consumption and analysis

## Installation

### Prerequisites

**System Dependencies:**
```bash
# Ubuntu/Debian
sudo apt-get update
sudo apt-get install tesseract-ocr tesseract-ocr-eng

# macOS (using Homebrew)
brew install tesseract

# Windows
# Download from: https://github.com/UB-Mannheim/tesseract/wiki
```

**Python Requirements:**
- Python 3.8+
- pip

### Install the Package

```bash
# Clone the repository
git clone <repository-url>
cd phishing_email_parser

# Install dependencies
pip install -r requirements.txt

# Install the package in development mode
pip install -e .
```

### Required Python Packages

```bash
pip install html2text beautifulsoup4 pillow pytesseract extract-msg pdfminer.three requests
```

## Usage

### Command Line Interface

```bash
# Parse an email file and output to stdout
python -m phishing_email_parser email_sample.eml

# Parse and save to JSON file
python -m phishing_email_parser email_sample.eml output.json

# Parse MSG files (automatically converted)
python -m phishing_email_parser email_sample.msg analysis.json
```

### Python API

```python
from phishing_email_parser import PhishingEmailParser

# Use as context manager for automatic cleanup
with PhishingEmailParser() as parser:
    result = parser.parse_email_file("phishing_email.eml")
    
    # Access parsed data
    print(f"Found {result['summary']['total_layers']} email layers")
    print(f"Extracted {result['summary']['total_urls']} URLs")
    print(f"Found {result['summary']['total_attachments']} attachments")
    
    # Process each layer
    for layer in result['message_layers']:
        if layer['is_carrier_email']:
            print(f"Carrier email detected: {layer['carrier_vendor']}")
        
        # Access cleaned email content
        body_text = layer['body']['final_text']
        urls = layer['urls']
        attachments = layer['attachments']

# Custom configuration example
from phishing_email_parser import ParserConfig

config = ParserConfig(
    suspicious_extensions=(".exe", ".zip"),
)
with PhishingEmailParser(config=config) as parser:
    parser.parse_email_file("phishing.eml")
```

### Core Components Usage

```python
# Detect carrier emails
from phishing_email_parser.core.carrier_detector import is_carrier
from email import message_from_file

with open('email.eml', 'r') as f:
    msg = message_from_file(f)
    
is_carrier_email, vendor = is_carrier(msg)
if is_carrier_email:
    print(f"Detected {vendor} carrier email")

# Clean HTML content
from phishing_email_parser.core.html_cleaner import PhishingEmailHtmlCleaner

html_content = "<p>Hello <b>world</b>!</p>"
clean_text = PhishingEmailHtmlCleaner.clean_html(html_content)
print(clean_text)  # "Hello world!"

# Process URLs
from phishing_email_parser.url_processing.processor import UrlProcessor

urls = ["https://bit.ly/example", "https://example.com"]
processed = UrlProcessor.process_urls(urls)
expanded = UrlProcessor.batch_expand_urls(processed)
```

## Output Format

The parser generates structured JSON with the following format:

```json
{
  "parser_info": {
    "version": "1.0",
    "purpose": "phishing_email_analysis"
  },
  "message_layers": [
    {
      "layer_depth": 0,
      "is_carrier_email": false,
      "carrier_vendor": null,
      "headers": {
        "subject": "Important Security Update",
        "from": "security@example.com",
        "to": "user@company.com",
        "date": "2024-01-15 10:30:00",
        "x_headers": {}
      },
      "body": {
        "plain_text": "",
        "html_text": "<html>...</html>",
        "converted_text": "Clean text version",
        "final_text": "Clean text version",
        "has_html": true,
        "has_plain": false
      },
      "attachments": [
        {
          "index": 1,
          "filename": "document.pdf",
          "content_type": "application/pdf",
          "size": 12345,
          "sha256": "abc123...",
          "disk_path": "/tmp/document.pdf",
          "text_content": "Extracted PDF text",
          "is_nested_email": false
        }
      ],
      "images": [
        {
          "index": 1,
          "filename": "image.png",
          "content_type": "image/png",
          "ocr_text": "Text found in image",
          "size": 5678
        }
      ],
      "urls": [
        {
          "original_url": "https://malicious-site.com",
          "is_shortened": false,
          "expanded_url": "Not Applicable"
        }
      ]
    }
  ],
  "summary": {
    "total_layers": 1,
    "carrier_emails": [],
    "total_attachments": 1,
    "total_images": 1,
    "total_urls": 1,
    "has_nested_emails": false
  }
}
```

## Architecture

### Core Design Principles

- **SOLID Principles**: Follows Single Responsibility, Open/Closed, Liskov Substitution, Interface Segregation, and Dependency Inversion
- **KISS & YAGNI**: Keep It Simple Stupid and You Aren't Gonna Need It
- **Production Ready**: Comprehensive error handling, logging, and cleanup
- **Modular Design**: Separate concerns across focused modules

### Package Structure

```
phishing_email_parser/
├── __init__.py              # Package initialization
├── __main__.py              # CLI entry point
├── main_parser.py           # Main parser class and logic
├── core/                    # Core email processing
│   ├── carrier_detector.py  # Security appliance detection
│   ├── html_cleaner.py      # HTML to text conversion
│   └── mime_walker.py       # MIME structure traversal
├── processing/              # Email format processing
│   ├── attachment_processor.py  # Attachment extraction/analysis
│   ├── msg_converter.py     # MSG to EML conversion
│   └── pdf_utils.py         # PDF text extraction
└── url_processing/          # URL handling
    ├── processor.py         # Main URL processing
    ├── decoder.py           # Wrapped URL decoding
    └── validator.py         # URL validation/cleaning
```

### Key Classes

- **`PhishingEmailParser`**: Main parser with context manager support
- **`PhishingEmailHtmlCleaner`**: HTML cleaning and text extraction
- **`AttachmentProcessor`**: Attachment handling and text extraction
- **`MSGConverter`**: Microsoft Outlook MSG file conversion
- **`UrlProcessor`**: URL extraction, expansion, and deduplication
- **`ParserConfig`**: Optional configuration object to customise parser behaviour

## Security Considerations

### Safe Processing
- All file operations use temporary directories with automatic cleanup
- Malicious content is isolated and processed safely
- No execution of embedded scripts or executables
- OCR and text extraction only, no code execution

### Data Handling
- Sensitive data is processed locally (no external API calls for parsing)
- Temporary files are securely cleaned up
- URL expansion can be disabled for air-gapped environments
- Hash generation for attachment verification

## Advanced Features

### Nested Email Detection
The parser automatically detects and processes:
- MIME `message/rfc822` parts (handled by MIME walker)
- Email attachments with `.eml` extensions
- Base64-encoded emails embedded in message bodies
- MIME-structured content within HTML bodies

### Carrier Email Detection
Recognizes emails from security appliances:
- **Proofpoint**: Subject/header patterns, X-Proofpoint headers
- **Mimecast**: Subject patterns, X-MC headers
- **Microsoft 365**: Quarantine notifications, X-Microsoft-Antispam
- **Cisco IronPort**: ESA patterns, X-IronPort headers

### URL Processing Pipeline
1. **Extraction**: From email body, HTML, attachments, and OCR text
2. **Decoding**: Unwrap Microsoft SafeLinks and Proofpoint URLs
3. **Validation**: Clean and normalize URL format
4. **Deduplication**: Remove duplicates while preserving context
5. **Expansion**: Follow redirects for shortened URLs (optional)

## Development

### Code Quality Standards
- All code must pass linting with zero issues
- Comprehensive error handling and logging
- Type hints and docstrings for all public methods
- No forbidden patterns (see AGENTS.md)

### Testing
```bash
# Run all tests
python -m pytest

# Run with coverage
python -m pytest --cov=phishing_email_parser
```

### Contributing
1. Follow the development workflow in `AGENTS.md`
2. Research → Plan → Implement
3. All hooks must pass before commit
4. Maintain backward compatibility for public APIs

## Troubleshooting

### Common Issues

**Tesseract not found:**
```bash
# Ensure Tesseract is installed and in PATH
tesseract --version

# Set custom path if needed
export TESSDATA_PREFIX=/usr/share/tesseract-ocr/
```

**MSG file conversion errors:**
```bash
# Install extract-msg if missing
pip install extract-msg

# Check file permissions and corruption
file suspicious.msg
```

**Memory issues with large emails:**
- Large emails are processed in chunks
- Temporary files are cleaned automatically
- Consider increasing available memory for very large attachments

**URL expansion timeouts:**
- Network-dependent feature with configurable timeouts
- Can be disabled for air-gapped environments
- Implements retry logic for transient failures

## License

[Add your license information here]

## Support

For issues and questions:
1. Check the troubleshooting section above
2. Review the code documentation in each module
3. File an issue with sample data (sanitized) and error logs

## Changelog

### Version 1.0.0
- Initial release with comprehensive email parsing
- Support for .eml and .msg files
- Nested email detection and processing
- URL extraction and processing
- OCR capabilities for images
- Carrier email detection