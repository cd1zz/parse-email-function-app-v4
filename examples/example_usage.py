#!/usr/bin/env python3
"""
Example usage of the Phishing Email Parser.

This script demonstrates how to use the parser for different scenarios.
"""

import json
import logging
from pathlib import Path
from phishing_email_parser import PhishingEmailParser

# Configure detailed logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

def analyze_email_file(email_path: str, output_path: str = None):
    """Analyze a single email file."""
    print(f"Analyzing email: {email_path}")
    
    with PhishingEmailParser() as parser:
        try:
            # Parse the email
            result = parser.parse_email_file(email_path)
            
            # Print summary
            summary = result['summary']
            print("\n=== ANALYSIS SUMMARY ===")
            print(f"Total message layers: {summary['total_layers']}")
            print(f"Carrier emails detected: {len(summary['carrier_emails'])}")
            print(f"Total attachments: {summary['total_attachments']}")
            print(f"Total URLs found: {summary['total_urls']}")
            print(f"Has nested emails: {summary['has_nested_emails']}")
            
            # Show carrier details
            if summary['carrier_emails']:
                print("\n=== CARRIER EMAILS ===")
                for carrier in summary['carrier_emails']:
                    print(f"Layer {carrier['layer']}: {carrier['vendor']}")
            
            # Show layer details
            print("\n=== MESSAGE LAYERS ===")
            for layer in result['message_layers']:
                depth = layer['layer_depth']
                subject = layer['headers']['subject']
                sender = layer['headers']['from']
                print(f"Layer {depth}: {subject}")
                print(f"  From: {sender}")
                print(f"  Carrier: {layer['carrier_vendor'] if layer['is_carrier_email'] else 'No'}")
                print(f"  Attachments: {len(layer['attachments'])}")
                print(f"  URLs: {len(layer['urls'])}")
                
                # Show attachment details
                if layer['attachments']:
                    print("  Attachment details:")
                    for att in layer['attachments']:
                        print(f"    - {att['filename']} ({att['size']} bytes)")
                        if att.get('is_suspicious_extension'):
                            print(f"      ⚠️  SUSPICIOUS EXTENSION: {att['extension']}")
                        if att.get('text_content'):
                            preview = att['text_content'][:100].replace('\n', ' ')
                            print(f"      Text preview: {preview}...")
                
                # Show URL details
                if layer['urls']:
                    print("  URL details:")
                    for url in layer['urls']:
                        print(f"    - {url['original_url']}")
                        if url.get('is_shortened'):
                            expanded = url.get('expanded_url', 'Not expanded')
                            print(f"      Expanded: {expanded}")
                
                print()
            
            # Save to file if requested
            if output_path:
                with open(output_path, 'w', encoding='utf-8') as f:
                    json.dump(result, f, indent=2, ensure_ascii=False)
                print(f"Full results saved to: {output_path}")
            
            return result
            
        except Exception as e:
            print(f"Error analyzing email: {e}")
            raise

def batch_analyze_directory(directory_path: str, output_dir: str = None):
    """Analyze all email files in a directory."""
    directory = Path(directory_path)
    if not directory.exists():
        print(f"Directory not found: {directory}")
        return
    
    # Find all email files
    email_files = []
    for pattern in ['*.eml', '*.msg']:
        email_files.extend(directory.glob(pattern))
    
    if not email_files:
        print(f"No email files found in {directory}")
        return
    
    print(f"Found {len(email_files)} email files to analyze")
    
    # Set up output directory
    if output_dir:
        output_path = Path(output_dir)
        output_path.mkdir(exist_ok=True)
    
    results = {}
    
    for email_file in email_files:
        print(f"\n{'='*60}")
        try:
            output_file = None
            if output_dir:
                output_file = output_path / f"{email_file.stem}_analysis.json"
            
            result = analyze_email_file(str(email_file), str(output_file) if output_file else None)
            results[str(email_file)] = {
                'status': 'success',
                'summary': result['summary']
            }
            
        except Exception as e:
            print(f"Failed to analyze {email_file}: {e}")
            results[str(email_file)] = {
                'status': 'error',
                'error': str(e)
            }
    
    # Print batch summary
    print(f"\n{'='*60}")
    print("BATCH ANALYSIS SUMMARY")
    print(f"{'='*60}")
    
    successful = sum(1 for r in results.values() if r['status'] == 'success')
    failed = len(results) - successful
    
    print(f"Successfully analyzed: {successful}")
    print(f"Failed: {failed}")
    
    if successful > 0:
        total_layers = sum(r['summary']['total_layers'] for r in results.values() 
                          if r['status'] == 'success')
        total_carriers = sum(len(r['summary']['carrier_emails']) for r in results.values() 
                            if r['status'] == 'success')
        
        print(f"Total message layers: {total_layers}")
        print(f"Total carrier emails: {total_carriers}")

def demonstrate_api_usage():
    """Demonstrate programmatic API usage."""
    print("=== API Usage Demonstration ===")
    
    # This would work with an actual email file
    sample_email_path = "sample_phishing_email.eml"
    
    if Path(sample_email_path).exists():
        with PhishingEmailParser() as parser:
            result = parser.parse_email_file(sample_email_path)
            
            # Example: Check for carrier emails
            carriers = result['summary']['carrier_emails']
            if carriers:
                print(f"Detected {len(carriers)} carrier email(s)")
                for carrier in carriers:
                    print(f"  Layer {carrier['layer']}: {carrier['vendor']}")
            
            # Example: Extract all URLs across layers
            all_urls = []
            for layer in result['message_layers']:
                all_urls.extend(layer['urls'])
            
            print(f"Found {len(all_urls)} total URLs")
            
            # Example: Check for suspicious attachments
            suspicious_attachments = []
            for layer in result['message_layers']:
                for attachment in layer['attachments']:
                    if attachment.get('is_suspicious_extension'):
                        suspicious_attachments.append(attachment)
            
            if suspicious_attachments:
                print(f"⚠️  Found {len(suspicious_attachments)} suspicious attachments")
    else:
        print("No sample email file found for demonstration")

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage:")
        print(f"  {sys.argv[0]} <email_file> [output_file]")
        print(f"  {sys.argv[0]} --batch <directory> [output_directory]")
        print(f"  {sys.argv[0]} --demo")
        sys.exit(1)
    
    if sys.argv[1] == "--demo":
        demonstrate_api_usage()
    elif sys.argv[1] == "--batch":
        if len(sys.argv) < 3:
            print("Batch mode requires directory path")
            sys.exit(1)
        output_dir = sys.argv[3] if len(sys.argv) > 3 else None
        batch_analyze_directory(sys.argv[2], output_dir)
    else:
        email_file = sys.argv[1]
        output_file = sys.argv[2] if len(sys.argv) > 2 else None
        analyze_email_file(email_file, output_file)
