#!/usr/bin/env python3
import json
import argparse
import logging
import importlib.util
import sys

def main():
    parser = argparse.ArgumentParser(description='Email Content Parser (Standard Library + Binary Support + Artifact Extraction)')
    parser.add_argument('files', nargs='+', help='Email files to parse')
    parser.add_argument('-o', '--output', help='Output JSON file')
    parser.add_argument('--compact', action='store_true', help='Compact JSON output')
    parser.add_argument('--max-depth', type=int, default=10, help='Maximum recursion depth (default: 10)')
    parser.add_argument('--include-raw', action='store_true',
                       help='Include raw base64 content for forensic analysis')
    parser.add_argument('--include-images', action='store_true',
                       help='Extract image content (otherwise only metadata is kept)')
    parser.add_argument('--include-large-images', action='store_true',
                       help='Include large images in output (may create very large files)')
    parser.add_argument('--forensics_mode', action='store_true',
                       help='Preserve full content details for forensics')
    parser.add_argument('--log-file', help='Write debug log to specified file')
    parser.add_argument('--debug', action='store_true', help='Enable debug logging')

    args = parser.parse_args()

    log_level = logging.DEBUG if args.debug else logging.INFO
    logging.basicConfig(
        level=log_level,
        filename=args.log_file,
        format='%(asctime)s %(levelname)s %(name)s: %(message)s'
    )

    # Ensure required dependencies are available
    required = ['extract_msg', 'tnefparse', 'chardet', 'tldextract', 'requests']
    missing = [m for m in required if importlib.util.find_spec(m) is None]
    if missing:
        print('Missing required dependencies: ' + ', '.join(missing), file=sys.stderr)
        print('Please install the missing packages and try again.', file=sys.stderr)
        sys.exit(1)

    from .email_parser import EmailParser
    
    # Parse all files
    results = []
    email_parser = EmailParser(
        max_depth=args.max_depth,
        include_raw=args.include_raw,
        include_images=args.include_images,
        include_large_images=args.include_large_images
    )
    
    for file_path in args.files:
        try:
            print(f"\n📧 Parsing: {file_path}")
            print("=" * 60)
            
            result = email_parser.parse_file(file_path, forensics_mode=args.forensics_mode)
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
                    sample_urls = [u['original_url'] for u in artifacts['urls'][:3] if isinstance(u, dict)]
                    print(f"    Sample URLs: {', '.join(sample_urls)}")
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
                logging.error(f"Error parsing {file_path}: {result['error']}")
                
        except Exception as e:
            print(f"✗ Error parsing {file_path}: {e}")
            logging.exception("Unhandled exception while parsing file")
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


if __name__ == "__main__":
    main()

