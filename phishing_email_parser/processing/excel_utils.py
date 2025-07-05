"""
Excel text extraction utilities for phishing email analysis.

Extracts text content, VBA macros, URLs, formulas, embedded images with OCR,
and other metadata from Excel files (.xlsx and .xls) with multiple fallback methods.
"""

import io
import logging
import re
import traceback
import zipfile
from pathlib import Path
from xml.etree import ElementTree as ET
from typing import Dict, List, Optional, Tuple

# Import for OCR functionality
try:
    import pytesseract
    from PIL import Image
    OCR_AVAILABLE = True
except ImportError:
    OCR_AVAILABLE = False
    pytesseract = None
    Image = None

logger = logging.getLogger(__name__)


class ExcelImageExtractor:
    """Handles extraction and OCR of images embedded in Excel files."""
    
    def __init__(self, output_dir: str):
        """Initialize with output directory for extracted images."""
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
    
    def extract_images_from_xlsx(self, excel_data: bytes) -> List[Dict]:
        """Extract and OCR images embedded in XLSX files."""
        if not OCR_AVAILABLE:
            logger.warning("OCR libraries not available - cannot extract images from Excel")
            return []
        
        images_found = []
        
        try:
            excel_bytes = io.BytesIO(excel_data)
            with zipfile.ZipFile(excel_bytes, 'r') as z:
                # Look for images in the media folder
                image_files = [f for f in z.namelist() if f.startswith('xl/media/')]
                logger.debug(f"Found {len(image_files)} images in XLSX: {image_files}")
                
                for idx, image_file in enumerate(image_files):
                    try:
                        image_info = self._process_xlsx_image(z, image_file, idx)
                        if image_info:
                            images_found.append(image_info)
                    except Exception as e:
                        logger.error(f"Error processing XLSX image {image_file}: {e}")
                        
        except zipfile.BadZipFile:
            logger.debug("Not a valid XLSX file for image extraction")
        except Exception as e:
            logger.error(f"Error extracting images from XLSX: {e}")
        
        logger.info(f"Extracted {len(images_found)} images from Excel file")
        return images_found
    
    def _process_xlsx_image(self, zip_file: zipfile.ZipFile, image_path: str, index: int) -> Optional[Dict]:
        """Process a single image from XLSX file."""
        try:
            # Extract image data
            image_data = zip_file.read(image_path)
            filename = f"xlsx_image_{index}_{Path(image_path).name}"
            
            # Save image to disk
            disk_path = self.output_dir / filename
            with disk_path.open('wb') as f:
                f.write(image_data)
            
            logger.debug(f"Extracted XLSX image: {filename} ({len(image_data)} bytes)")
            
            # Perform OCR
            ocr_text = self._ocr_image(image_data, filename)
            
            # Extract URLs from OCR text
            urls_from_ocr = self._extract_urls_from_text(ocr_text) if ocr_text else []
            
            # Find hyperlinks associated with this image
            image_hyperlinks = self._find_image_hyperlinks(zip_file, image_path)
            
            return {
                "index": index,
                "filename": filename,
                "source_path": image_path,
                "disk_path": str(disk_path),
                "size": len(image_data),
                "ocr_text": ocr_text,
                "hyperlinks": image_hyperlinks,
                "urls_from_ocr": urls_from_ocr,
                "content_type": self._guess_image_type(image_path),
                "is_excel_embedded": True
            }
            
        except Exception as e:
            logger.error(f"Error processing XLSX image {image_path}: {e}")
            return None
    
    def _ocr_image(self, image_data: bytes, filename: str) -> Optional[str]:
        """Perform OCR on image data."""
        if not OCR_AVAILABLE:
            return None
        
        try:
            img = Image.open(io.BytesIO(image_data))
            
            # Convert to grayscale for better OCR
            if img.mode != 'L':
                img = img.convert('L')
            
            # Perform OCR
            ocr_text = pytesseract.image_to_string(img, config='--psm 6')
            
            if ocr_text and ocr_text.strip():
                cleaned_text = ocr_text.strip()
                logger.debug(f"OCR extracted {len(cleaned_text)} characters from {filename}")
                return cleaned_text
            
        except Exception as e:
            logger.warning(f"OCR failed for {filename}: {e}")
        
        return None
    
    def _find_image_hyperlinks(self, zip_file: zipfile.ZipFile, image_path: str) -> List[str]:
        """Find hyperlinks associated with images in XLSX drawings."""
        hyperlinks = []
        
        try:
            # Check drawing relationship files
            drawing_rels = [f for f in zip_file.namelist() 
                           if 'drawings/_rels/' in f and f.endswith('.rels')]
            
            for rel_file in drawing_rels:
                try:
                    content = zip_file.read(rel_file).decode('utf-8', errors='ignore')
                    root = ET.fromstring(content)
                    
                    ns = {'r': 'http://schemas.openxmlformats.org/package/2006/relationships'}
                    for relationship in root.findall('.//r:Relationship', ns):
                        rel_type = relationship.get('Type', '')
                        target = relationship.get('Target', '')
                        
                        if 'hyperlink' in rel_type.lower() and target:
                            # Filter out Microsoft/Office internal links
                            if not any(domain in target.lower() for domain in [
                                'microsoft.com', 'live.com', 'office.com', 'purl.org',
                                'microsoftonline.com', 'openxmlformats.org', 'w3.org'
                            ]):
                                hyperlinks.append(target)
                                logger.debug(f"Found image hyperlink: {target}")
                                
                except ET.ParseError as e:
                    logger.debug(f"Could not parse drawing relationship {rel_file}: {e}")
                except Exception as e:
                    logger.debug(f"Error processing drawing relationship {rel_file}: {e}")
                    
        except Exception as e:
            logger.debug(f"Error finding image hyperlinks: {e}")
        
        return list(set(hyperlinks))  # Remove duplicates
    
    def _extract_urls_from_text(self, text: str) -> List[str]:
        """Extract URLs from text content."""
        if not text:
            return []
        
        # Pattern to match URLs
        url_pattern = re.compile(
            r'https?://[^\s<>"{}|\\^`\[\]]+|www\.[^\s<>"{}|\\^`\[\]]+',
            re.IGNORECASE
        )
        
        urls = url_pattern.findall(text)
        # Clean up URLs (remove trailing punctuation)
        cleaned_urls = []
        for url in urls:
            cleaned = url.rstrip('.,;:!?)]}')
            if cleaned:
                cleaned_urls.append(cleaned)
        
        return list(set(cleaned_urls))  # Remove duplicates
    
    def _guess_image_type(self, image_path: str) -> str:
        """Guess image content type from file extension."""
        extension = Path(image_path).suffix.lower()
        type_map = {
            '.png': 'image/png',
            '.jpg': 'image/jpeg',
            '.jpeg': 'image/jpeg',
            '.gif': 'image/gif',
            '.bmp': 'image/bmp',
            '.tiff': 'image/tiff',
            '.webp': 'image/webp'
        }
        return type_map.get(extension, 'image/unknown')


def extract_text_from_excel(excel_data: bytes, output_dir: Optional[str] = None) -> str:
    """
    Extract text content from Excel binary data using multiple methods.
    Now includes OCR of embedded images.
    
    Args:
        excel_data: The binary content of the Excel file
        output_dir: Optional directory to save extracted images
        
    Returns:
        Extracted text from the Excel file including content, metadata, and OCR text
    """
    if not excel_data:
        return "[Empty Excel file]"
        
    try:
        logger.debug(f"Extracting text from Excel file ({len(excel_data)} bytes)")
        
        # Create a file-like object from the binary data
        excel_file = io.BytesIO(excel_data)
        
        # Try pandas first for simple structured data extraction
        text_result = _extract_text_content(excel_file)
        
        # If we have an output directory, also extract images
        images_result = ""
        if output_dir:
            try:
                image_extractor = ExcelImageExtractor(output_dir)
                images = image_extractor.extract_images_from_xlsx(excel_data)
                
                if images:
                    images_result = _format_image_results(images)
                    
            except Exception as img_err:
                logger.warning(f"Could not extract images from Excel: {img_err}")
        
        # Get deep metadata extraction
        metadata_result = ""
        try:
            excel_file.seek(0)
            metadata_result = _extract_excel_metadata(excel_data)
        except Exception as meta_err:
            logger.debug(f"Could not extract metadata: {meta_err}")
        
        # Combine all results
        final_result = text_result
        if images_result:
            final_result += f"\n\n{images_result}"
        if metadata_result:
            final_result += f"\n\n{metadata_result}"
        
        return final_result
        
    except Exception as e:
        logger.error(f"Error extracting text from Excel: {e}")
        logger.debug(traceback.format_exc())
        return f"[Error extracting Excel text: {e}]"


def extract_excel_with_images(excel_data: bytes, output_dir: str) -> Tuple[str, List[Dict]]:
    """
    Extract both text content and images from Excel file.
    
    Args:
        excel_data: The binary content of the Excel file
        output_dir: Directory to save extracted images
        
    Returns:
        Tuple of (text_content, list_of_image_info_dicts)
    """
    text_content = extract_text_from_excel(excel_data, output_dir)
    
    # Extract images separately for detailed processing
    images = []
    try:
        image_extractor = ExcelImageExtractor(output_dir)
        images = image_extractor.extract_images_from_xlsx(excel_data)
    except Exception as e:
        logger.error(f"Error extracting images from Excel: {e}")
    
    return text_content, images


def _extract_text_content(excel_file: io.BytesIO) -> str:
    """Extract text content using existing methods."""
    # Try pandas first for simple structured data extraction
    try:
        import pandas as pd
        
        # Try reading with pandas - handles xls and xlsx
        dfs = pd.read_excel(excel_file, sheet_name=None, engine=None)
        
        # Concatenate all sheets into a text representation
        text_content = []
        for sheet_name, df in dfs.items():
            if not df.empty:
                text_content.append(f"=== Sheet: {sheet_name} ===")
                # Convert to string and remove NaN values
                df_text = df.fillna('').to_string(index=False)
                text_content.append(df_text)
                text_content.append("")
        
        if text_content:
            result = "\n".join(text_content).strip()
            logger.debug(f"Successfully extracted Excel text using pandas, {len(result)} characters")
            return result
        else:
            logger.debug("Pandas extracted empty content, trying deep extraction")
            
    except ImportError:
        logger.debug("Pandas not available, trying alternative methods")
    except Exception as pandas_err:
        logger.debug(f"Pandas Excel reading failed: {pandas_err}, trying deep extraction")
    
    # Reset file position for next attempt
    excel_file.seek(0)
    
    # Try deep extraction for XLSX files
    try:
        result = _extract_excel_deep(excel_file.getvalue())
        if result and result != "[No text content found in Excel file]":
            logger.debug(f"Successfully extracted Excel text using deep extraction, {len(result)} characters")
            return result
    except Exception as deep_err:
        logger.debug(f"Deep Excel extraction failed: {deep_err}, trying openpyxl")
    
    # Reset file position
    excel_file.seek(0)
    
    # Try using openpyxl as a fallback
    try:
        import openpyxl
        
        workbook = openpyxl.load_workbook(excel_file, data_only=True)
        text_content = []
        
        for sheet in workbook.worksheets:
            text_content.append(f"=== Sheet: {sheet.title} ===")
            
            for row in sheet.iter_rows():
                row_values = []
                for cell in row:
                    if cell.value is not None:
                        row_values.append(str(cell.value))
                    else:
                        row_values.append("")
                
                # Only add non-empty rows
                if any(val.strip() for val in row_values):
                    text_content.append("\t".join(row_values))
            
            text_content.append("")
        
        if text_content:
            result = "\n".join(text_content).strip()
            logger.debug(f"Successfully extracted Excel text using openpyxl, {len(result)} characters")
            return result
            
    except ImportError:
        logger.debug("Openpyxl not available, trying xlrd")
    except Exception as openpyxl_err:
        logger.debug(f"Openpyxl Excel reading failed: {openpyxl_err}, trying xlrd")
    
    # Reset file position
    excel_file.seek(0)
    
    # Try xlrd as a last resort for xls files
    try:
        import xlrd
        
        workbook = xlrd.open_workbook(file_contents=excel_file.getvalue())
        text_content = []
        
        for sheet_idx in range(workbook.nsheets):
            sheet = workbook.sheet_by_index(sheet_idx)
            text_content.append(f"=== Sheet: {sheet.name} ===")
            
            for row_idx in range(sheet.nrows):
                row_values = []
                for cell in sheet.row(row_idx):
                    if cell.value:
                        row_values.append(str(cell.value))
                    else:
                        row_values.append("")
                
                # Only add non-empty rows
                if any(val.strip() for val in row_values):
                    text_content.append("\t".join(row_values))
            
            text_content.append("")
        
        if text_content:
            result = "\n".join(text_content).strip()
            logger.debug(f"Successfully extracted Excel text using xlrd, {len(result)} characters")
            return result
            
    except ImportError:
        logger.warning("No Excel processing libraries available (pandas, openpyxl, xlrd)")
        return "[Error: No Excel processing libraries available. Install pandas, openpyxl, or xlrd]"
    except Exception as xlrd_err:
        logger.warning(f"All Excel reading methods failed. Last error: {xlrd_err}")
        return f"[Error: Could not extract Excel text - {xlrd_err}]"
    
    # If we get here, no method worked
    return "[Error: Could not extract text from Excel file using any available method]"


def _format_image_results(images: List[Dict]) -> str:
    """Format image extraction results for text output."""
    if not images:
        return ""
    
    result_parts = [f"=== EMBEDDED IMAGES ({len(images)} found) ==="]
    
    for img in images:
        result_parts.append(f"Image: {img['filename']}")
        result_parts.append(f"  Size: {img['size']} bytes")
        result_parts.append(f"  Type: {img['content_type']}")
        
        if img.get('ocr_text'):
            result_parts.append(f"  OCR Text: {img['ocr_text'][:200]}...")
        
        if img.get('urls_from_ocr'):
            result_parts.append(f"  URLs in Image: {', '.join(img['urls_from_ocr'])}")
        
        if img.get('hyperlinks'):
            result_parts.append(f"  Image Hyperlinks: {', '.join(img['hyperlinks'])}")
        
        result_parts.append("")
    
    return "\n".join(result_parts)


def _extract_excel_metadata(excel_data: bytes) -> str:
    """
    Extract security-relevant metadata from Excel files.
    
    Returns metadata like VBA macros, URLs, formulas, etc.
    """
    try:
        return _extract_excel_deep(excel_data)
    except Exception as e:
        logger.debug(f"Could not extract Excel metadata: {e}")
        return ""


def _extract_excel_deep(excel_data: bytes) -> str:
    """
    Extract detailed information from Excel files including text, URLs, VBA code, etc.
    
    Args:
        excel_data: The binary content of the Excel file
        
    Returns:
        Extracted text content and security-relevant metadata
    """
    excel_bytes = io.BytesIO(excel_data)
    extracted_text = []
    metadata = []

    try:
        logger.debug("Performing deep extraction from Excel file")
        
        with zipfile.ZipFile(excel_bytes, 'r') as z:
            # Process VBA code if present (IMPORTANT for phishing analysis)
            if 'xl/vbaProject.bin' in z.namelist():
                try:
                    vba_binary = z.read('xl/vbaProject.bin')
                    # Look for VBA code segments
                    modules = re.findall(
                        b'Attribute VB_Name = "([^"]+)".*?(?=Attribute VB_Name|$)', 
                        vba_binary, 
                        re.DOTALL
                    )
                    
                    if modules:
                        metadata.append("=== VBA CODE DETECTED ===")
                        metadata.append("WARNING: This Excel file contains VBA macros")
                    
                    for i, module in enumerate(modules):
                        try:
                            decoded_content = module.decode('utf-8', errors='ignore')
                            cleaned_content = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f]', '', decoded_content)
                            if cleaned_content.strip():
                                metadata.append(f"--- VBA Module {i} ---")
                                metadata.append(cleaned_content.strip())
                        except Exception as e:
                            logger.debug(f"Could not decode VBA module {i}: {e}")
                            
                except Exception as e:
                    logger.debug(f"Error processing VBA project: {e}")

            # Process relationship files for hyperlinks
            hyperlinks = set()
            for filename in z.namelist():
                if filename.endswith('.rels'):
                    try:
                        content = z.read(filename).decode('utf-8', errors='ignore')
                        root = ET.fromstring(content)
                        
                        ns = {'r': 'http://schemas.openxmlformats.org/package/2006/relationships'}
                        for relationship in root.findall('.//r:Relationship', ns):
                            rel_type = relationship.get('Type', '')
                            target = relationship.get('Target', '')
                            
                            if 'hyperlink' in rel_type.lower() and target:
                                # Filter out Microsoft/Office internal links
                                if not any(domain in target.lower() for domain in [
                                    'microsoft.com', 'live.com', 'office.com', 'purl.org',
                                    'microsoftonline.com', 'openxmlformats.org', 'w3.org'
                                ]):
                                    hyperlinks.add(target)
                                    
                    except ET.ParseError as e:
                        logger.debug(f"Could not parse relationships in {filename}: {e}")
                    except Exception as e:
                        logger.debug(f"Error processing relationships in {filename}: {e}")
            
            if hyperlinks:
                metadata.append("=== HYPERLINKS ===")
                metadata.extend(sorted(hyperlinks))
            
            # Process XML files for content
            urls = set()
            formulas = []
            comments = []
            
            for filename in z.namelist():
                if filename.endswith('.xml'):
                    try:
                        content = z.read(filename).decode('utf-8', errors='ignore')
                        root = ET.fromstring(content)
                        
                        # Extract text content from cells
                        for elem in root.iter():
                            if elem.text and elem.text.strip():
                                text = elem.text.strip()
                                # Only add substantial text content
                                if len(text) > 2 and not text.isdigit():
                                    extracted_text.append(text)
                        
                        # Extract URLs from XML content
                        found_urls = re.findall(
                            r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+[^\s<>"]*', 
                            content
                        )
                        for url in found_urls:
                            # Filter out Microsoft/Office internal URLs
                            if url and not any(domain in url.lower() for domain in [
                                'microsoft.com', 'live.com', 'office.com', 'purl.org',
                                'microsoftonline.com', 'openxmlformats.org', 'w3.org'
                            ]):
                                urls.add(url)
                        
                        # Extract formulas (important for analysis)
                        for formula_elem in root.findall('.//*[@f]'):
                            formula_text = formula_elem.get('f')
                            if formula_text and len(formula_text.strip()) > 1:
                                formulas.append(formula_text.strip())
                        
                        # Extract comments
                        for comment in root.findall('.//comment'):
                            if comment.text and comment.text.strip():
                                comments.append(comment.text.strip())
                                
                        # Also look for text in different namespaces
                        namespaces = {
                            'mc': 'http://schemas.openxmlformats.org/spreadsheetml/2006/main',
                            'x': 'http://schemas.openxmlformats.org/spreadsheetml/2006/main'
                        }
                        
                        for ns_prefix, ns_uri in namespaces.items():
                            for comment in root.findall(f'.//{ns_prefix}:comment', {ns_prefix: ns_uri}):
                                if comment.text and comment.text.strip():
                                    comments.append(comment.text.strip())
                                    
                    except ET.ParseError as e:
                        logger.debug(f"Could not parse XML in {filename}: {e}")
                    except Exception as e:
                        logger.debug(f"Error processing XML in {filename}: {e}")

            # Add security-relevant metadata sections
            if urls:
                metadata.append("=== EMBEDDED URLS ===")
                metadata.extend(sorted(urls))
            
            if formulas:
                metadata.append("=== FORMULAS ===")
                metadata.extend(formulas[:20])  # Limit to first 20 formulas
                if len(formulas) > 20:
                    metadata.append(f"... and {len(formulas) - 20} more formulas")
            
            if comments:
                metadata.append("=== COMMENTS ===")
                metadata.extend(comments)

            # Check for embedded files (potential security risk)
            embedded_files = []
            for filename in z.namelist():
                if 'embeddings' in filename.lower() or 'objects' in filename.lower():
                    try:
                        file_info = z.getinfo(filename)
                        embedded_files.append(f"{filename} ({file_info.file_size} bytes)")
                    except Exception as e:
                        logger.debug(f"Error processing embedded file {filename}: {e}")
            
            if embedded_files:
                metadata.append("=== EMBEDDED FILES ===")
                metadata.extend(embedded_files)

        # Clean and join the extracted text
        result_parts = []
        
        if extracted_text:
            # Remove duplicates and clean text
            unique_text = list(dict.fromkeys(extracted_text))  # Preserve order
            full_text = ' '.join(unique_text)
            cleaned_text = re.sub(r'[^\x20-\x7E\n\r\t]+', '', full_text)
            cleaned_text = re.sub(r'\s+', ' ', cleaned_text).strip()
            
            if cleaned_text:
                result_parts.append("=== EXCEL CONTENT ===")
                result_parts.append(cleaned_text)
        
        # Add metadata
        if metadata:
            result_parts.extend(metadata)
        
        if result_parts:
            return "\n\n".join(result_parts)
        else:
            return "[No text content found in Excel file]"

    except zipfile.BadZipFile:
        logger.debug("Not a valid XLSX file (bad zip format)")
        raise ValueError("Invalid XLSX file format")
    except Exception as e:
        logger.debug(f"Failed to extract text from Excel (deep extraction): {e}")
        raise