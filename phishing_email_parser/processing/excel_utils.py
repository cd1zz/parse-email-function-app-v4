"""
Excel text extraction utilities for phishing email analysis.

Extracts text content, VBA macros, URLs, formulas, and other metadata
from Excel files (.xlsx and .xls) with multiple fallback methods.
"""

import io
import logging
import re
import traceback
import zipfile
from xml.etree import ElementTree as ET

logger = logging.getLogger(__name__)


def extract_text_from_excel(excel_data: bytes) -> str:
    """
    Extract text content from Excel binary data using multiple methods.
    
    Args:
        excel_data: The binary content of the Excel file
        
    Returns:
        Extracted text from the Excel file including content and metadata
    """
    if not excel_data:
        return "[Empty Excel file]"
        
    try:
        logger.debug(f"Extracting text from Excel file ({len(excel_data)} bytes)")
        
        # Create a file-like object from the binary data
        excel_file = io.BytesIO(excel_data)
        
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
                
                # Try to add deep extraction metadata for enhanced analysis
                try:
                    excel_file.seek(0)
                    deep_metadata = _extract_excel_metadata(excel_data)
                    if deep_metadata:
                        result += f"\n\n=== METADATA ===\n{deep_metadata}"
                except Exception as meta_err:
                    logger.debug(f"Could not extract metadata: {meta_err}")
                
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
            result = _extract_excel_deep(excel_data)
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
            
            workbook = xlrd.open_workbook(file_contents=excel_data)
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
    
    except Exception as e:
        logger.error(f"Error extracting text from Excel: {e}")
        logger.debug(traceback.format_exc())
        return f"[Error extracting Excel text: {e}]"
    
    # If we get here, no method worked
    return "[Error: Could not extract text from Excel file using any available method]"


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