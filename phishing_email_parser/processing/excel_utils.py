# ============================================================================
# phishing_email_parser/processing/excel_utils.py  
# ============================================================================
"""Excel text extraction utilities."""

import io
import logging

logger = logging.getLogger(__name__)


def extract_text_from_excel(excel_data: bytes, output_dir: str = None) -> str:
    """Extract text content from Excel binary data."""
    if not excel_data:
        return "[Empty Excel file]"
        
    try:
        # Try pandas first
        try:
            import pandas as pd
            
            excel_file = io.BytesIO(excel_data)
            dfs = pd.read_excel(excel_file, sheet_name=None, engine=None)
            
            text_content = []
            for sheet_name, df in dfs.items():
                if not df.empty:
                    text_content.append(f"=== Sheet: {sheet_name} ===")
                    df_text = df.fillna('').to_string(index=False)
                    text_content.append(df_text)
                    text_content.append("")
            
            if text_content:
                return "\n".join(text_content).strip()
                
        except ImportError:
            logger.warning("pandas not available for Excel processing")
        
        # Fallback
        return "[Excel content - processing libraries not available]"
        
    except Exception as e:
        logger.error(f"Error extracting text from Excel: {e}")
        return f"[Error extracting Excel text: {e}]"


def extract_excel_with_images(excel_data: bytes, output_dir: str) -> tuple[str, list]:
    """Extract both text content and images from Excel file."""
    text_content = extract_text_from_excel(excel_data, output_dir)
    images = []  # Simplified - no image extraction in basic version
    return text_content, images


class ExcelImageExtractor:
    """Handles extraction of images embedded in Excel files."""
    
    def __init__(self, output_dir: str):
        self.output_dir = output_dir
    
    def extract_images_from_xlsx(self, excel_data: bytes) -> list:
        """Extract images from XLSX files."""
        # Simplified implementation
        return []