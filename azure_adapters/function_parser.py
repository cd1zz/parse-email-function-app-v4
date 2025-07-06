# ============================================================================
# azure_adapters/function_parser.py
# ============================================================================
"""
Azure Function adapter for phishing email parser.
Optimized for serverless environment with cold start optimization.
"""

import base64
import json
import logging
import os
import tempfile
import time
from typing import Dict, Any, Optional, Union

from ..refactored_parser import create_production_parser
from ..config_manager import get_azure_config, ParserConfiguration
from ..data_models import ParsingResult
from ..exceptions import (
    PhishingParserError, EmailParsingError, AttachmentProcessingError,
    SecurityViolationError, ConfigurationError, DependencyError
)

logger = logging.getLogger(__name__)

# Global parser instance for cold start optimization
_global_parser = None
_global_config = None


class AzureFunctionParser:
    """
    Azure Function parser optimized for serverless environment.
    
    Features:
    - Cold start optimization with global parser instance
    - Azure environment variable configuration  
    - Memory management and timeout handling
    - Dependency checking
    """
    
    def __init__(self, config: Optional[ParserConfiguration] = None):
        """Initialize with Azure-optimized configuration."""
        self.config = config or get_azure_config()
        self.parser = None
        self._dependencies_checked = False
    
    def get_parser(self):
        """Get parser instance with cold start optimization."""
        global _global_parser, _global_config
        
        # Use global instance if available and config matches
        if _global_parser and _global_config and self._configs_match(_global_config, self.config):
            logger.debug("Using cached global parser instance")
            return _global_parser
        
        # Create new parser instance
        logger.info("Creating new parser instance for Azure Function")
        self.parser = create_production_parser(config=self.config)
        
        # Cache globally for future requests
        _global_parser = self.parser
        _global_config = self.config
        
        return self.parser
    
    def parse_email_data(self, email_data: bytes, filename: str = "email.eml") -> ParsingResult:
        """
        Parse email data in Azure Function context.
        
        Args:
            email_data: Raw email data (bytes)
            filename: Original filename for context
            
        Returns:
            ParsingResult with parsed email data
        """
        start_time = time.time()
        
        # Check dependencies
        self._check_dependencies()
        
        # Create temporary file for processing
        with tempfile.NamedTemporaryFile(suffix=".eml", delete=False) as temp_file:
            temp_file.write(email_data)
            temp_file_path = temp_file.name
        
        try:
            parser = self.get_parser()
            
            with parser:
                result = parser.parse_email_file(temp_file_path)
                
            # Add Azure Function metadata
            processing_time = time.time() - start_time
            result.processing_metadata.update({
                "azure_function_processing": True,
                "cold_start_used": _global_parser is not None,
                "processing_time_seconds": processing_time,
                "original_filename": filename
            })
            
            logger.info(f"Azure Function parsing complete: {processing_time:.2f}s")
            return result
            
        finally:
            # Clean up temporary file
            try:
                os.unlink(temp_file_path)
            except Exception as e:
                logger.warning(f"Failed to clean up temp file: {e}")
    
    def _check_dependencies(self):
        """Check if required dependencies are available in Azure environment."""
        if self._dependencies_checked:
            return
        
        missing_deps = []
        
        # Check OCR dependencies
        if self.config.ocr.enabled:
            try:
                import pytesseract
                from PIL import Image
            except ImportError:
                missing_deps.append("OCR libraries (pytesseract, Pillow)")
                logger.warning("OCR functionality disabled - libraries not available")
        
        # Check Excel processing
        try:
            import pandas as pd
            import openpyxl
        except ImportError:
            missing_deps.append("Excel processing libraries (pandas, openpyxl)")
            logger.warning("Excel processing may be limited")
        
        if missing_deps:
            logger.warning(f"Missing optional dependencies: {', '.join(missing_deps)}")
        
        self._dependencies_checked = True
    
    def _configs_match(self, config1: ParserConfiguration, config2: ParserConfiguration) -> bool:
        """Check if two configurations are equivalent for caching purposes."""
        # Simple comparison - could be enhanced with deep comparison if needed
        return (
            config1.ocr.enabled == config2.ocr.enabled and
            config1.processing.enable_deduplication == config2.processing.enable_deduplication and
            config1.url_processing.enable_expansion == config2.url_processing.enable_expansion
        )


# ============================================================================
# azure_adapters/response_formatter.py
# ============================================================================
"""
Response formatting for Azure Functions with consistent JSON structure.
"""

from typing import Dict, Any, Optional
import json

from ..data_models import ParsingResult
from ..exceptions import PhishingParserError


def format_success_response(
    result: ParsingResult, 
    format_type: str = "standard",
    include_metadata: bool = True
) -> Dict[str, Any]:
    """
    Format successful parsing response.
    
    Args:
        result: Parsing result to format
        format_type: Response format ('standard', 'summary', 'detailed')
        include_metadata: Whether to include processing metadata
        
    Returns:
        Formatted response dictionary
    """
    response = {
        "success": True,
        "status": "completed",
        "data": None,
        "metadata": {}
    }
    
    if format_type == "summary":
        response["data"] = {
            "parser_info": result.parser_info,
            "summary": result.summary.to_dict(),
            "carrier_analysis": {
                "total_carriers": result.carrier_analysis.total_carriers,
                "analysis_recommendations": result.carrier_analysis.analysis_recommendations
            }
        }
    elif format_type == "detailed":
        response["data"] = result.to_dict()
    else:  # standard
        # Return full data but truncate large text fields for performance
        data = result.to_dict()
        _truncate_large_fields(data)
        response["data"] = data
    
    if include_metadata:
        response["metadata"] = {
            "processing_time": result.processing_metadata.get("processing_time_seconds", 0),
            "total_layers": result.summary.total_layers,
            "total_attachments": result.summary.total_attachments,
            "architecture_version": "2.0_production"
        }
    
    # Add security headers
    response["_headers"] = {
        "Content-Type": "application/json",
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Cache-Control": "no-cache, no-store, must-revalidate"
    }
    
    return response


def format_error_response(
    error: Exception,
    error_code: str = "PARSING_ERROR",
    include_details: bool = False
) -> Dict[str, Any]:
    """
    Format error response with consistent structure.
    
    Args:
        error: Exception that occurred
        error_code: Specific error code for categorization
        include_details: Whether to include detailed error