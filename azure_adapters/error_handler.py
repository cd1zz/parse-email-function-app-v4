# ============================================================================
# azure_adapters/error_handler.py
# ============================================================================

"""
Centralized error handling for Azure Functions.
"""

import logging
import azure.functions as func
from typing import Any
from phishing_email_parser.exceptions import (
    PhishingParserError,
    FileProcessingError,
    EmailParsingError,
    SecurityViolationError,
    ConfigurationError
)
from .response_formatter import format_error_response

logger = logging.getLogger(__name__)

def handle_function_error(error: Exception, function_name: str) -> func.HttpResponse:
    """
    Handle errors in Azure Functions with appropriate HTTP status codes.
    
    Args:
        error: The exception that occurred
        function_name: Name of the function where error occurred
        
    Returns:
        Formatted HTTP error response
    """
    
    # Log the error with context
    logger.error(f"Error in {function_name}: {str(error)}", exc_info=True)
    
    # Handle specific parser errors
    if isinstance(error, FileProcessingError):
        return format_error_response(
            error_message=error.message,
            status_code=400,
            error_code="FILE_PROCESSING_ERROR",
            details={
                "file_path": error.file_path,
                "file_type": error.file_type
            }
        )
    
    elif isinstance(error, EmailParsingError):
        return format_error_response(
            error_message=error.message,
            status_code=422,
            error_code="EMAIL_PARSING_ERROR",
            details={
                "layer_depth": error.layer_depth,
                "email_file": error.file_path
            }
        )
    
    elif isinstance(error, SecurityViolationError):
        return format_error_response(
            error_message=error.message,
            status_code=413,
            error_code="SECURITY_VIOLATION",
            details={
                "violation_type": error.violation_type,
                "limit_exceeded": error.limit_exceeded
            }
        )
    
    elif isinstance(error, ConfigurationError):
        return format_error_response(
            error_message=error.message,
            status_code=500,
            error_code="CONFIGURATION_ERROR"
        )
    
    elif isinstance(error, PhishingParserError):
        return format_error_response(
            error_message=error.message,
            status_code=500,
            error_code="PARSER_ERROR",
            details=error.details
        )
    
    # Handle common Python errors
    elif isinstance(error, ValueError):
        return format_error_response(
            error_message="Invalid input data",
            status_code=400,
            error_code="INVALID_INPUT"
        )
    
    elif isinstance(error, MemoryError):
        return format_error_response(
            error_message="Insufficient memory to process request",
            status_code=507,
            error_code="MEMORY_ERROR"
        )
    
    elif isinstance(error, TimeoutError):
        return format_error_response(
            error_message="Request processing timed out",
            status_code=408,
            error_code="TIMEOUT_ERROR"
        )
    
    # Generic error handling
    else:
        return format_error_response(
            error_message="An unexpected error occurred",
            status_code=500,
            error_code="INTERNAL_ERROR"
        )
