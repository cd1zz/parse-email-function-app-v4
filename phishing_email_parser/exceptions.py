# ============================================================================
# phishing_email_parser/exceptions.py  
# ============================================================================
"""
Custom exceptions for the phishing email parser with detailed error context.
Supports structured error handling for production Azure Function deployment.
"""

from typing import Dict, Any, Optional
import functools
import logging

logger = logging.getLogger(__name__)


class PhishingParserError(Exception):
    """Base exception for all phishing parser errors."""
    
    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None, 
                 original_exception: Optional[Exception] = None):
        super().__init__(message)
        self.message = message
        self.details = details or {}
        self.original_exception = original_exception
        
    def __str__(self) -> str:
        base_msg = self.message
        if self.details:
            details_str = ", ".join(f"{k}={v}" for k, v in self.details.items())
            return f"{base_msg} (Details: {details_str})"
        return base_msg


class EmailParsingError(PhishingParserError):
    """Raised when email parsing fails."""
    pass


class AttachmentProcessingError(PhishingParserError):
    """Raised when attachment processing fails."""
    pass


class TextExtractionError(PhishingParserError):
    """Raised when text extraction from files fails."""
    pass


class OCRProcessingError(PhishingParserError):
    """Raised when OCR processing fails."""
    pass


class URLProcessingError(PhishingParserError):
    """Raised when URL processing fails."""
    pass


class CarrierDetectionError(PhishingParserError):
    """Raised when carrier detection fails."""
    pass


class SecurityViolationError(PhishingParserError):
    """Raised when security limits are exceeded."""
    pass


class ResourceManagementError(PhishingParserError):
    """Raised when resource management fails (temp files, memory, etc.)."""
    pass


class DataValidationError(PhishingParserError):
    """Raised when data validation fails."""
    pass


class DependencyError(PhishingParserError):
    """Raised when required dependencies are missing or incompatible."""
    pass


class ConfigurationError(PhishingParserError):
    """Raised when configuration is invalid."""
    pass


class FileProcessingError(PhishingParserError):
    """Raised when file processing fails (covers file I/O issues)."""
    pass


def wrap_processing_error(original_error: Exception, context: str, 
                         details: Optional[Dict[str, Any]] = None) -> PhishingParserError:
    """
    Convert generic exceptions to appropriate PhishingParserError types.
    
    Args:
        original_error: The original exception that occurred
        context: Context string describing where the error occurred  
        details: Additional details about the error
        
    Returns:
        Appropriate PhishingParserError subclass
    """
    error_type = type(original_error).__name__
    error_msg = str(original_error)
    
    # Create enhanced details
    enhanced_details = {
        "original_error_type": error_type,
        "context": context,
        **(details or {})
    }
    
    # Map common exception types to our custom exceptions
    if isinstance(original_error, (IOError, OSError, FileNotFoundError)):
        return FileProcessingError(
            f"File processing failed in {context}: {error_msg}",
            enhanced_details,
            original_error
        )
    elif isinstance(original_error, MemoryError):
        return ResourceManagementError(
            f"Memory limit exceeded in {context}: {error_msg}",
            enhanced_details,
            original_error
        )
    elif isinstance(original_error, TimeoutError):
        return ResourceManagementError(
            f"Operation timed out in {context}: {error_msg}",
            enhanced_details,
            original_error
        )
    elif isinstance(original_error, (ValueError, TypeError)):
        return DataValidationError(
            f"Data validation failed in {context}: {error_msg}",
            enhanced_details,
            original_error
        )
    elif isinstance(original_error, ImportError):
        return DependencyError(
            f"Missing dependency in {context}: {error_msg}",
            enhanced_details,
            original_error
        )
    else:
        # Generic fallback
        return PhishingParserError(
            f"Unexpected error in {context}: {error_msg}",
            enhanced_details,
            original_error
        )


def handle_processing_errors(context: str, reraise_as: Optional[type] = None):
    """
    Decorator for consistent error handling across processing methods.
    
    Args:
        context: Description of the operation being performed
        reraise_as: Optional specific exception type to reraise as
        
    Usage:
        @handle_processing_errors("header extraction")
        def extract_headers(self, msg):
            # Implementation here
    """
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except PhishingParserError:
                # Re-raise our custom exceptions as-is
                raise
            except Exception as e:
                # Wrap other exceptions
                details = {
                    "function": func.__name__,
                    "args_count": len(args),
                    "kwargs_keys": list(kwargs.keys())
                }
                
                wrapped_error = wrap_processing_error(e, context, details)
                
                # Log the error for debugging
                logger.error(f"Error in {context}: {wrapped_error}", exc_info=True)
                
                # Optionally reraise as specific type
                if reraise_as and issubclass(reraise_as, PhishingParserError):
                    raise reraise_as(
                        wrapped_error.message,
                        wrapped_error.details,
                        wrapped_error.original_exception
                    )
                else:
                    raise wrapped_error
        return wrapper
    return decorator


# Convenience functions for common error scenarios
def raise_file_too_large(filename: str, size_mb: float, max_size_mb: float):
    """Raise SecurityViolationError for files that are too large."""
    raise SecurityViolationError(
        f"File '{filename}' exceeds size limit",
        {
            "filename": filename,
            "size_mb": size_mb,
            "max_size_mb": max_size_mb,
            "violation_type": "file_size_limit"
        }
    )


def raise_too_many_attachments(count: int, max_count: int):
    """Raise SecurityViolationError for too many attachments."""
    raise SecurityViolationError(
        f"Too many attachments: {count} exceeds limit of {max_count}",
        {
            "attachment_count": count,
            "max_attachments": max_count,
            "violation_type": "attachment_count_limit"
        }
    )


def raise_nesting_too_deep(depth: int, max_depth: int):
    """Raise SecurityViolationError for email nesting that's too deep."""
    raise SecurityViolationError(
        f"Email nesting too deep: {depth} exceeds limit of {max_depth}",
        {
            "current_depth": depth,
            "max_depth": max_depth,
            "violation_type": "nesting_depth_limit"
        }
    )


def raise_dependency_missing(dependency_name: str, install_command: str):
    """Raise DependencyError for missing dependencies."""
    raise DependencyError(
        f"Required dependency '{dependency_name}' is not available",
        {
            "dependency": dependency_name,
            "install_command": install_command,
            "error_type": "missing_dependency"
        }
    )


def raise_ocr_timeout(filename: str, timeout_seconds: int):
    """Raise OCRProcessingError for OCR timeouts."""
    raise OCRProcessingError(
        f"OCR processing timed out for '{filename}'",
        {
            "filename": filename,
            "timeout_seconds": timeout_seconds,
            "error_type": "ocr_timeout"
        }
    )


def raise_url_expansion_failed(url: str, error_msg: str):
    """Raise URLProcessingError for URL expansion failures."""
    raise URLProcessingError(
        f"Failed to expand URL '{url}'",
        {
            "url": url,
            "error_message": error_msg,
            "error_type": "url_expansion_failed"
        }
    )