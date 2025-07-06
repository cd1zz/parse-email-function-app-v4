# ============================================================================
# phishing_email_parser/config_manager.py
# ============================================================================
"""
Production configuration management for phishing email parser.
Supports environment variable configuration for Azure Functions deployment.
"""

import os
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Any
from pathlib import Path


@dataclass(frozen=True)
class OCRConfiguration:
    """OCR-specific configuration settings."""
    enabled: bool = True
    tesseract_cmd: Optional[str] = None
    config_options: str = '--psm 6'
    timeout_seconds: int = 30
    max_image_size_mb: int = 10


@dataclass(frozen=True) 
class URLProcessingConfiguration:
    """URL processing configuration settings."""
    enable_expansion: bool = True
    expansion_timeout: int = 5
    max_redirects: int = 10
    batch_delay: float = 0.5
    skip_image_urls: bool = True
    user_agent: str = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'


@dataclass(frozen=True)
class SecurityConfiguration:
    """Security-related configuration settings."""
    max_file_size_mb: int = 50
    max_nested_depth: int = 10
    max_attachments: int = 100
    suspicious_extensions: Tuple[str, ...] = (
        ".exe", ".scr", ".bat", ".cmd", ".com", ".pif", ".vbs", ".js", ".jar",
        ".zip", ".rar", ".7z", ".ace", ".arj", ".cab", ".lzh", ".tar", ".gz"
    )
    text_extractable_types: Tuple[str, ...] = (
        "application/pdf", "text/plain", "text/html", "text/csv", "application/rtf",
        "application/msword", "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "application/vnd.ms-excel", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    )


@dataclass(frozen=True)
class ProcessingConfiguration:
    """Email processing configuration settings."""
    enable_deduplication: bool = True
    enable_enhanced_carrier_detection: bool = True
    aggressive_html_cleaning: bool = True
    preserve_excel_images: bool = True
    max_ocr_text_length: int = 10000
    max_body_text_length: int = 50000
    max_html_text_length: int = 5000  # Truncate HTML after this many chars
    include_html_in_response: bool = True  # Whether to include html_text at all
    html_truncation_suffix: str = "...[truncated]"  # What to append when truncated
    
    # Alternative: percentage-based truncation
    html_truncation_percentage: float = 0.1  # Show only first 10% of HTML


@dataclass(frozen=True)
class LoggingConfiguration:
    """Logging configuration settings."""
    level: str = "INFO"
    enable_azure_insights: bool = False
    log_attachments: bool = True
    log_urls: bool = True
    max_log_message_length: int = 1000


@dataclass(frozen=True)
class ParserConfiguration:
    """Complete parser configuration combining all sub-configurations."""
    ocr: OCRConfiguration = field(default_factory=OCRConfiguration)
    url_processing: URLProcessingConfiguration = field(default_factory=URLProcessingConfiguration)
    security: SecurityConfiguration = field(default_factory=SecurityConfiguration)
    processing: ProcessingConfiguration = field(default_factory=ProcessingConfiguration)
    logging: LoggingConfiguration = field(default_factory=LoggingConfiguration)
    
    def validate(self) -> None:
        """Validate configuration values and raise specific errors for invalid settings."""
        errors = []
        
        # Security validation
        if self.security.max_file_size_mb <= 0:
            errors.append("max_file_size_mb must be positive")
        if self.security.max_nested_depth <= 0:
            errors.append("max_nested_depth must be positive")
        if self.security.max_attachments <= 0:
            errors.append("max_attachments must be positive")
            
        # OCR validation
        if self.ocr.timeout_seconds <= 0:
            errors.append("OCR timeout_seconds must be positive")
        if self.ocr.max_image_size_mb <= 0:
            errors.append("OCR max_image_size_mb must be positive")
            
        # URL processing validation
        if self.url_processing.expansion_timeout <= 0:
            errors.append("URL expansion_timeout must be positive")
        if self.url_processing.max_redirects <= 0:
            errors.append("URL max_redirects must be positive")
        if self.url_processing.batch_delay < 0:
            errors.append("URL batch_delay cannot be negative")
            
        # Processing validation
        if self.processing.max_ocr_text_length <= 0:
            errors.append("max_ocr_text_length must be positive")
        if self.processing.max_body_text_length <= 0:
            errors.append("max_body_text_length must be positive")
            
        if errors:
            raise ValueError(f"Configuration validation failed: {'; '.join(errors)}")


def get_config_from_env() -> ParserConfiguration:
    """Load configuration from environment variables with Azure Function support."""
    
    # OCR Configuration
    ocr_config = OCRConfiguration(
        enabled=_get_bool_env("PARSER_OCR_ENABLED", True),
        tesseract_cmd=os.getenv("PARSER_TESSERACT_CMD"),
        config_options=os.getenv("PARSER_OCR_CONFIG", "--psm 6"),
        timeout_seconds=_get_int_env("PARSER_OCR_TIMEOUT", 30),
        max_image_size_mb=_get_int_env("PARSER_OCR_MAX_SIZE_MB", 10)
    )
    
    # URL Processing Configuration  
    url_config = URLProcessingConfiguration(
        enable_expansion=_get_bool_env("PARSER_URL_EXPANSION_ENABLED", True),
        expansion_timeout=_get_int_env("PARSER_URL_TIMEOUT", 5),
        max_redirects=_get_int_env("PARSER_URL_MAX_REDIRECTS", 10),
        batch_delay=_get_float_env("PARSER_URL_BATCH_DELAY", 0.5),
        skip_image_urls=_get_bool_env("PARSER_URL_SKIP_IMAGES", True),
        user_agent=os.getenv("PARSER_URL_USER_AGENT", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
    )
    
    # Security Configuration
    security_config = SecurityConfiguration(
        max_file_size_mb=_get_int_env("PARSER_MAX_FILE_SIZE_MB", 50),
        max_nested_depth=_get_int_env("PARSER_MAX_NESTED_DEPTH", 10),
        max_attachments=_get_int_env("PARSER_MAX_ATTACHMENTS", 100)
        # Note: suspicious_extensions and text_extractable_types use defaults for now
        # Could be made configurable if needed
    )
    
    # Processing Configuration
    processing_config = ProcessingConfiguration(
        enable_deduplication=_get_bool_env("PARSER_DEDUPLICATION_ENABLED", True),
        enable_enhanced_carrier_detection=_get_bool_env("PARSER_ENHANCED_CARRIER_DETECTION", True),
        aggressive_html_cleaning=_get_bool_env("PARSER_AGGRESSIVE_HTML_CLEANING", True),
        preserve_excel_images=_get_bool_env("PARSER_PRESERVE_EXCEL_IMAGES", True),
        max_ocr_text_length=_get_int_env("PARSER_MAX_OCR_TEXT_LENGTH", 10000),
        max_body_text_length=_get_int_env("PARSER_MAX_BODY_TEXT_LENGTH", 50000),
        max_html_text_length=_get_int_env("PARSER_MAX_HTML_TEXT_LENGTH", 5000),
        include_html_in_response=_get_bool_env("PARSER_INCLUDE_HTML_IN_RESPONSE", True),
        html_truncation_suffix=os.getenv("PARSER_HTML_TRUNCATION_SUFFIX", "...[truncated]"),
        html_truncation_percentage=_get_float_env("PARSER_HTML_TRUNCATION_PERCENTAGE", 0.1)
    )
    
    # Logging Configuration
    logging_config = LoggingConfiguration(
        level=os.getenv("PARSER_LOG_LEVEL", "INFO").upper(),
        enable_azure_insights=_get_bool_env("PARSER_AZURE_INSIGHTS_ENABLED", False),
        log_attachments=_get_bool_env("PARSER_LOG_ATTACHMENTS", True),
        log_urls=_get_bool_env("PARSER_LOG_URLS", True),
        max_log_message_length=_get_int_env("PARSER_MAX_LOG_LENGTH", 1000)
    )
    
    config = ParserConfiguration(
        ocr=ocr_config,
        url_processing=url_config,
        security=security_config,
        processing=processing_config,
        logging=logging_config
    )
    
    # Validate the loaded configuration
    config.validate()
    
    return config


def get_default_config() -> ParserConfiguration:
    """Get default configuration with factory defaults."""
    config = ParserConfiguration()
    config.validate()
    return config


def _get_bool_env(key: str, default: bool) -> bool:
    """Get boolean value from environment variable."""
    value = os.getenv(key, "").lower()
    if value in ("true", "1", "yes", "on"):
        return True
    elif value in ("false", "0", "no", "off"):
        return False
    else:
        return default


def _get_int_env(key: str, default: int) -> int:
    """Get integer value from environment variable."""
    try:
        return int(os.getenv(key, str(default)))
    except (ValueError, TypeError):
        return default


def _get_float_env(key: str, default: float) -> float:
    """Get float value from environment variable."""
    try:
        return float(os.getenv(key, str(default)))
    except (ValueError, TypeError):
        return default


# Convenience function for Azure Functions
def get_azure_config() -> ParserConfiguration:
    """Get configuration optimized for Azure Functions environment."""
    # Try environment first, fallback to defaults
    try:
        return get_config_from_env()
    except Exception:
        # If environment config fails, use defaults but with Azure optimizations
        config = get_default_config()
        return config