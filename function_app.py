#!/usr/bin/env python3
"""
Modern Azure Function App for Phishing Email Parser - Production Architecture

Clean implementation using SOLID principles and dependency injection.
Designed for new Logic App integrations with modern JSON API patterns.
"""

import logging
import azure.functions as func
import json
import base64
import tempfile
import os
import time
from typing import Dict, Any, Optional

# Import production parser architecture
from phishing_email_parser.refactored_parser import create_production_parser
from phishing_email_parser.config_manager import get_azure_config
from phishing_email_parser.exceptions import (
    PhishingParserError, EmailParsingError, SecurityViolationError,
    FileProcessingError, ResourceManagementError, ConfigurationError
)
from phishing_email_parser.data_models import ParsingResult

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("PhishingParserFunction")

# Initialize function app
app = func.FunctionApp(http_auth_level=func.AuthLevel.FUNCTION)

# Global parser for cold start optimization
_global_parser = None
_parser_config = None


def get_parser():
    """Get or create global parser instance with cold start optimization."""
    global _global_parser, _parser_config
    
    if _global_parser is None:
        logger.info("Initializing production email parser")
        _parser_config = get_azure_config()
        _global_parser = create_production_parser(config=_parser_config)
        logger.info("Parser initialized successfully")
    
    return _global_parser


def parse_request_data(req: func.HttpRequest) -> tuple[bytes, str]:
    """
    Parse request data supporting multiple input formats for Logic Apps.
    
    Supports:
    1. JSON with base64 encoded email data
    2. Raw email data in request body
    """
    content_type = req.headers.get('content-type', '').lower()
    
    if 'application/json' in content_type:
        # JSON request with base64 encoded email data
        try:
            json_data = req.get_json()
            if not json_data:
                raise ValueError("Empty JSON body")
            
            # Support multiple field names for flexibility
            email_data = None
            if 'email_data' in json_data:
                email_data = base64.b64decode(json_data['email_data'])
            elif 'data' in json_data:
                email_data = base64.b64decode(json_data['data'])
            elif 'email_content' in json_data:
                email_data = base64.b64decode(json_data['email_content'])
            else:
                raise ValueError("JSON must contain 'email_data', 'data', or 'email_content' field with base64 encoded email")
            
            filename = json_data.get('filename', 'email.eml')
            return email_data, filename
            
        except (ValueError, json.JSONDecodeError) as e:
            raise ValueError(f"Invalid JSON request: {e}")
    
    else:
        # Raw email data in body
        email_data = req.get_body()
        if not email_data:
            raise ValueError("Request body is empty")
        
        filename = req.headers.get('x-filename', req.params.get('filename', 'email.eml'))
        return email_data, filename


def create_success_response(result: ParsingResult, format_type: str = "standard") -> Dict[str, Any]:
    """Create structured success response."""
    response = {
        "success": True,
        "timestamp": time.time(),
        "data": None,
        "metadata": {
            "parser_version": "2.0.0",
            "architecture": "solid_di_production",
            "total_layers": result.summary.total_layers,
            "total_attachments": result.summary.total_attachments,
            "total_urls": result.summary.total_urls,
            "processing_time": result.processing_metadata.get("processing_time_seconds", 0)
        }
    }
    
    if format_type == "summary":
        response["data"] = {
            "summary": result.summary.to_dict(),
            "carrier_analysis": result.carrier_analysis.to_dict(),
            "high_priority_layers": [
                layer.layer_depth for layer in result.message_layers 
                if layer.analysis_priority.value == "HIGH"
            ]
        }
    elif format_type == "detailed":
        response["data"] = result.to_dict()
    else:  # standard
        # Optimized response with key information
        response["data"] = {
            "summary": result.summary.to_dict(),
            "message_layers": [layer.to_dict() for layer in result.message_layers],
            "carrier_analysis": result.carrier_analysis.to_dict(),
            "analysis_recommendations": result.carrier_analysis.analysis_recommendations
        }
    
    return response


def create_error_response(error: Exception) -> tuple[Dict[str, Any], int]:
    """Create structured error response with appropriate HTTP status code."""
    
    # Map exceptions to HTTP status codes
    status_code_map = {
        FileProcessingError: 400,
        EmailParsingError: 422,
        SecurityViolationError: 413,
        ValueError: 400,
        FileNotFoundError: 404,
        TimeoutError: 504,
        ConfigurationError: 500,
        ResourceManagementError: 507
    }
    
    status_code = status_code_map.get(type(error), 500)
    
    error_response = {
        "success": False,
        "timestamp": time.time(),
        "error": {
            "type": type(error).__name__,
            "message": str(error),
            "code": status_code
        }
    }
    
    # Add detailed error information for custom exceptions
    if isinstance(error, PhishingParserError) and hasattr(error, 'details'):
        error_response["error"]["details"] = error.details
    
    logger.error(f"Function error: {error}", exc_info=True)
    
    return error_response, status_code


# ============================================================================
# PRIMARY EMAIL PARSING ENDPOINT
# ============================================================================

@app.function_name("parse_email")
@app.route(methods=["POST"], route="parse")
def parse_email(req: func.HttpRequest) -> func.HttpResponse:
    """
    Primary email parsing endpoint for Logic App integration.
    
    Request Body (JSON):
    {
        "email_data": "base64_encoded_email_content",
        "filename": "optional_filename.eml",
        "format": "standard|summary|detailed"
    }
    
    Response:
    {
        "success": true,
        "timestamp": 1234567890,
        "data": { ... parsed email data ... },
        "metadata": { ... processing metadata ... }
    }
    """
    logger.info("Processing email parsing request")
    
    try:
        # Parse request data
        email_data, filename = parse_request_data(req)
        
        # Get response format
        format_type = req.params.get('format', 'standard')
        if format_type not in ['standard', 'summary', 'detailed']:
            format_type = 'standard'
        
        logger.info(f"Processing email: {filename} ({len(email_data)} bytes, format: {format_type})")
        
        # Get parser instance
        parser = get_parser()
        
        # Create temporary file for processing
        with tempfile.NamedTemporaryFile(suffix=".eml", delete=False) as temp_file:
            temp_file.write(email_data)
            temp_file_path = temp_file.name
        
        try:
            # Parse email using production architecture
            with parser:
                result = parser.parse_email_file(temp_file_path)
            
            # Create structured response
            response_data = create_success_response(result, format_type)
            
            logger.info(f"Successfully parsed email: {result.summary.total_layers} layers, "
                       f"{result.summary.total_attachments} attachments, "
                       f"{result.summary.total_urls} URLs")
            
            return func.HttpResponse(
                json.dumps(response_data, ensure_ascii=False, indent=2),
                status_code=200,
                mimetype="application/json",
                headers={
                    "Content-Type": "application/json",
                    "X-Content-Type-Options": "nosniff",
                    "Cache-Control": "no-cache"
                }
            )
            
        finally:
            # Clean up temporary file
            try:
                os.unlink(temp_file_path)
            except Exception as cleanup_error:
                logger.warning(f"Failed to cleanup temp file: {cleanup_error}")
        
    except Exception as e:
        error_response, status_code = create_error_response(e)
        
        return func.HttpResponse(
            json.dumps(error_response, ensure_ascii=False, indent=2),
            status_code=status_code,
            mimetype="application/json"
        )


# ============================================================================
# BATCH PROCESSING ENDPOINT
# ============================================================================

@app.function_name("parse_email_batch")
@app.route(methods=["POST"], route="parse/batch")
def parse_email_batch(req: func.HttpRequest) -> func.HttpResponse:
    """
    Batch email parsing endpoint for processing multiple emails.
    
    Request Body (JSON):
    {
        "emails": [
            {
                "email_data": "base64_encoded_email_1",
                "filename": "email1.eml"
            },
            {
                "email_data": "base64_encoded_email_2", 
                "filename": "email2.eml"
            }
        ],
        "format": "summary"
    }
    """
    logger.info("Processing batch email parsing request")
    
    try:
        json_data = req.get_json()
        if not json_data or 'emails' not in json_data:
            raise ValueError("Request must contain 'emails' array")
        
        emails = json_data['emails']
        if not isinstance(emails, list) or len(emails) == 0:
            raise ValueError("'emails' must be a non-empty array")
        
        if len(emails) > 10:  # Reasonable batch limit
            raise ValueError("Batch size limited to 10 emails")
        
        format_type = json_data.get('format', 'summary')
        parser = get_parser()
        
        results = []
        successful = 0
        failed = 0
        
        for i, email_item in enumerate(emails):
            logger.info(f"Processing email {i+1}/{len(emails)}")
            
            try:
                if not isinstance(email_item, dict) or 'email_data' not in email_item:
                    raise ValueError("Each email must contain 'email_data' field")
                
                email_data = base64.b64decode(email_item['email_data'])
                filename = email_item.get('filename', f'email_{i}.eml')
                
                # Create temporary file
                with tempfile.NamedTemporaryFile(suffix=".eml", delete=False) as temp_file:
                    temp_file.write(email_data)
                    temp_file_path = temp_file.name
                
                try:
                    # Parse email
                    with parser:
                        result = parser.parse_email_file(temp_file_path)
                    
                    # Add to results
                    results.append({
                        "index": i,
                        "filename": filename,
                        "success": True,
                        "data": create_success_response(result, format_type)["data"]
                    })
                    successful += 1
                    
                finally:
                    os.unlink(temp_file_path)
                
            except Exception as e:
                logger.error(f"Error processing email {i}: {e}")
                results.append({
                    "index": i,
                    "filename": email_item.get('filename', f'email_{i}.eml'),
                    "success": False,
                    "error": {
                        "type": type(e).__name__,
                        "message": str(e)
                    }
                })
                failed += 1
        
        # Create batch response
        batch_response = {
            "success": True,
            "timestamp": time.time(),
            "batch_summary": {
                "total": len(emails),
                "successful": successful,
                "failed": failed,
                "success_rate": successful / len(emails)
            },
            "results": results
        }
        
        logger.info(f"Batch processing complete: {successful}/{len(emails)} successful")
        
        return func.HttpResponse(
            json.dumps(batch_response, ensure_ascii=False, indent=2),
            status_code=200,
            mimetype="application/json"
        )
        
    except Exception as e:
        error_response, status_code = create_error_response(e)
        
        return func.HttpResponse(
            json.dumps(error_response, ensure_ascii=False, indent=2),
            status_code=status_code,
            mimetype="application/json"
        )


# ============================================================================
# ANALYSIS ENDPOINT
# ============================================================================

@app.function_name("analyze_email")
@app.route(methods=["POST"], route="analyze")
def analyze_email(req: func.HttpRequest) -> func.HttpResponse:
    """
    Email analysis endpoint focused on threat analysis and recommendations.
    
    Returns analysis-focused response with threat indicators and recommendations.
    """
    logger.info("Processing email analysis request")
    
    try:
        email_data, filename = parse_request_data(req)
        parser = get_parser()
        
        with tempfile.NamedTemporaryFile(suffix=".eml", delete=False) as temp_file:
            temp_file.write(email_data)
            temp_file_path = temp_file.name
        
        try:
            with parser:
                result = parser.parse_email_file(temp_file_path)
            
            # Create analysis-focused response
            high_priority_layers = [
                layer for layer in result.message_layers 
                if layer.analysis_priority.value == "HIGH"
            ]
            
            threat_indicators = []
            for layer in high_priority_layers:
                if layer.urls:
                    threat_indicators.extend([
                        {"type": "url", "value": url.original_url, "layer": layer.layer_depth}
                        for url in layer.urls
                    ])
                
                if layer.attachments:
                    for att in layer.attachments:
                        if att.is_suspicious_extension:
                            threat_indicators.append({
                                "type": "suspicious_attachment",
                                "value": att.filename,
                                "layer": layer.layer_depth
                            })
            
            analysis_response = {
                "success": True,
                "timestamp": time.time(),
                "analysis": {
                    "threat_level": "HIGH" if high_priority_layers else "LOW",
                    "priority_layers": [layer.layer_depth for layer in high_priority_layers],
                    "threat_indicators": threat_indicators,
                    "carrier_analysis": result.carrier_analysis.to_dict(),
                    "recommendations": result.carrier_analysis.analysis_recommendations,
                    "summary": {
                        "total_layers": result.summary.total_layers,
                        "total_urls": result.summary.total_urls,
                        "total_attachments": result.summary.total_attachments,
                        "has_nested_emails": result.summary.has_nested_emails
                    }
                },
                "filename": filename
            }
            
            return func.HttpResponse(
                json.dumps(analysis_response, ensure_ascii=False, indent=2),
                status_code=200,
                mimetype="application/json"
            )
            
        finally:
            os.unlink(temp_file_path)
        
    except Exception as e:
        error_response, status_code = create_error_response(e)
        
        return func.HttpResponse(
            json.dumps(error_response, ensure_ascii=False, indent=2),
            status_code=status_code,
            mimetype="application/json"
        )


# ============================================================================
# HEALTH AND STATUS ENDPOINTS
# ============================================================================

@app.function_name("health_check")
@app.route(methods=["GET"], route="health")
def health_check(req: func.HttpRequest) -> func.HttpResponse:
    """Health check endpoint for monitoring and Logic App validation."""
    try:
        # Test parser initialization
        parser = get_parser()
        config = _parser_config
        
        health_data = {
            "status": "healthy",
            "timestamp": time.time(),
            "service": {
                "name": "phishing-email-parser",
                "version": "2.0.0",
                "architecture": "solid_di_production"
            },
            "endpoints": [
                "POST /api/parse",
                "POST /api/parse/batch", 
                "POST /api/analyze",
                "GET  /api/health",
                "GET  /api/status"
            ],
            "features": {
                "enhanced_carrier_detection": config.processing.enable_enhanced_carrier_detection,
                "content_deduplication": config.processing.enable_deduplication,
                "ocr_enabled": config.ocr.enabled,
                "url_expansion": config.url_processing.enable_expansion,
                "excel_image_extraction": config.processing.preserve_excel_images
            },
            "limits": {
                "max_file_size_mb": config.security.max_file_size_mb,
                "max_nested_depth": config.security.max_nested_depth,
                "max_attachments": config.security.max_attachments
            }
        }
        
        return func.HttpResponse(
            json.dumps(health_data, indent=2),
            status_code=200,
            mimetype="application/json"
        )
        
    except Exception as e:
        return func.HttpResponse(
            json.dumps({
                "status": "unhealthy", 
                "timestamp": time.time(),
                "error": str(e)
            }, indent=2),
            status_code=503,
            mimetype="application/json"
        )


@app.function_name("status")
@app.route(methods=["GET"], route="status")
def get_status(req: func.HttpRequest) -> func.HttpResponse:
    """Detailed status endpoint with performance metrics."""
    try:
        parser = get_parser()
        
        status_data = {
            "service": "phishing-email-parser",
            "version": "2.0.0",
            "timestamp": time.time(),
            "parser_initialized": parser is not None,
            "architecture": "solid_di_production",
            "dependencies": {
                "azure_functions": True,
                "production_parser": True,
                "ocr_libraries": _parser_config.ocr.enabled if _parser_config else False,
                "excel_processing": True,
                "url_processing": True
            },
            "configuration": {
                "environment": "azure_function",
                "cold_start_optimization": True,
                "dependency_injection": True,
                "structured_error_handling": True
            }
        }
        
        return func.HttpResponse(
            json.dumps(status_data, indent=2),
            status_code=200,
            mimetype="application/json"
        )
        
    except Exception as e:
        return func.HttpResponse(
            json.dumps({"error": str(e)}, indent=2),
            status_code=500,
            mimetype="application/json"
        )


if __name__ == "__main__":
    logger.info("Phishing Email Parser Azure Function App - Production Version")
    logger.info("Available endpoints:")
    logger.info("  POST /api/parse - Primary email parsing")
    logger.info("  POST /api/parse/batch - Batch email processing")
    logger.info("  POST /api/analyze - Threat analysis focused")
    logger.info("  GET  /api/health - Health check")
    logger.info("  GET  /api/status - Detailed status")