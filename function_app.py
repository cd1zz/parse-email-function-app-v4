#!/usr/bin/env python3
"""
Modern Azure Function App for Phishing Email Parser - Enhanced Architecture

Clean implementation using SOLID principles with pure structural representation.
Designed for new Logic App integrations with consolidated content tracking.
"""

import logging
import azure.functions as func
import json
import base64
import tempfile
import os
import time
from typing import Dict, Any, Optional

# Import enhanced parser architecture
from phishing_email_parser.enhanced_parser import create_enhanced_parser
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
        logger.info("Initializing enhanced email parser")
        _parser_config = get_azure_config()
        _global_parser = create_enhanced_parser(config=_parser_config)
        logger.info("Enhanced parser initialized successfully")
    
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
    """Create structured success response with enhanced data."""
    response = {
        "success": True,
        "timestamp": time.time(),
        "data": None,
        "metadata": {
            "parser_version": "2.0.0",
            "architecture": "enhanced_structural_representation",
            "total_layers": result.structural_summary.total_layers,
            "total_attachments": result.structural_summary.total_attachments,
            "total_urls": result.structural_summary.total_urls,
            "processing_time": result.processing_metadata.get("processing_time_seconds", 0)
        }
    }
    
    if format_type == "summary":
        response["data"] = {
            "structural_summary": result.structural_summary.to_dict(),
            "carrier_analysis": result.carrier_analysis.to_dict(),
            "consolidated_content_counts": {
                "total_urls": len(result.consolidated_content.all_urls),
                "total_images": len(result.consolidated_content.all_images),
                "total_attachments": len(result.consolidated_content.all_attachments),
                "content_chains": len(result.consolidated_content.content_chains)
            }
        }
    elif format_type == "detailed":
        response["data"] = result.to_dict()
    elif format_type == "llm_optimized":
        # Special format optimized for LLM consumption
        response["data"] = create_llm_optimized_response(result)
    else:  # standard
        # Enhanced response with key information and consolidated content
        response["data"] = {
            "structural_summary": result.structural_summary.to_dict(),
            "layers": [layer.to_dict() for layer in result.layers],
            "consolidated_content": result.consolidated_content.to_dict(),
            "carrier_analysis": result.carrier_analysis.to_dict()
        }
    
    return response


def create_llm_optimized_response(result: ParsingResult) -> Dict[str, Any]:
    """Create LLM-optimized response with focused threat content."""
    
    # Extract non-carrier layers (primary threat content)
    threat_layers = []
    for layer in result.layers:
        if not layer.is_carrier_email:
            layer_summary = {
                "layer_depth": layer.layer_depth,
                "subject": layer.headers.subject[:100],
                "from": layer.headers.from_addr[:50],
                "body_preview": layer.body.final_text[:500] + "..." if len(layer.body.final_text) > 500 else layer.body.final_text,
                "attachment_count": len(layer.attachments),
                "url_count": len(layer.urls),
                "image_count": len(layer.images)
            }
            if layer.parent_reference:
                layer_summary["source"] = f"Nested in layer {layer.parent_reference.layer_depth} via {layer.parent_reference.via_attachment}"
            threat_layers.append(layer_summary)
    
    # Extract URLs with full provenance
    threat_urls = []
    for url in result.consolidated_content.all_urls:
        url_analysis = {
            "url": url.original_url,
            "is_shortened": url.is_shortened,
            "found_in_layer": url.found_in.layer if url.found_in else None,
            "source_type": url.found_in.source if url.found_in else "unknown",
            "context": url.found_in.context_snippet if url.found_in else None
        }
        
        # Add specific provenance details
        if url.found_in:
            if url.found_in.attachment_filename:
                url_analysis["found_in_attachment"] = url.found_in.attachment_filename
            if url.found_in.image_filename:
                url_analysis["found_in_image"] = url.found_in.image_filename
                url_analysis["threat_pattern"] = "url_in_image"
        
        threat_urls.append(url_analysis)
    
    # Extract content chains (suspicious patterns)
    suspicious_patterns = []
    for chain in result.consolidated_content.content_chains:
        pattern_analysis = {
            "pattern_type": chain["type"],
            "complexity_indicators": chain.get("complexity_indicators", []),
            "chain_description": " → ".join([
                f"{step['type']}({step.get('filename', step.get('value', step.get('depth', 'unknown')))[:30]})" 
                for step in chain["chain"]
            ])
        }
        suspicious_patterns.append(pattern_analysis)
    
    return {
        "email_structure": {
            "total_layers": result.structural_summary.total_layers,
            "nesting_chain": result.structural_summary.nesting_chain,
            "layer_types": result.structural_summary.layer_types
        },
        "threat_content": {
            "primary_threat_layers": threat_layers,
            "all_urls_with_provenance": threat_urls,
            "suspicious_content_patterns": suspicious_patterns
        },
        "carrier_context": {
            "total_carriers": result.carrier_analysis.total_carriers,
            "carrier_details": result.carrier_analysis.carrier_details,
            "submission_method": result.carrier_analysis.carrier_details[0] if result.carrier_analysis.carrier_details else None
        }
    }


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
    Primary email parsing endpoint with enhanced structural representation.
    
    Request Body (JSON):
    {
        "email_data": "base64_encoded_email_content",
        "filename": "optional_filename.eml",
        "format": "standard|summary|detailed|llm_optimized"
    }
    
    Response:
    {
        "success": true,
        "timestamp": 1234567890,
        "data": { ... enhanced parsed email data ... },
        "metadata": { ... processing metadata ... }
    }
    """
    logger.info("Processing email parsing request with enhanced parser")
    
    try:
        # Parse request data
        email_data, filename = parse_request_data(req)
        
        # Get response format
        format_type = req.params.get('format', 'standard')
        if format_type not in ['standard', 'summary', 'detailed', 'llm_optimized']:
            format_type = 'standard'
        
        logger.info(f"Processing email: {filename} ({len(email_data)} bytes, format: {format_type})")
        
        # Get enhanced parser instance
        parser = get_parser()
        
        # Create temporary file for processing
        with tempfile.NamedTemporaryFile(suffix=".eml", delete=False) as temp_file:
            temp_file.write(email_data)
            temp_file_path = temp_file.name
        
        try:
            # Parse email using enhanced architecture
            with parser:
                result = parser.parse_email_file(temp_file_path)
            
            # Create structured response
            response_data = create_success_response(result, format_type)
            
            logger.info(f"Successfully parsed email: {result.structural_summary.total_layers} layers, "
                       f"{len(result.consolidated_content.all_urls)} URLs (deduplicated), "
                       f"{len(result.consolidated_content.all_attachments)} attachments")
            
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
    Batch email parsing endpoint with enhanced processing.
    
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
        "format": "summary|llm_optimized"
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
# LLM-OPTIMIZED ANALYSIS ENDPOINT
# ============================================================================

@app.function_name("analyze_email")
@app.route(methods=["POST"], route="analyze")
def analyze_email(req: func.HttpRequest) -> func.HttpResponse:
    """
    Email analysis endpoint optimized for LLM consumption.
    
    Returns structured threat analysis with consolidated content and provenance tracking.
    """
    logger.info("Processing LLM-optimized email analysis request")
    
    try:
        email_data, filename = parse_request_data(req)
        parser = get_parser()
        
        with tempfile.NamedTemporaryFile(suffix=".eml", delete=False) as temp_file:
            temp_file.write(email_data)
            temp_file_path = temp_file.name
        
        try:
            with parser:
                result = parser.parse_email_file(temp_file_path)
            
            # Create LLM-optimized analysis response
            llm_data = create_llm_optimized_response(result)
            
            analysis_response = {
                "success": True,
                "timestamp": time.time(),
                "analysis": llm_data,
                "filename": filename,
                "processing_notes": {
                    "content_deduplication": "URLs, images, and attachments deduplicated across layers",
                    "provenance_tracking": "Each element includes full source location information",
                    "structural_preservation": "Email nesting hierarchy maintained for threat analysis"
                }
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
                "architecture": "enhanced_structural_representation"
            },
            "endpoints": [
                "POST /api/parse - Enhanced email parsing with content consolidation",
                "POST /api/parse/batch - Batch email processing", 
                "POST /api/analyze - LLM-optimized threat analysis",
                "GET  /api/health - Health check",
                "GET  /api/status - Detailed status"
            ],
            "features": {
                "content_consolidation": True,
                "provenance_tracking": True,
                "structural_preservation": True,
                "carrier_detection": config.processing.enable_enhanced_carrier_detection,
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
    """Detailed status endpoint with enhanced parser information."""
    try:
        parser = get_parser()
        
        status_data = {
            "service": "phishing-email-parser",
            "version": "2.0.0",
            "timestamp": time.time(),
            "parser_initialized": parser is not None,
            "architecture": "enhanced_structural_representation",
            "dependencies": {
                "azure_functions": True,
                "enhanced_parser": True,
                "content_consolidator": True,
                "provenance_tracking": True,
                "ocr_libraries": _parser_config.ocr.enabled if _parser_config else False,
                "excel_processing": True,
                "url_processing": True
            },
            "configuration": {
                "environment": "azure_function",
                "cold_start_optimization": True,
                "dependency_injection": True,
                "structured_error_handling": True,
                "content_deduplication": True,
                "llm_optimization": True
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
    logger.info("Phishing Email Parser Azure Function App - Enhanced Version")
    logger.info("Available endpoints:")
    logger.info("  POST /api/parse - Enhanced email parsing with content consolidation")
    logger.info("  POST /api/parse/batch - Batch email processing")
    logger.info("  POST /api/analyze - LLM-optimized threat analysis")
    logger.info("  GET  /api/health - Health check")
    logger.info("  GET  /api/status - Detailed status")