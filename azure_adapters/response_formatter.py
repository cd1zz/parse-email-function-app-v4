# ============================================================================
# azure_adapters/response_formatter.py
# ============================================================================

"""
HTTP response formatting for Azure Functions.
"""

import json
import azure.functions as func
from typing import Any, Dict, Optional
from datetime import datetime

def format_success_response(
    data: Any, 
    status_code: int = 200,
    headers: Optional[Dict[str, str]] = None
) -> func.HttpResponse:
    """Format successful response."""
    
    response_data = {
        "success": True,
        "timestamp": datetime.utcnow().isoformat(),
        "data": data
    }
    
    default_headers = {
        "Content-Type": "application/json",
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY"
    }
    
    if headers:
        default_headers.update(headers)
    
    return func.HttpResponse(
        json.dumps(response_data, default=str, indent=2),
        status_code=status_code,
        headers=default_headers
    )

def format_error_response(
    error_message: str,
    status_code: int = 500,
    error_code: Optional[str] = None,
    details: Optional[Dict[str, Any]] = None
) -> func.HttpResponse:
    """Format error response."""
    
    response_data = {
        "success": False,
        "timestamp": datetime.utcnow().isoformat(),
        "error": {
            "message": error_message,
            "code": error_code,
            "details": details
        }
    }
    
    return func.HttpResponse(
        json.dumps(response_data, default=str, indent=2),
        status_code=status_code,
        headers={"Content-Type": "application/json"}
    )
