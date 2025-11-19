"""
Standard API Response Utility

Provides a unified response format for all API endpoints.
All endpoints should use this to ensure consistent response structure.
"""
from typing import Any, Optional


def standard_response(
    success: bool,
    message: str,
    data: Optional[Any] = None,
    error: Optional[dict] = None,
    meta: Optional[dict] = None
) -> dict:
    """
    Create a standardized API response.
    
    Args:
        success: Whether the operation succeeded
        message: Human-readable message describing the result
        data: The actual payload (can be any type)
        error: Error details if operation failed (dict with code, message, details)
        meta: Optional metadata (pagination, timestamps, etc.)
    
    Returns:
        Dictionary with unified response structure
    """
    return {
        "success": success,
        "message": message,
        "data": data,
        "error": error,
        "meta": meta or {}
    }

