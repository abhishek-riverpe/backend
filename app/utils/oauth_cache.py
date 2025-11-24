"""
Temporary OAuth code storage for secure authorization code flow.
Stores temporary codes with expiration for one-time use.
"""
import secrets
import time
from typing import Optional, Dict, Any
from datetime import datetime, timedelta

# In-memory storage for OAuth codes
# Format: {code: {"data": {...}, "expires_at": timestamp}}
_oauth_codes: Dict[str, Dict[str, Any]] = {}

# Cleanup interval (seconds) - remove expired codes
CLEANUP_INTERVAL = 300  # 5 minutes
_last_cleanup = time.time()

# Code expiration time (5 minutes)
CODE_EXPIRY_SECONDS = 300


def _cleanup_expired_codes():
    """Remove expired codes from storage"""
    global _last_cleanup
    current_time = time.time()
    
    # Only cleanup every CLEANUP_INTERVAL seconds
    if current_time - _last_cleanup < CLEANUP_INTERVAL:
        return
    
    _last_cleanup = current_time
    expired_codes = [
        code for code, value in _oauth_codes.items()
        if value.get("expires_at", 0) < current_time
    ]
    for code in expired_codes:
        _oauth_codes.pop(code, None)


def generate_oauth_code(data: Dict[str, Any]) -> str:
    """
    Generate a temporary OAuth code and store it with expiration.
    
    Args:
        data: Dictionary containing user_id, access_token, refresh_token, etc.
    
    Returns:
        Temporary code string
    """
    _cleanup_expired_codes()
    
    # Generate cryptographically secure random code
    code = secrets.token_urlsafe(32)
    expires_at = time.time() + CODE_EXPIRY_SECONDS
    
    _oauth_codes[code] = {
        "data": data,
        "expires_at": expires_at,
        "created_at": time.time()
    }
    
    return code


def exchange_oauth_code(code: str) -> Optional[Dict[str, Any]]:
    """
    Exchange temporary code for stored data (one-time use).
    
    Args:
        code: Temporary OAuth code
    
    Returns:
        Stored data dictionary or None if code is invalid/expired
    """
    _cleanup_expired_codes()
    
    if code not in _oauth_codes:
        return None
    
    code_data = _oauth_codes[code]
    
    # Check expiration
    if code_data["expires_at"] < time.time():
        _oauth_codes.pop(code, None)
        return None
    
    # Remove code (one-time use)
    data = code_data["data"]
    _oauth_codes.pop(code, None)
    
    return data


def get_code_count() -> int:
    """Get current number of stored codes (for monitoring)"""
    _cleanup_expired_codes()
    return len(_oauth_codes)

