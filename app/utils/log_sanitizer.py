"""
Log Sanitization Utility

Provides secure logging helpers to prevent log injection vulnerabilities.
Log injection can occur when user-controlled data containing CRLF characters
or other malicious content is logged directly, potentially allowing attackers
to forge log entries or inject malicious data.

Usage:
    from app.utils.log_sanitizer import sanitize_for_log

    # Sanitize user-controlled data before logging
    logger.info("User login attempt: email=%s", sanitize_for_log(email))
    logger.warning("Failed login for: %s", sanitize_for_log(user.email))

References:
    - OWASP Log Injection: https://owasp.org/www-community/attacks/Log_Injection
    - CWE-117: Improper Output Neutralization for Logs
"""

import re
import base64
from typing import Any, Optional


# Allowlist pattern: alphanumeric, dots, hyphens, underscores, @, and spaces
# This covers most legitimate email addresses and usernames
SAFE_CHAR_PATTERN = re.compile(r'^[a-zA-Z0-9.\-_@\s]+$')

# Pattern to detect CRLF injection attempts
CRLF_PATTERN = re.compile(r'[\r\n]')


def sanitize_for_log(value: Any, max_length: int = 200, encoding: str = 'base64') -> str:
    """
    Sanitize user-controlled data for safe logging.

    This function prevents log injection attacks by:
    1. Removing or encoding CR/LF characters
    2. Enforcing an allowlist of safe characters
    3. Base64-encoding values that contain unsafe characters
    4. Truncating overly long values to prevent log flooding

    Args:
        value: The value to sanitize (will be converted to string)
        max_length: Maximum length for the sanitized output (default: 200)
        encoding: Encoding method for unsafe values: 'base64', 'replace', or 'remove'
                  - 'base64': Base64-encode unsafe values (preserves data, clearly marked)
                  - 'replace': Replace unsafe chars with underscores (human-readable)
                  - 'remove': Remove all unsafe characters (most aggressive)

    Returns:
        A sanitized string safe for logging

    Examples:
        >>> sanitize_for_log("user@example.com")
        'user@example.com'

        >>> sanitize_for_log("user@example.com\\nADMIN=true")
        '[BASE64]dXNlckBleGFtcGxlLmNvbQpBRE1JTj10cnVl'

        >>> sanitize_for_log("test@test.com", encoding='replace')
        'test@test.com'

        >>> sanitize_for_log("evil\\r\\nINJECTION", encoding='remove')
        'evilINJECTION'
    """
    # Handle None and convert to string
    if value is None:
        return "[NULL]"

    # Convert to string
    str_value = str(value)

    # Truncate if too long (before processing to avoid wasting CPU on huge inputs)
    if len(str_value) > max_length * 2:  # Allow some headroom for encoding
        str_value = str_value[:max_length * 2]

    # Check if value is safe (only contains allowlisted characters)
    is_safe = bool(SAFE_CHAR_PATTERN.match(str_value)) and not CRLF_PATTERN.search(str_value)

    if is_safe:
        # Value is safe, return as-is (truncated if needed)
        return str_value[:max_length]

    # Value contains unsafe characters - handle based on encoding method
    if encoding == 'base64':
        # Base64 encode the value and prefix with [BASE64] marker
        encoded = base64.b64encode(str_value.encode('utf-8', errors='replace')).decode('ascii')
        result = f"[BASE64]{encoded}"
        return result[:max_length]

    elif encoding == 'replace':
        # Replace unsafe characters with underscores
        sanitized = CRLF_PATTERN.sub('_', str_value)
        # Replace any other non-allowlisted chars
        sanitized = ''.join(c if c.isalnum() or c in '.-_@' else '_' for c in sanitized)
        return sanitized[:max_length]

    elif encoding == 'remove':
        # Remove all unsafe characters
        sanitized = CRLF_PATTERN.sub('', str_value)
        # Keep only allowlisted chars
        sanitized = ''.join(c for c in sanitized if c.isalnum() or c in '.-_@')
        return sanitized[:max_length]

    else:
        # Unknown encoding method, fall back to base64
        encoded = base64.b64encode(str_value.encode('utf-8', errors='replace')).decode('ascii')
        result = f"[BASE64]{encoded}"
        return result[:max_length]


def sanitize_pii(value: Any, show_prefix: int = 3) -> str:
    """
    Sanitize PII (Personally Identifiable Information) for logging.

    Shows only a prefix of the value and masks the rest with asterisks.
    Useful for logging emails, usernames, or other PII while maintaining privacy.

    Args:
        value: The PII value to sanitize
        show_prefix: Number of characters to show before masking (default: 3)

    Returns:
        A masked string safe for logging

    Examples:
        >>> sanitize_pii("user@example.com")
        'use***'

        >>> sanitize_pii("user@example.com", show_prefix=5)
        'user@***'
    """
    if value is None:
        return "[NULL]"

    str_value = str(value)

    # First, sanitize to prevent injection
    safe_value = sanitize_for_log(str_value, encoding='replace')

    # Then mask
    if len(safe_value) <= show_prefix:
        return "***"

    return safe_value[:show_prefix] + "***"


def sanitize_dict_for_log(data: dict, sensitive_keys: Optional[set] = None) -> dict:
    """
    Sanitize all values in a dictionary for safe logging.

    Recursively sanitizes dictionary values and masks sensitive keys.

    Args:
        data: Dictionary to sanitize
        sensitive_keys: Set of keys to mask (e.g., {'password', 'token', 'secret'})
                       Default: {'password', 'token', 'secret', 'api_key', 'authorization'}

    Returns:
        A new dictionary with sanitized values

    Examples:
        >>> sanitize_dict_for_log({"email": "test@test.com", "password": "secret123"})
        {'email': 'test@test.com', 'password': '[REDACTED]'}
    """
    if sensitive_keys is None:
        sensitive_keys = {'password', 'token', 'secret', 'api_key', 'authorization',
                         'refresh_token', 'access_token', 'jwt', 'auth'}

    result = {}
    for key, value in data.items():
        # Check if key is sensitive (case-insensitive)
        if any(sensitive_key in key.lower() for sensitive_key in sensitive_keys):
            result[key] = "[REDACTED]"
        elif isinstance(value, dict):
            # Recursively sanitize nested dicts
            result[key] = sanitize_dict_for_log(value, sensitive_keys)
        elif isinstance(value, (list, tuple)):
            # Sanitize lists/tuples
            result[key] = [sanitize_for_log(v) if not isinstance(v, dict) else sanitize_dict_for_log(v, sensitive_keys) for v in value]
        else:
            # Sanitize primitive values
            result[key] = sanitize_for_log(value)

    return result
