"""
Device and User-Agent Parser

Parses user-agent strings to extract device, browser, and OS information.
"""

import re
import logging
from typing import Dict, Optional, Any

logger = logging.getLogger(__name__)


def parse_device_from_headers(request) -> Dict[str, Optional[str]]:
    """
    Extract device information from custom headers (prioritized for mobile apps)
    or fall back to user-agent parsing.
    
    Args:
        request: FastAPI Request object with headers
        
    Returns:
        Dictionary with device_type, device_name, os_name, os_version, 
        browser_name, browser_version, and app_version
    """
    # First, check for custom headers sent by mobile app (prioritized)
    device_type = request.headers.get("X-Device-Type")
    device_name = request.headers.get("X-Device-Name")
    os_name = request.headers.get("X-OS-Name")
    os_version = request.headers.get("X-OS-Version")
    browser_name = request.headers.get("X-Browser-Name")
    browser_version = request.headers.get("X-Browser-Version")
    app_version = request.headers.get("X-App-Version")
    
    # Convert empty strings to None
    custom_headers = {
        "device_type": device_type if device_type else None,
        "device_name": device_name if device_name else None,
        "os_name": os_name if os_name else None,
        "os_version": os_version if os_version else None,
        "browser_name": browser_name if browser_name else None,  # Usually null for apps
        "browser_version": browser_version if browser_version else None,  # Usually null for apps
        "app_version": app_version if app_version else None,
    }
    
    # If custom headers are present (mobile app), use them
    if custom_headers["device_type"] or custom_headers["os_name"]:
        return custom_headers
    
    # Otherwise, fall back to user-agent parsing (web browsers)
    user_agent = request.headers.get("user-agent")
    return parse_user_agent(user_agent)


def _detect_device_type(user_agent_lower: str) -> str:
    """Detect device type from user agent."""
    if "mobile" in user_agent_lower or "android" in user_agent_lower or "iphone" in user_agent_lower or "ipod" in user_agent_lower:
        return "mobile"
    if "tablet" in user_agent_lower or "ipad" in user_agent_lower:
        return "tablet"
    return "desktop"


def _detect_os(result: Dict[str, Optional[str]], user_agent_lower: str) -> None:
    """Detect OS name and version from user agent."""
    if "windows" in user_agent_lower:
        result["os_name"] = "Windows"
        win_match = re.search(r'windows nt (\d+\.?\d*)', user_agent_lower)
        if win_match:
            version_map = {"10.0": "10", "6.3": "8.1", "6.2": "8", "6.1": "7"}
            result["os_version"] = version_map.get(win_match.group(1), win_match.group(1))
    elif "mac os" in user_agent_lower or "macos" in user_agent_lower or "macintosh" in user_agent_lower:
        result["os_name"] = "macOS"
        mac_match = re.search(r'mac os x (\d+[._]\d+[._]?\d*)', user_agent_lower)
        if mac_match:
            result["os_version"] = mac_match.group(1).replace("_", ".")
    elif "android" in user_agent_lower:
        result["os_name"] = "Android"
        android_match = re.search(r'android ([\d.]+)', user_agent_lower)
        if android_match:
            result["os_version"] = android_match.group(1)
    elif "iphone" in user_agent_lower or "ipod" in user_agent_lower:
        result["os_name"] = "iOS"
        ios_match = re.search(r'os (\d+[._]\d+[._]?\d*)', user_agent_lower)
        if ios_match:
            result["os_version"] = ios_match.group(1).replace("_", ".")
    elif "ipad" in user_agent_lower:
        result["os_name"] = "iPadOS"
        ipados_match = re.search(r'os (\d+[._]\d+[._]?\d*)', user_agent_lower)
        if ipados_match:
            result["os_version"] = ipados_match.group(1).replace("_", ".")
    elif "linux" in user_agent_lower:
        result["os_name"] = "Linux"


def _detect_device_name(result: Dict[str, Optional[str]], user_agent_lower: str) -> None:
    """Detect device name from user agent."""
    if "iphone" in user_agent_lower:
        iphone_match = re.search(r'iphone(?:\s+os)?\s*(\d+)', user_agent_lower, re.IGNORECASE)
        if iphone_match:
            result["device_name"] = f"iPhone {iphone_match.group(1)}"
        else:
            result["device_name"] = "iPhone"
    elif "ipad" in user_agent_lower:
        result["device_name"] = "iPad"
    elif "samsung" in user_agent_lower:
        samsung_match = re.search(r'samsung[-\s]?(\w+)', user_agent_lower, re.IGNORECASE)
        if samsung_match:
            result["device_name"] = f"Samsung {samsung_match.group(1).title()}"
        else:
            result["device_name"] = "Samsung"
    elif "android" in user_agent_lower:
        model_match = re.search(r'android.*?;\s*([a-z0-9\s-]+?)(?:\s+build|\))', user_agent_lower)
        if model_match and len(model_match.group(1).strip()) < 30:
            result["device_name"] = model_match.group(1).strip().title()
        else:
            result["device_name"] = "Android Device"


def _detect_browser(result: Dict[str, Optional[str]], user_agent_lower: str) -> None:
    """Detect browser name and version from user agent."""
    if "chrome" in user_agent_lower and "edg" not in user_agent_lower:
        result["browser_name"] = "Chrome"
        chrome_match = re.search(r'chrome/([\d.]+)', user_agent_lower)
        if chrome_match:
            result["browser_version"] = chrome_match.group(1)
    elif "safari" in user_agent_lower and "chrome" not in user_agent_lower:
        result["browser_name"] = "Safari"
        safari_match = re.search(r'version/([\d.]+)', user_agent_lower)
        if safari_match:
            result["browser_version"] = safari_match.group(1)
    elif "firefox" in user_agent_lower:
        result["browser_name"] = "Firefox"
        firefox_match = re.search(r'firefox/([\d.]+)', user_agent_lower)
        if firefox_match:
            result["browser_version"] = firefox_match.group(1)
    elif "edg" in user_agent_lower or "edge" in user_agent_lower:
        result["browser_name"] = "Edge"
        edge_match = re.search(r'edg?e?/([\d.]+)', user_agent_lower)
        if edge_match:
            result["browser_version"] = edge_match.group(1)
    elif "opera" in user_agent_lower or "opr" in user_agent_lower:
        result["browser_name"] = "Opera"
        opera_match = re.search(r'(?:opera|opr)/([\d.]+)', user_agent_lower)
        if opera_match:
            result["browser_version"] = opera_match.group(1)


def _extract_app_version(result: Dict[str, Optional[str]], user_agent_lower: str) -> None:
    """Extract app version from user agent."""
    app_match = re.search(r'riverpe[\/\s]+([\d.]+)', user_agent_lower, re.IGNORECASE)
    if app_match:
        result["app_version"] = app_match.group(1)


def parse_user_agent(user_agent: Optional[str]) -> Dict[str, Optional[str]]:
    """
    Parse user-agent string to extract device, browser, and OS information.
    
    Args:
        user_agent: User-agent string from request
        
    Returns:
        Dictionary with device_type, device_name, os_name, os_version, 
        browser_name, browser_version, and app_version
    """
    if not user_agent:
        return {
            "device_type": None,
            "device_name": None,
            "os_name": None,
            "os_version": None,
            "browser_name": None,
            "browser_version": None,
            "app_version": None,
        }
    
    user_agent_lower = user_agent.lower()
    
    result: Dict[str, Optional[str]] = {
        "device_type": None,
        "device_name": None,
        "os_name": None,
        "os_version": None,
        "browser_name": None,
        "browser_version": None,
        "app_version": None,
    }
    
    result["device_type"] = _detect_device_type(user_agent_lower)
    _detect_os(result, user_agent_lower)
    _detect_device_name(result, user_agent_lower)
    _detect_browser(result, user_agent_lower)
    _extract_app_version(result, user_agent_lower)
    
    return result

