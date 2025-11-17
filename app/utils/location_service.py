"""
Location Service

Gets location information from IP address using free geolocation APIs.
Falls back gracefully if services are unavailable.
"""

import httpx
import logging
from typing import Dict, Optional, Any
from ..core.config import settings

logger = logging.getLogger(__name__)


async def get_location_from_ip(ip_address: Optional[str]) -> Dict[str, Optional[Any]]:
    """
    Get location information from IP address using ip-api.com (free, no API key needed).
    
    Args:
        ip_address: IP address to geolocate
        
    Returns:
        Dictionary with country, city, latitude, longitude
    """
    if not ip_address:
        return {
            "country": None,
            "city": None,
            "latitude": None,
            "longitude": None,
        }
    
    # Skip localhost/private IPs
    if ip_address in ["127.0.0.1", "localhost", "::1"] or ip_address.startswith("192.168.") or ip_address.startswith("10."):
        return {
            "country": None,
            "city": None,
            "latitude": None,
            "longitude": None,
        }
    
    try:
        # Using ip-api.com (free, 45 requests/minute, no API key needed)
        # Docs: https://ip-api.com/docs/api:json
        url = f"http://ip-api.com/json/{ip_address}?fields=status,message,country,city,lat,lon"
        
        async with httpx.AsyncClient(timeout=5.0) as client:
            response = await client.get(url)
            
            if response.status_code == 200:
                data = response.json()
                
                if data.get("status") == "success":
                    return {
                        "country": data.get("country"),
                        "city": data.get("city"),
                        "latitude": data.get("lat"),
                        "longitude": data.get("lon"),
                    }
                else:
                    logger.warning(f"[LOCATION] IP geolocation failed: {data.get('message', 'Unknown error')}")
                    return {
                        "country": None,
                        "city": None,
                        "latitude": None,
                        "longitude": None,
                    }
            else:
                logger.warning(f"[LOCATION] IP geolocation API returned status {response.status_code}")
                return {
                    "country": None,
                    "city": None,
                    "latitude": None,
                    "longitude": None,
                }
                
    except httpx.TimeoutException:
        logger.warning(f"[LOCATION] Timeout getting location for IP {ip_address}")
        return {
            "country": None,
            "city": None,
            "latitude": None,
            "longitude": None,
        }
    except Exception as e:
        logger.warning(f"[LOCATION] Error getting location for IP {ip_address}: {str(e)}")
        return {
            "country": None,
            "city": None,
            "latitude": None,
            "longitude": None,
        }


async def get_location_from_client(request) -> Dict[str, Optional[Any]]:
    """
    Get location from request headers (frontend sends if user grants permission).
    Falls back to IP-based geolocation if headers not available.
    
    Args:
        request: FastAPI Request object
        
    Returns:
        Dictionary with country, city, latitude, longitude
    """
    # Check if location is provided by frontend (user granted permission)
    lat_header = request.headers.get("X-User-Latitude")
    lon_header = request.headers.get("X-User-Longitude")
    city_header = request.headers.get("X-User-City")
    country_header = request.headers.get("X-User-Country")
    
    if lat_header and lon_header:
        try:
            latitude = float(lat_header)
            longitude = float(lon_header)
            
            return {
                "country": country_header if country_header else None,
                "city": city_header if city_header else None,
                "latitude": latitude,
                "longitude": longitude,
            }
        except (ValueError, TypeError):
            logger.warning("[LOCATION] Invalid latitude/longitude in headers, falling back to IP geolocation")
    
    # Fallback to IP-based geolocation
    ip_address = getattr(request.client, "host", None)
    return await get_location_from_ip(ip_address)

