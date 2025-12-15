import httpx
from typing import Dict, Optional, Any
from ..core.config import settings


async def get_location_from_ip(ip_address: Optional[str]) -> Dict[str, Optional[Any]]:
    if not ip_address:
        return {
            "country": None,
            "city": None,
            "latitude": None,
            "longitude": None,
        }
    
    # Filter out localhost and private network addresses (RFC 1918)
    # Note: RFC 5737 documentation addresses (192.0.2.x, 198.51.100.x, 203.0.113.x) are NOT filtered
    # as they are safe for testing and may be used in mocked API calls
    if (ip_address in ["127.0.0.1", "localhost", "::1"] or 
        ip_address.startswith("192.168.") or 
        ip_address.startswith("10.")):
        return {
            "country": None,
            "city": None,
            "latitude": None,
            "longitude": None,
        }
    
    try:
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
                    return {
                        "country": None,
                        "city": None,
                        "latitude": None,
                        "longitude": None,
                    }
            else:
                return {
                    "country": None,
                    "city": None,
                    "latitude": None,
                    "longitude": None,
                }
                
    except httpx.TimeoutException:
        return {
            "country": None,
            "city": None,
            "latitude": None,
            "longitude": None,
        }
    except Exception:
        return {
            "country": None,
            "city": None,
            "latitude": None,
            "longitude": None,
        }


async def get_location_from_client(request) -> Dict[str, Optional[Any]]:
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
            pass
    
    ip_address = getattr(request.client, "host", None)
    return await get_location_from_ip(ip_address)

