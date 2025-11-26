"""
Middleware to explicitly handle OPTIONS requests before route matching.
This ensures CORS preflight requests are handled correctly.
"""

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response
import logging

logger = logging.getLogger(__name__)


class CORSOptionsHandlerMiddleware(BaseHTTPMiddleware):
    """
    Middleware that explicitly handles OPTIONS requests before they reach route handlers.
    This works in conjunction with CORSMiddleware to ensure preflight requests are handled.
    """
    
    async def dispatch(self, request: Request, call_next):
        # Handle OPTIONS requests explicitly
        if request.method == "OPTIONS":
            logger.info(f"[CORS] Intercepting OPTIONS request for {request.url.path}")
            # Call next to let CORSMiddleware add CORS headers
            # CORSMiddleware should handle OPTIONS and return early, but if it doesn't,
            # we'll catch it here
            try:
                response = await call_next(request)
                # If we get here and status is not 200, ensure it's 200 for OPTIONS
                if response.status_code != 200:
                    logger.warning(f"[CORS] OPTIONS request returned {response.status_code}, forcing 200")
                    response.status_code = 200
                # Ensure CORS headers are present (CORSMiddleware should add them, but double-check)
                origin = request.headers.get("origin")
                allowed_origins = ["http://localhost:5173", "http://127.0.0.1:5173", "https://www.dattapay.com", "https://app.dattapay.com"]
                if origin and origin in allowed_origins:
                    # Always set CORS headers for allowed origins
                    response.headers["access-control-allow-origin"] = origin
                    response.headers["access-control-allow-methods"] = "GET, POST, PUT, DELETE, OPTIONS"
                    response.headers["access-control-allow-headers"] = "Content-Type, Authorization, Accept, X-Request-ID, X-RP-Skip-Refresh"
                    response.headers["access-control-allow-credentials"] = "true"
                    response.headers["access-control-max-age"] = "600"
                return response
            except Exception as e:
                logger.error(f"[CORS] Error handling OPTIONS request: {e}", exc_info=True)
                # Return a simple 200 response with CORS headers if something goes wrong
                response = Response(status_code=200)
                origin = request.headers.get("origin")
                allowed_origins = ["http://localhost:5173", "http://127.0.0.1:5173", "https://www.dattapay.com", "https://app.dattapay.com"]
                if origin and origin in allowed_origins:
                    response.headers["access-control-allow-origin"] = origin
                    response.headers["access-control-allow-methods"] = "GET, POST, PUT, DELETE, OPTIONS"
                    response.headers["access-control-allow-headers"] = "Content-Type, Authorization, Accept, X-Request-ID, X-RP-Skip-Refresh"
                    response.headers["access-control-allow-credentials"] = "true"
                    response.headers["access-control-max-age"] = "600"
                return response
        
        # For non-OPTIONS requests, proceed normally
        # But ensure CORS headers are added to all responses
        response = await call_next(request)
        
        # Ensure CORS headers are present on all responses (not just OPTIONS)
        # This is a safety net in case CORSMiddleware doesn't add them
        origin = request.headers.get("origin")
        allowed_origins = ["http://localhost:5173", "http://127.0.0.1:5173", "https://www.dattapay.com", "https://app.dattapay.com"]
        if origin and origin in allowed_origins:
            # Only add if not already present (CORSMiddleware should have added them)
            if "access-control-allow-origin" not in response.headers:
                response.headers["access-control-allow-origin"] = origin
            if "access-control-allow-credentials" not in response.headers:
                response.headers["access-control-allow-credentials"] = "true"
        
        return response

