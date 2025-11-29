from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response
from ..core.config import settings


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """
    Middleware to add security headers to all HTTP responses.
    Implements OWASP-recommended security headers for banking applications.
    """
    
    async def dispatch(self, request: Request, call_next):
        # ✅ Skip security headers for OPTIONS preflight requests (CORS handles these)
        if request.method == "OPTIONS":
            return await call_next(request)
        
        response = await call_next(request)
        
        # Content-Security-Policy: Prevents XSS attacks by controlling resource loading
        # Relaxed for development to allow localhost connections
        if request.url.hostname in ["localhost", "127.0.0.1"]:
            response.headers["Content-Security-Policy"] = "default-src 'self' 'unsafe-inline' 'unsafe-eval' http://localhost:* http://127.0.0.1:*"
        else:
            response.headers["Content-Security-Policy"] = "default-src 'self'"
        
        # X-Frame-Options: Prevents clickjacking by blocking iframe embedding
        response.headers["X-Frame-Options"] = "DENY"
        
        # X-Content-Type-Options: Prevents MIME type sniffing
        response.headers["X-Content-Type-Options"] = "nosniff"
        
        # Strict-Transport-Security (HSTS): Forces HTTPS connections
        # max-age=31536000 = 1 year, includeSubDomains applies to all subdomains
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        
        # X-XSS-Protection: Legacy XSS protection (still useful for older browsers)
        response.headers["X-XSS-Protection"] = "1; mode=block"
        
        # Referrer-Policy: Controls referrer information sent with requests
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        
        # Permissions-Policy: Allows geolocation for location tracking (user permission required)
        # Blocks microphone and camera for banking security
        # geolocation=(self) allows same-origin access (frontend can request permission)
        response.headers["Permissions-Policy"] = "geolocation=(self), microphone=(), camera=()"

        # LOW-01: Cross-Origin isolation headers for enhanced security
        # Cross-Origin-Embedder-Policy: Requires cross-origin resources to explicitly opt-in
        # Note: COEP can break CORS in development, so we make it conditional
        is_production = settings.frontend_url.startswith("https://")
        if is_production:
            response.headers["Cross-Origin-Embedder-Policy"] = "require-corp"
        
        # Cross-Origin-Opener-Policy: Isolates browsing context to same-origin
        response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
        
        # Cross-Origin-Resource-Policy: Restricts resource loading to same-origin
        # CORS FIX: Only set in production to avoid blocking CORS requests in development
        # In development, this header blocks cross-origin requests even with CORS configured
        if is_production:
            response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
        # In development, don't set CORP to allow CORS to work properly

        return response

