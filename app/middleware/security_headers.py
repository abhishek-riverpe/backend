from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """
    Middleware to add security headers to all HTTP responses.
    Implements OWASP-recommended security headers for banking applications.
    """
    
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        
        # Content-Security-Policy: Prevents XSS attacks by controlling resource loading
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
        
        # Permissions-Policy: Disables access to sensitive browser features
        # Blocks geolocation, microphone, and camera for banking security
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
        
        return response

