from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response
from ..core.config import settings


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        if request.method == "OPTIONS":
            return await call_next(request)
        
        response = await call_next(request)
        
        if request.url.hostname in ["localhost", "127.0.0.1"]:
            response.headers["Content-Security-Policy"] = "default-src 'self' 'unsafe-inline' 'unsafe-eval' http://localhost:* http://127.0.0.1:*"
        else:
            response.headers["Content-Security-Policy"] = "default-src 'self'"
        
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "geolocation=(self), microphone=(), camera=()"

        is_production = settings.frontend_url.startswith("https://")
        if is_production:
            response.headers["Cross-Origin-Embedder-Policy"] = "require-corp"
        
        response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
        
        if is_production:
            response.headers["Cross-Origin-Resource-Policy"] = "same-origin"

        return response

