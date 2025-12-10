from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

ALLOWED_ORIGINS = {
    "http://localhost:5173",
    "http://127.0.0.1:5173",
    "https://www.dattapay.com",
    "https://app.dattapay.com",
}

CORS_HEADERS = {
    "access-control-allow-methods": "GET, POST, PUT, DELETE, OPTIONS",
    "access-control-allow-headers": (
        "Content-Type, Authorization, Accept, X-Request-ID, X-RP-Skip-Refresh"
    ),
    "access-control-allow-credentials": "true",
    "access-control-max-age": "600",
}


class CORSRewriteMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        origin = request.headers.get("origin")
        is_allowed = origin in ALLOWED_ORIGINS

        # --- Fast-path for preflight requests ---
        if request.method == "OPTIONS":
            response = Response(status_code=200)
            if is_allowed:
                response.headers["access-control-allow-origin"] = origin
                response.headers.update(CORS_HEADERS)
            return response

        # --- Normal request flow ---
        response = await call_next(request)

        # Safety-net: ensure CORS headers exist if origin is allowed
        if is_allowed:
            response.headers.setdefault("access-control-allow-origin", origin)
            response.headers.setdefault("access-control-allow-credentials", "true")

        return response
