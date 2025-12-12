from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response


class CORSOptionsHandlerMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        if request.method == "OPTIONS":
            try:
                response = await call_next(request)
                if response.status_code != 200:
                    response.status_code = 200
                origin = request.headers.get("origin")
                allowed_origins = ["http://localhost:5173", "http://127.0.0.1:5173", "https://www.dattapay.com", "https://app.dattapay.com"]
                if origin and origin in allowed_origins:
                    response.headers["access-control-allow-origin"] = origin
                    response.headers["access-control-allow-methods"] = "GET, POST, PUT, DELETE, OPTIONS"
                    response.headers["access-control-allow-headers"] = "Content-Type, Authorization, Accept, X-Request-ID, X-RP-Skip-Refresh"
                    response.headers["access-control-allow-credentials"] = "true"
                    response.headers["access-control-max-age"] = "600"
                return response
            except Exception:
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
        
        response = await call_next(request)
        
        origin = request.headers.get("origin")
        allowed_origins = ["http://localhost:5173", "http://127.0.0.1:5173", "https://www.dattapay.com", "https://app.dattapay.com"]
        if origin and origin in allowed_origins:
            if "access-control-allow-origin" not in response.headers:
                response.headers["access-control-allow-origin"] = origin
            if "access-control-allow-credentials" not in response.headers:
                response.headers["access-control-allow-credentials"] = "true"
        
        return response

