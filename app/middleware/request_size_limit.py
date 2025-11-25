from fastapi import Request, HTTPException
from starlette.middleware.base import BaseHTTPMiddleware

from ..core.config import settings

# Request size limit in bytes
MAX_REQUEST_SIZE = settings.max_request_size_mb * 1024 * 1024


class RequestSizeLimitMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        # Skip size check for OPTIONS preflight requests (they have no body)
        if request.method == "OPTIONS":
            return await call_next(request)
        
        content_length = request.headers.get("content-length")
        try:
            if content_length and int(content_length) > MAX_REQUEST_SIZE:
                raise HTTPException(status_code=413, detail="Request too large")
        except ValueError:
            # Non-integer or malformed header; proceed to next handler
            pass
        return await call_next(request)

