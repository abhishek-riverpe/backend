from fastapi import Request, HTTPException
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.datastructures import UploadFile

from ..core.config import settings

# Request size limit in bytes
MAX_REQUEST_SIZE = settings.max_request_size_mb * 1024 * 1024


class RequestSizeLimitMiddleware(BaseHTTPMiddleware):
    """
    LOW-03: Validates both Content-Length header and actual body size.
    Prevents attackers from sending a small Content-Length header but large body.
    """
    async def dispatch(self, request: Request, call_next):
        # First check Content-Length header
        content_length = request.headers.get("content-length")
        try:
            if content_length and int(content_length) > MAX_REQUEST_SIZE:
                raise HTTPException(status_code=413, detail="Request too large")
        except ValueError:
            # Non-integer or malformed header; proceed to body validation
            pass
        
        # Skip body validation for requests without a body (GET, HEAD, etc.)
        if request.method in ("GET", "HEAD", "OPTIONS"):
            return await call_next(request)
        
        # LOW-03: Validate actual body size by reading the body
        # This prevents attackers from sending a small Content-Length but large body
        try:
            body = await request.body()
            body_size = len(body)
            
            if body_size > MAX_REQUEST_SIZE:
                raise HTTPException(status_code=413, detail="Request body too large")
            
            # Reconstruct body for downstream handlers
            # Store original receive function
            original_receive = request._receive
            
            # Create a new receive function that returns the cached body
            # This allows FastAPI to read the body multiple times if needed
            body_sent = False
            async def receive():
                nonlocal body_sent
                if not body_sent:
                    body_sent = True
                    return {"type": "http.request", "body": body, "more_body": False}
                # After first call, return empty body to signal completion
                return {"type": "http.request", "body": b"", "more_body": False}
            
            # Replace the receive function
            request._receive = receive
        except RuntimeError:
            # Body already consumed, skip validation
            pass
        
        return await call_next(request)

