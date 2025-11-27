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
        
        # LOW-03: Validate actual body size by reading in chunks
        # This prevents attackers from sending a small Content-Length but large body
        body_size = 0
        body_chunks = []
        
        # Read body stream in chunks
        async for chunk in request.stream():
            body_size += len(chunk)
            if body_size > MAX_REQUEST_SIZE:
                raise HTTPException(status_code=413, detail="Request body too large")
            body_chunks.append(chunk)
        
        # Reconstruct body for downstream handlers
        if body_chunks:
            body = b"".join(body_chunks)
            # Replace the receive function to return the body we just read
            async def receive():
                return {"type": "http.request", "body": body}
            request._receive = receive
        
        return await call_next(request)

