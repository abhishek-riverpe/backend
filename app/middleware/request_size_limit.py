from fastapi import Request, HTTPException
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import ClientDisconnect

from ..core.config import settings

MAX_REQUEST_SIZE = settings.max_request_size_mb * 1024 * 1024


class RequestSizeLimitMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        content_length = request.headers.get("content-length")
        try:
            if content_length and int(content_length) > MAX_REQUEST_SIZE:
                raise HTTPException(status_code=413, detail="Request too large")
        except ValueError:
            pass
        
        if request.method in ("GET", "HEAD", "OPTIONS"):
            return await call_next(request)
        
        try:
            body = await request.body()
            body_size = len(body)
            
            if body_size > MAX_REQUEST_SIZE:
                raise HTTPException(status_code=413, detail="Request body too large")
            
            body_sent = False
            async def receive():
                nonlocal body_sent
                if not body_sent:
                    body_sent = True
                    return {"type": "http.request", "body": body, "more_body": False}
                return {"type": "http.request", "body": b"", "more_body": False}
            
            request._receive = receive
        except ClientDisconnect:
            raise
        except RuntimeError:
            pass
        
        return await call_next(request)

