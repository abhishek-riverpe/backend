"""
Request ID Middleware - MED-05
Adds request ID to all requests for audit trail tracking.
PCI DSS 4.0.1 Requirement 10.2: Detailed audit log trail for all system components
"""
import uuid
import logging
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request

logger = logging.getLogger(__name__)


class RequestIDMiddleware(BaseHTTPMiddleware):
    """
    MED-05: Adds request ID to all requests for audit trail tracking.
    Generates a unique request ID for each request and includes it in:
    - Request state (for use in handlers)
    - Response headers (X-Request-ID)
    - Log messages
    """
    async def dispatch(self, request: Request, call_next):
        # Get request ID from header or generate new one
        request_id = request.headers.get("X-Request-ID") or str(uuid.uuid4())
        request.state.request_id = request_id

        # Log request with ID
        logger.info(f"[REQUEST] {request.method} {request.url.path} [ID: {request_id}]")

        response = await call_next(request)
        response.headers["X-Request-ID"] = request_id
        return response

