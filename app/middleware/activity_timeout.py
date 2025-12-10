from starlette.middleware.base import BaseHTTPMiddleware
from fastapi import Request, HTTPException, status
from fastapi.responses import JSONResponse
from app.core.database import prisma
from app.services.session_service import SessionService
from app.core import auth
import logging

logger = logging.getLogger(__name__)


class ActivityTimeoutMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        # Skip activity check for OPTIONS preflight requests
        if request.method == "OPTIONS":
            return await call_next(request)
        
        # Only enforce for requests with access token (from cookie or Authorization header)
        # Try cookie first (secure method), then fallback to Authorization header
        token = request.cookies.get("rp_access")
        if not token:
            auth_header = request.headers.get("authorization") or request.headers.get("Authorization")
            if auth_header and auth_header.lower().startswith("bearer "):
                token = auth_header.split(" ", 1)[1].strip()
        
        if token:
            try:
                # If token valid, enforce inactivity on this session token
                service = SessionService(prisma)
                active = await service.enforce_and_update_activity(token)
                # active == True  -> session updated and valid
                # active == False -> session found but expired
                # active == None  -> no session record found or error; skip enforcement
                if active is False:
                    logger.info("[MIDDLEWARE] Session expired due to inactivity for token (prefix): %s", token[:16])
                    return JSONResponse(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        content={
                            "success": False,
                            "message": "Session expired due to inactivity",
                            "data": None,
                            "error": {"code": "SESSION_EXPIRED", "message": "Session expired due to inactivity"},
                            "meta": {},
                        },
                    )
            except Exception as e:
                # If token invalid, let downstream auth handlers decide
                logger.debug(f"[MIDDLEWARE] Activity check skipped: {e}")

        response = await call_next(request)
        return response

