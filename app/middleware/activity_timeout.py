from starlette.middleware.base import BaseHTTPMiddleware
from fastapi import Request, status
from fastapi.responses import JSONResponse
from app.core.database import prisma
from app.services.session_service import SessionService
from app.core import auth


class ActivityTimeoutMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        if request.method == "OPTIONS":
            return await call_next(request)
        
        token = request.cookies.get("rp_access")
        if not token:
            auth_header = request.headers.get("authorization") or request.headers.get("Authorization")
            if auth_header and auth_header.lower().startswith("bearer "):
                token = auth_header.split(" ", 1)[1].strip()
        
        if token:
            try:
                payload = auth.verify_token_type(token, "access")
                service = SessionService(prisma)
                active = await service.enforce_and_update_activity(token)
                if active is False:
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
            except Exception:
                pass

        response = await call_next(request)
        return response

