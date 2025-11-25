import logging
from fastapi import FastAPI, Request, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.middleware.sessions import SessionMiddleware
from starlette.requests import Request as StarletteRequest
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from .core.config import settings
from .core.database import prisma
from .routers import google_oauth, auth_routes, zync, transformer, webhooks, kyc_router, funding_account_router, otp_router, captcha_routes, wallet_router
from .middleware import RequestSizeLimitMiddleware, ActivityTimeoutMiddleware, SecurityHeadersMiddleware, CORSOptionsHandlerMiddleware

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI()

# FIXED: HIGH-04 - Rate limiting setup to prevent resource exhaustion
# Initialize rate limiter using IP address as the key
limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Exception handler for HTTPException to ensure CORS headers are on error responses
@app.exception_handler(HTTPException)
async def http_exception_handler(request: StarletteRequest, exc: HTTPException):
    """
    HTTPException handler to ensure CORS headers are present on error responses.
    This prevents CORS errors when the backend throws HTTPExceptions.
    """
    response = JSONResponse(
        status_code=exc.status_code,
        content={
            "success": False,
            "message": exc.detail,
            "error": {"code": f"HTTP_{exc.status_code}", "details": exc.detail},
            "data": None,
            "meta": {},
        }
    )
    
    # Add CORS headers to error response
    origin = request.headers.get("origin")
    allowed_origins = ["http://localhost:5173", "http://127.0.0.1:5173", "https://www.dattapay.com", "https://app.dattapay.com"]
    if origin and origin in allowed_origins:
        response.headers["access-control-allow-origin"] = origin
        response.headers["access-control-allow-credentials"] = "true"
    
    return response

# Global exception handler to ensure CORS headers are on all error responses
@app.exception_handler(Exception)
async def global_exception_handler(request: StarletteRequest, exc: Exception):
    """
    Global exception handler to ensure CORS headers are present on all error responses.
    This prevents CORS errors when the backend throws exceptions.
    """
    import traceback
    logger.error(f"Unhandled exception: {exc}", exc_info=True)
    
    # Create error response
    response = JSONResponse(
        status_code=500,
        content={
            "success": False,
            "message": "Internal server error",
            "error": {"code": "INTERNAL_ERROR", "details": str(exc)},
            "data": None,
            "meta": {},
        }
    )
    
    # Add CORS headers to error response
    origin = request.headers.get("origin")
    allowed_origins = ["http://localhost:5173", "http://127.0.0.1:5173", "https://www.dattapay.com", "https://app.dattapay.com"]
    if origin and origin in allowed_origins:
        response.headers["access-control-allow-origin"] = origin
        response.headers["access-control-allow-credentials"] = "true"
    
    return response

# ✅ CORS setup - MUST be first to handle OPTIONS preflight requests
# FIXED: HIGH-06 - Restrictive CORS configuration
# FIXED: HIGH-06 - Explicit allow-lists for methods and headers to reduce attack surface
# PCI DSS 4.0.1 Requirement 6.4.3: Only allow scripts/requests from allow-listed domains
# Note: CORSMiddleware automatically handles OPTIONS requests
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",      # Local development (Vite)
        "http://127.0.0.1:5173",      # Local development (alternative)
        "https://www.dattapay.com",    # Production app (if separate subdomain)
        "https://app.dattapay.com",    # Production app (if separate subdomain)
    ],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],  # Explicit list - OPTIONS required for CORS preflight
    allow_headers=[
        "Content-Type",
        "Authorization",
        "Accept",
        "X-Request-ID",  # For request tracking (if used)
        "X-RP-Skip-Refresh",  # Custom header to skip token refresh on auth endpoints
    ],  # Explicit list - no wildcards
    max_age=600,  # Cache preflight requests for 10 minutes
    expose_headers=["*"],  # Allow all response headers to be exposed
)

# ✅ OPTIONS handler middleware - placed AFTER CORS to ensure OPTIONS always returns 200
# This is a safety net in case CORSMiddleware doesn't handle OPTIONS properly
app.add_middleware(CORSOptionsHandlerMiddleware)

# ✅ Security headers middleware (adds security headers to all responses)
app.add_middleware(SecurityHeadersMiddleware)

# ✅ Request size limit (rejects > configured MB)
app.add_middleware(RequestSizeLimitMiddleware)

# ✅ Session inactivity timeout enforcement for authenticated requests
app.add_middleware(ActivityTimeoutMiddleware)


# ✅ Session middleware with secure cookie settings
# SECURITY: Uses separate session_secret (not jwt_secret) to prevent single point of failure
# FIXED: HIGH-03 - Always enforce HTTPS for cookies to prevent session hijacking
# In development, allow HTTP for local testing; in production, enforce HTTPS
import os
is_development = os.getenv("ENVIRONMENT", "development").lower() == "development"
app.add_middleware(
    SessionMiddleware,
    secret_key=settings.session_secret,  # Separate secret from JWT to prevent token forgery
    session_cookie="riverpe_session",
    same_site="lax",    # allows redirect from Google back to your backend
    https_only=not is_development,    # Allow HTTP in dev, enforce HTTPS in production - required for PCI DSS 4.0.1 Requirement 4.2.1
)  

@app.on_event("startup")
async def startup():
    await prisma.connect()
    logger.info("Successfully connected to the database")

@app.on_event("shutdown")
async def shutdown():
    if prisma.is_connected():
        await prisma.disconnect()

# Include routers
app.include_router(google_oauth.router)
app.include_router(auth_routes.router)
app.include_router(zync.router)
app.include_router(transformer.router)  # Enable transformer router for KYC status endpoint
app.include_router(webhooks.router)
app.include_router(kyc_router.router)
app.include_router(otp_router.router)
app.include_router(funding_account_router.router)
app.include_router(captcha_routes.router)
app.include_router(wallet_router.router)

@app.get("/")
def read_root():
    return {"message": "NeoBank API is running"}
