import logging
from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.middleware.sessions import SessionMiddleware
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.responses import Response
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from .core.config import settings
from .core.database import prisma
from .routers import google_oauth, auth_routes, zync, transformer, webhooks, kyc_router, funding_account_router, otp_router, captcha_routes, wallet_router
from .middleware import RequestSizeLimitMiddleware, ActivityTimeoutMiddleware, SecurityHeadersMiddleware

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI()

# FIXED: HIGH-04 - Rate limiting setup to prevent resource exhaustion
# Initialize rate limiter using IP address as the key
limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# ✅ CORS setup - MUST be FIRST middleware to handle preflight requests
# FIXED: HIGH-06 - Explicit allow-lists for methods and headers to reduce attack surface
# PCI DSS 4.0.1 Requirement 6.4.3: Only allow scripts/requests from allow-listed domains
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",      # Local development (Vite)
        "http://127.0.0.1:5173",      # Local development (alternative)
        "https://www.riverpe.com",    # Production website
        "https://app.riverpe.com",    # Production app (if separate subdomain)
        "https://www.dattapay.com",    # Production app (if separate subdomain)
        "https://app.dattapay.com",    # Production app (if separate subdomain)
    ],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],  # ✅ OPTIONS required for CORS preflight
    allow_headers=[
        "Content-Type",
        "Authorization",
        "Accept",
        "X-Request-ID",  # For request tracking (if used)
        "X-RP-Skip-Refresh",  # ✅ Custom header to skip token refresh on auth endpoints
    ],  # Explicit list - no wildcards
    max_age=600,  # Cache preflight requests for 10 minutes
    expose_headers=["*"],  # Allow all response headers to be exposed
)

# ✅ Security headers middleware (adds security headers to all responses)
app.add_middleware(SecurityHeadersMiddleware)

# ✅ Request size limit (rejects > configured MB)
app.add_middleware(RequestSizeLimitMiddleware)

# ✅ Session inactivity timeout enforcement for authenticated requests
app.add_middleware(ActivityTimeoutMiddleware)


# ✅ Session middleware with secure cookie settings
# SECURITY: Uses separate session_secret (not jwt_secret) to prevent single point of failure
# FIXED: HIGH-03 - Enforce HTTPS for cookies in production, allow HTTP in development
is_production = not settings.frontend_url.startswith("http://localhost")
app.add_middleware(
    SessionMiddleware,
    secret_key=settings.session_secret,  # Separate secret from JWT to prevent token forgery
    session_cookie="riverpe_session",
    same_site="lax",    # allows redirect from Google back to your backend
    https_only=is_production,  # True in production (HTTPS), False in development (HTTP)
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


# ✅ Global exception handlers to ensure CORS headers are always present on error responses
async def add_cors_headers_to_response(request: Request, response: Response):
    """Add CORS headers to response for allowed origins"""
    origin = request.headers.get("origin")
    allowed_origins = [
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "https://www.riverpe.com",
        "https://app.riverpe.com",
        "https://www.dattapay.com",
        "https://app.dattapay.com",
    ]
    if origin and origin in allowed_origins:
        response.headers["Access-Control-Allow-Origin"] = origin
        response.headers["Access-Control-Allow-Credentials"] = "true"
        response.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS"
        response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization, Accept, X-Request-ID, X-RP-Skip-Refresh"
        response.headers["Access-Control-Max-Age"] = "600"


@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(request: Request, exc: StarletteHTTPException):
    """Handle HTTP exceptions and ensure CORS headers are present"""
    response = JSONResponse(
        status_code=exc.status_code,
        content={"success": False, "message": exc.detail, "error": {"code": exc.status_code, "details": exc.detail}},
    )
    await add_cors_headers_to_response(request, response)
    return response


@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    """Handle general exceptions and ensure CORS headers are present"""
    logger.error(f"Unhandled exception: {exc}", exc_info=True)
    response = JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"success": False, "message": "Internal Server Error", "error": {"code": 500, "details": str(exc)}},
    )
    await add_cors_headers_to_response(request, response)
    return response
