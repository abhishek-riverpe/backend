import logging
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.sessions import SessionMiddleware
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from .core.config import settings
from .core.database import prisma
from .routers import google_oauth, auth_routes, zync, transformer, webhooks, kyc_router, funding_account_router, otp_router, captcha_routes
from .middleware import RequestSizeLimitMiddleware, ActivityTimeoutMiddleware, SecurityHeadersMiddleware, RequestIDMiddleware

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI()

# FIXED: HIGH-04 - Rate limiting setup to prevent resource exhaustion
# Initialize rate limiter using IP address as the key
limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# MED-05: Request ID middleware for audit trail tracking
# PCI DSS 4.0.1 Requirement 10.2: Detailed audit log trail for all system components
app.add_middleware(RequestIDMiddleware)

# ✅ Security headers middleware (adds security headers to all responses)
app.add_middleware(SecurityHeadersMiddleware)

# ✅ Request size limit (rejects > configured MB)
app.add_middleware(RequestSizeLimitMiddleware)

# ✅ Session inactivity timeout enforcement for authenticated requests
app.add_middleware(ActivityTimeoutMiddleware)

# ✅ CORS setup - FIXED: HIGH-06 - Restrictive CORS configuration
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
    allow_methods=["GET", "POST", "PUT", "DELETE"],  # Explicit list - no wildcards
    allow_headers=[
        "Content-Type",
        "Authorization",
        "Accept",
        "X-Request-ID",  # For request tracking (if used)
    ],  # Explicit list - no wildcards
    max_age=600,  # Cache preflight requests for 10 minutes
)


# ✅ Session middleware with secure cookie settings
# SECURITY: Uses separate session_secret (not jwt_secret) to prevent single point of failure
# FIXED: HIGH-03 - Always enforce HTTPS for cookies to prevent session hijacking
app.add_middleware(
    SessionMiddleware,
    secret_key=settings.session_secret,  # Separate secret from JWT to prevent token forgery
    session_cookie="riverpe_session",
    same_site="lax",    # allows redirect from Google back to your backend
    https_only=True,    # ALWAYS enforce HTTPS - required for PCI DSS 4.0.1 Requirement 4.2.1
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

@app.get("/")
def read_root():
    return {"message": "NeoBank API is running"}
