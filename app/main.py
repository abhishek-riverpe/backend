import logging
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.sessions import SessionMiddleware
from .core.config import settings
from .core.database import prisma
from .routers import google_oauth, auth_routes, zync, transformer, webhooks, kyc_router, funding_account_router, otp_router, captcha_routes
from .middleware import RequestSizeLimitMiddleware, ActivityTimeoutMiddleware, SecurityHeadersMiddleware

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI()

# ✅ Security headers middleware (adds security headers to all responses)
app.add_middleware(SecurityHeadersMiddleware)

# ✅ Request size limit (rejects > configured MB)
app.add_middleware(RequestSizeLimitMiddleware)

# ✅ Session inactivity timeout enforcement for authenticated requests
app.add_middleware(ActivityTimeoutMiddleware)

# ✅ CORS setup - Production-ready with explicit allowlist
# Parse CORS origins from config (support both string and list)
cors_origins_list = (
    settings.cors_origins.split(",") if isinstance(settings.cors_origins, str)
    else settings.cors_origins
)
# Strip whitespace from each origin
cors_origins_list = [origin.strip() for origin in cors_origins_list]

app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins_list,
    allow_credentials=settings.cors_allow_credentials,
    allow_methods=["GET", "POST", "OPTIONS"],  # Explicit whitelist - only methods actually used
    allow_headers=[
        "Authorization",
        "Content-Type",
        "Accept",
        "X-Requested-With",
        "X-RP-Skip-Refresh",  # Custom header for token refresh
        # Device information headers (used by mobile app and middleware)
        "X-Device-Type",
        "X-Device-Name",
        "X-OS-Name",
        "X-OS-Version",
        "X-Browser-Name",
        "X-Browser-Version",
        "X-App-Version",
        # Location headers (optional, used by location service)
        "X-User-Latitude",
        "X-User-Longitude",
        "X-User-City",
        "X-User-Country",
        # Standard browser headers
        "User-Agent",
        "Content-Length",
    ],
    max_age=settings.cors_max_age,  # Cache preflight requests
)


# ✅ Session middleware with secure cookie settings
app.add_middleware(
    SessionMiddleware,
    secret_key=settings.jwt_secret,  # or use settings.secret_key if you have one
    session_cookie="riverpe_session",
    same_site="lax",    # allows redirect from Google back to your backend
    https_only=False,   # True in production with HTTPS
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
# app.include_router(google_oauth.router)
app.include_router(auth_routes.router)
app.include_router(zync.router)
# app.include_router(transformer.router)
app.include_router(webhooks.router)
app.include_router(kyc_router.router)
app.include_router(otp_router.router)
app.include_router(funding_account_router.router)
app.include_router(captcha_routes.router)

@app.get("/")
def read_root():
    return {"message": "NeoBank API is running"}
