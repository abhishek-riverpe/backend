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

# ✅ CORS setup - Allowing all origins for development
# For React Native/Expo development, this is the simplest approach
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "https://www.riverpe.com",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ✅ Session middleware with secure cookie settings
# SECURITY: Uses separate session_secret (not jwt_secret) to prevent single point of failure
app.add_middleware(
    SessionMiddleware,
    secret_key=settings.session_secret,  # Separate secret from JWT to prevent token forgery
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
app.include_router(transformer.router)  # Enable transformer router for KYC status endpoint
app.include_router(webhooks.router)
app.include_router(kyc_router.router)
app.include_router(otp_router.router)
app.include_router(funding_account_router.router)
app.include_router(captcha_routes.router)

@app.get("/")
def read_root():
    return {"message": "NeoBank API is running"}
