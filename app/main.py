import logging
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.sessions import SessionMiddleware
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from .core.config import settings
from .core.database import prisma
from .routers import google_oauth, auth_routes, zync, transformer, webhooks, kyc_router, funding_account_router, otp_router, captcha_routes, teleport_router, wallet_router, user_router
from .middleware import RequestSizeLimitMiddleware, ActivityTimeoutMiddleware, SecurityHeadersMiddleware, RequestIDMiddleware

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI()

limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",      
        "http://127.0.0.1:5173",      
        "https://www.dattapay.com",   
        "https://app.dattapay.com",   
    ],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"], 
    allow_headers=[
        "Content-Type",
        "Authorization",
        "Accept",
        "X-Request-ID",  
        "X-RP-Skip-Refresh", 
    ],  
    max_age=600,  
    expose_headers=["*"],
)


app.add_middleware(RequestIDMiddleware)
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(RequestSizeLimitMiddleware)
app.add_middleware(ActivityTimeoutMiddleware)

is_production = not settings.frontend_url.startswith("http://localhost")

app.add_middleware(
    SessionMiddleware,
    secret_key=settings.session_secret, 
    session_cookie="riverpe_session",
    same_site="lax",    
    https_only=is_production,
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
app.include_router(transformer.router) 
app.include_router(webhooks.router)
app.include_router(kyc_router.router)
app.include_router(otp_router.router)
app.include_router(funding_account_router.router)
app.include_router(captcha_routes.router)
app.include_router(teleport_router.router)
app.include_router(wallet_router.router)
app.include_router(user_router.router)

@app.get("/")
def read_root():
    return {"message": "NeoBank API is running"}

@app.get("/health")
async def health_check():
    return {"status": "healthy", "service": "RiverPe API"}

@app.get("/readiness")
async def readiness_check():
    try:
        if prisma.is_connected():
            await prisma.query_raw("SELECT 1")
            return {"status": "ready", "database": "connected"}
        else:
            return {"status": "not ready", "database": "disconnected"}, 503
    except Exception as e:
        logger.error(f"[HEALTH] Readiness check failed: {e}")
        return {"status": "not ready", "error": "Database check failed"}, 503

@app.get("/liveness")
async def liveness_check():
    return {"status": "alive", "service": "RiverPe API"}
