import logging
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.sessions import SessionMiddleware
from .core.config import settings
from .core.database import db
from .routers import google_oauth, auth_routes, zync, transformer
from .middleware import RequestSizeLimitMiddleware

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI()

# ✅ Request size limit (rejects > configured MB)
app.add_middleware(RequestSizeLimitMiddleware)

# ✅ CORS setup (must include BOTH 5173 & 127.0.0.1 if needed)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "https://www.riverpe.com/",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
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
    await db.connect()
    logger.info("Successfully connected to the database")

@app.on_event("shutdown")
async def shutdown():
    if db.is_connected():
        await db.disconnect()

# Include routers
# app.include_router(google_oauth.router)
app.include_router(auth_routes.router)
app.include_router(zync.router)
# app.include_router(transformer.router)

@app.get("/")
def read_root():
    return {"message": "NeoBank API is running"}
