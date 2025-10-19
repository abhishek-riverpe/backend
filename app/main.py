from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.sessions import SessionMiddleware
from .config import settings
from .database import db
from .routers import user, account, google_oauth
from .routers import auth_routes
from .middleware import RequestSizeLimitMiddleware

app = FastAPI()

# ✅ Request size limit (rejects > configured MB)
app.add_middleware(RequestSizeLimitMiddleware)

# ✅ CORS setup (must include BOTH 5173 & 127.0.0.1 if needed)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
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

@app.on_event("shutdown")
async def shutdown():
    if db.is_connected():
        await db.disconnect()

# Include routers
app.include_router(user.router)
app.include_router(account.router)
app.include_router(google_oauth.router)
app.include_router(auth_routes.router)

@app.get("/")
def read_root():
    return {"message": "NeoBank API is running"}
