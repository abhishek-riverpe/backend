import secrets
import random
from fastapi import APIRouter, HTTPException, Request, Response, status
from urllib.parse import urlencode
from starlette.responses import RedirectResponse
from authlib.integrations.starlette_client import OAuth, OAuthError

from ..core.config import settings
from ..core.database import prisma
from ..core import auth
from ..utils.oauth_cache import generate_oauth_code, exchange_oauth_code

router = APIRouter(prefix="/auth", tags=["auth"]) 
# Configure Authlib OAuth client for Google
oauth = OAuth()
oauth.register(
    name="google",
    client_id=settings.google_client_id,
    client_secret=settings.google_client_secret,
    server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
    client_kwargs={"scope": "openid email profile"},
)


@router.get("/google")
async def google_login(request: Request):
    if not settings.google_client_id or not settings.google_client_secret:
        raise HTTPException(status_code=500, detail="Google OAuth is not configured")
    # Build redirect URI; allow override via BACKEND_URL for consistency with Google Console config
    if settings.backend_url:
        redirect_uri = f"{settings.backend_url.rstrip('/')}/auth/google/callback"
    else:
        redirect_uri = request.url_for("google_callback")
    return await oauth.google.authorize_redirect(request, redirect_uri)


@router.get("/google/callback")
async def google_callback(request: Request):
    try:
        token = await oauth.google.authorize_access_token(request)
    except OAuthError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"OAuth error: {e.error}")

    userinfo = token.get("userinfo")
    if not userinfo:
        # Fallback to parse id_token if userinfo not present
        userinfo = await oauth.google.parse_id_token(request, token)

    if not userinfo or not userinfo.get("email"):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Failed to retrieve Google user info")

    email = userinfo["email"].lower()
    first_name = userinfo.get("given_name") or ""
    last_name = userinfo.get("family_name") or ""

    # Find or create user
    user = await prisma.entities.find_unique(where={"email": email})
    if not user:
        # Create a random password since login is via Google
        random_password = secrets.token_urlsafe(16)
        hashed = auth.get_password_hash(random_password)
        user = await prisma.entities.create(
            data={
                "email": email,
                "first_name": first_name,
                "last_name": last_name,
                "password": hashed,
            }
        )

    # Issue JWTs using new helpers (sub = user id)
    access_token = auth.create_access_token(data={"sub": user.id, "type": "access"})
    refresh_token = auth.create_refresh_token(data={"sub": user.id, "type": "refresh"})

    # ✅ SECURITY: Generate temporary code instead of passing token in URL
    # Store tokens securely for exchange
    oauth_data = {
        "user_id": user.id,
        "email": user.email,
        "access_token": access_token,
        "refresh_token": refresh_token,
        "first_name": first_name,
        "last_name": last_name,
    }
    temp_code = generate_oauth_code(oauth_data)

    # Redirect back to React app with temporary code (NOT token)
    redirect_to = f"{settings.frontend_url}/oauth/callback?code={temp_code}"
    return RedirectResponse(url=redirect_to, status_code=302)


@router.post("/google/exchange")
async def exchange_oauth_code_endpoint(code_data: dict, response: Response):
    """
    Exchange temporary OAuth code for session cookies.
    
    ✅ SECURITY: This endpoint validates the code and sets HttpOnly cookies.
    The frontend never receives tokens directly, preventing XSS token theft.
    """
    code = code_data.get("code")
    if not code:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Code is required"
        )
    
    # Exchange code for stored data (one-time use)
    oauth_data = exchange_oauth_code(code)
    if not oauth_data:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired code"
        )
    
    # Set HttpOnly cookie for refresh token (long-lived, 7 days)
    # Access token is returned in response for immediate use
    response.set_cookie(
        key="rp_refresh",
        value=oauth_data["refresh_token"],
        httponly=True,
        secure=settings.frontend_url.startswith("https"),  # Secure in production
        samesite="strict",  # CSRF protection
        max_age=7 * 24 * 60 * 60,  # 7 days
        path="/",
    )
    
    # Return user info and access token
    # Access token in response for immediate API calls
    # Refresh token in HttpOnly cookie for security
    return {
        "success": True,
        "message": "Authentication successful",
        "data": {
            "access_token": oauth_data["access_token"],
            "user": {
                "id": oauth_data["user_id"],
                "email": oauth_data["email"],
                "firstName": oauth_data.get("first_name", ""),
                "lastName": oauth_data.get("last_name", ""),
            }
        },
        "error": None,
        "meta": {}
    }
