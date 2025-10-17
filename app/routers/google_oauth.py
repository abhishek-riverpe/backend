import secrets
import random
from fastapi import APIRouter, HTTPException, Request, status
from urllib.parse import urlencode
from starlette.responses import RedirectResponse
from authlib.integrations.starlette_client import OAuth, OAuthError

from ..config import settings
from ..database import db
from .. import auth

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
    user = await db.user.find_unique(where={"username": email})
    if not user:
        # Create a random password since login is via Google
        random_password = secrets.token_urlsafe(16)
        hashed = auth.get_password_hash(random_password)
        user = await db.user.create(
            data={
                "username": email,
                "password_hash": hashed,
                "first_name": first_name,
                "last_name": last_name,
            }
        )

        # Also create an account like in signup flow
        await db.account.create(
            data={
                "userId": user.id,
                "balance": round(1 + random.random() * 9999, 2)
            }
        )

    # Issue JWTs using new helpers (sub = user id)
    access_token = auth.create_access_token(data={"sub": user.id, "type": "access"})
    refresh_token = auth.create_refresh_token(data={"sub": user.id, "type": "refresh"})

    # Redirect back to React app with token and basic profile info
    query = urlencode({
        "token": access_token,
        "firstName": first_name or "",
        "lastName": last_name or "",
    })
    redirect_to = f"{settings.frontend_url}/oauth/callback?{query}"
    resp = RedirectResponse(url=redirect_to, status_code=302)
    resp.set_cookie(
        key="rp_refresh",
        value=refresh_token,
        httponly=True,
        samesite="lax",
        secure=False,
        max_age=30 * 24 * 60 * 60,
        path="/",
    )
    return resp
