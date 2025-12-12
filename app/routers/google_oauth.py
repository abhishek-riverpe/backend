import secrets
from fastapi import APIRouter, HTTPException, Request, Response, status
from starlette.responses import RedirectResponse
from authlib.integrations.starlette_client import OAuth, OAuthError # type: ignore

from ..core.config import settings
from ..core.database import prisma
from ..core import auth
from ..utils.oauth_cache import generate_oauth_code, exchange_oauth_code
from ..utils.errors import internal_error

router = APIRouter(prefix="/auth", tags=["auth"]) 
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
    if settings.backend_url:
        redirect_uri = f"{settings.backend_url.rstrip('/')}/auth/google/callback"
    else:
        redirect_uri = request.url_for("google_callback")
    return await oauth.google.authorize_redirect(request, redirect_uri)


@router.get("/google/callback")
async def google_callback(request: Request):
    try:
        token = await oauth.google.authorize_access_token(request)
    except OAuthError:
        raise internal_error(
            user_message="Authentication failed. Please try again.",
        )

    userinfo = token.get("userinfo")
    if not userinfo:
        # Fallback to parse id_token if userinfo not present
        userinfo = await oauth.google.parse_id_token(request, token)

    if not userinfo or not userinfo.get("email"):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Failed to retrieve Google user info")

    email = userinfo["email"].lower()
    first_name = userinfo.get("given_name") or ""
    last_name = userinfo.get("family_name") or ""

    user = await prisma.entities.find_unique(where={"email": email})
    if not user:
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

    access_token = auth.create_access_token(data={"sub": user.id, "type": "access"})
    refresh_token = auth.create_refresh_token(data={"sub": user.id, "type": "refresh"})

    oauth_data = {
        "user_id": user.id,
        "email": user.email,
        "access_token": access_token,
        "refresh_token": refresh_token,
        "first_name": first_name,
        "last_name": last_name,
    }
    temp_code = generate_oauth_code(oauth_data)

    redirect_to = f"{settings.frontend_url}/oauth/callback?code={temp_code}"
    return RedirectResponse(url=redirect_to, status_code=302)


@router.post("/google/exchange")
async def exchange_oauth_code_endpoint(code_data: dict, request: Request, response: Response):
    code = code_data.get("code")
    if not code:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Code is required"
        )
    
    oauth_data = exchange_oauth_code(code)
    if not oauth_data:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired code"
        )
    
    is_production = not settings.frontend_url.startswith("http://localhost")
    
    response.set_cookie(
        key="rp_access",
        value=oauth_data["access_token"],
        httponly=True,
        samesite="lax" if not is_production else "strict",
        secure=is_production,
        max_age=15 * 60,
        path="/",
    )
    
    response.set_cookie(
        key="rp_refresh",
        value=oauth_data["refresh_token"],
        httponly=True,
        samesite="lax" if not is_production else "strict",
        secure=is_production,
        max_age=24 * 60 * 60,
        path="/",
    )
    
    return {
        "success": True,
        "message": "Authentication successful",
        "data": {
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
