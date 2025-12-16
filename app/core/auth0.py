"""
Auth0 JWT verification for FastAPI.

Verifies access tokens issued by Auth0 using RS256 and JWKS.
Provides JIT (Just-In-Time) user creation on first authenticated request.
"""

from datetime import datetime, timezone
from typing import Optional
import httpx
from fastapi import Depends, HTTPException, status, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import jwt, JWTError, ExpiredSignatureError
from functools import lru_cache

from .config import settings
from .database import prisma


# Use HTTPBearer for Authorization: Bearer <token> header
auth0_scheme = HTTPBearer(auto_error=False)

# Cache for JWKS keys
_jwks_cache: dict = {}
_jwks_cache_time: Optional[datetime] = None
JWKS_CACHE_TTL_SECONDS = 3600  # 1 hour


class Auth0Error(Exception):
    """Base exception for Auth0 errors."""
    pass


async def _fetch_jwks() -> dict:
    """Fetch JWKS from Auth0."""
    global _jwks_cache, _jwks_cache_time

    # Check cache
    now = datetime.now(timezone.utc)
    if _jwks_cache and _jwks_cache_time:
        age = (now - _jwks_cache_time).total_seconds()
        if age < JWKS_CACHE_TTL_SECONDS:
            return _jwks_cache

    if not settings.auth0_domain:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Auth0 domain not configured"
        )

    jwks_url = f"https://{settings.auth0_domain}/.well-known/jwks.json"

    try:
        async with httpx.AsyncClient(timeout=10) as client:
            response = await client.get(jwks_url)
            response.raise_for_status()
            _jwks_cache = response.json()
            _jwks_cache_time = now
            return _jwks_cache
    except httpx.RequestError as e:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Unable to fetch Auth0 JWKS"
        )


def _get_signing_key(jwks: dict, kid: str) -> dict:
    """Get the signing key from JWKS by key ID."""
    for key in jwks.get("keys", []):
        if key.get("kid") == kid:
            return key
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Unable to find appropriate key"
    )


async def verify_auth0_token(token: str) -> dict:
    """
    Verify an Auth0 access token.

    Returns the decoded payload if valid.
    Raises HTTPException if invalid.
    """
    if not settings.auth0_domain or not settings.auth0_audience:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Auth0 configuration incomplete"
        )

    try:
        # Get the key ID from token header (unverified)
        unverified_header = jwt.get_unverified_header(token)
        kid = unverified_header.get("kid")

        if not kid:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token missing key ID"
            )

        # Fetch JWKS and get signing key
        jwks = await _fetch_jwks()
        signing_key = _get_signing_key(jwks, kid)

        # Verify and decode token
        payload = jwt.decode(
            token,
            signing_key,
            algorithms=settings.auth0_algorithms,
            audience=settings.auth0_audience,
            issuer=f"https://{settings.auth0_domain}/"
        )

        return payload

    except ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token expired"
        )
    except JWTError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token"
        )


async def get_current_user(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(auth0_scheme)
):
    """
    FastAPI dependency to get the current authenticated user.

    - Verifies the Auth0 access token
    - Extracts auth0_sub (subject) from token
    - Performs JIT user creation if user doesn't exist
    - Returns the entity from database
    """
    if not credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = credentials.credentials
    payload = await verify_auth0_token(token)

    # Extract user identity from token
    auth0_sub = payload.get("sub")
    if not auth0_sub:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token: missing sub claim"
        )

    # Get email from token claims
    # Auth0 can include email in different places depending on configuration
    email = (
        payload.get("email") or
        payload.get(f"{settings.auth0_audience}/email") or
        payload.get("https://riverpe.com/email")  # Custom claim namespace
    )
    email_verified = payload.get("email_verified", False)

    # Look up user by auth0_sub
    entity = await prisma.entities.find_unique(where={"auth0_sub": auth0_sub})

    if entity:
        # Update last login time
        entity = await prisma.entities.update(
            where={"id": entity.id},
            data={"last_login_at": datetime.now(timezone.utc)}
        )
        return entity

    # JIT user creation - user doesn't exist yet
    if not email:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email not provided in token. Please ensure email scope is requested."
        )

    # Check if email already exists (edge case: user registered with different auth method)
    existing_by_email = await prisma.entities.find_unique(where={"email": email})
    if existing_by_email:
        # Link Auth0 sub to existing account
        entity = await prisma.entities.update(
            where={"id": existing_by_email.id},
            data={
                "auth0_sub": auth0_sub,
                "email_verified": email_verified,
                "last_login_at": datetime.now(timezone.utc)
            }
        )
        return entity

    # Create new entity with REGISTERED status
    entity = await prisma.entities.create(
        data={
            "auth0_sub": auth0_sub,
            "email": email,
            "email_verified": email_verified,
            "status": "REGISTERED",
            "last_login_at": datetime.now(timezone.utc)
        }
    )

    return entity


async def get_current_user_optional(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(auth0_scheme)
):
    """
    Optional authentication - returns None if no valid token provided.
    Useful for endpoints that work differently for authenticated vs anonymous users.
    """
    if not credentials:
        return None

    try:
        return await get_current_user(request, credentials)
    except HTTPException:
        return None
