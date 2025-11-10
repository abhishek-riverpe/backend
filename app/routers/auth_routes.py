from fastapi import APIRouter, HTTPException, status, Response, Request
from datetime import datetime, timedelta, timezone
from ..core import auth
from ..core.database import db
from .. import schemas
from prisma.errors import UniqueViolationError, PrismaError
from passlib.context import CryptContext

# from prisma.models import entities  # prisma python generates models from schema
from .security import (
    normalize_email,
    validate_password,
    hash_password,
)

MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_MINUTES = 15

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
router = APIRouter(
    prefix="/api/v1/auth",
    tags=["auth"],
)

# Return unified response with tokens + user
@router.post("/signup", response_model=schemas.AuthResponse, status_code=status.HTTP_201_CREATED)
async def signup(user_in: schemas.UserCreate, response: Response):
    """
    Create a new entity (user) with username, email, password.
    Returns access & refresh tokens and sets refresh token as HttpOnly cookie.
    """
    first_name = user_in.first_name.strip()
    last_name = user_in.last_name.strip()
    email = normalize_email(user_in.email)
    password = user_in.password
    print(f"Signup request: first_name={first_name}, last_name={last_name}, email={email}, password={password}")

    # Validate semantics
    try:
        validate_password(password)
    except ValueError as ve:
        # 400 for client input that fails our policy
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(ve))

    # Hash password
    pwd_hash = hash_password(password)

    # Pre-check for duplicates (nice UX), but still handle race with try/except below
    # if await db.entities.find_first(where={"OR": [{"username": user_in.name}, {"email": email}]}):
        # Distinguish which one collided (not strictly necessary)
        # existing_username = await db.entities.find_unique(where={"username": name})
        # if existing_username:
        #     raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Username already in use")
        # raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Email already registered")
    if await db.entities.find_first(where={"email": email}):
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Email already registered")

    # Create user in a transaction to keep things consistent
    try:
        async with db.tx() as tx:
            entity = await tx.entities.create(
                data={
                    # "username": name,
                    "email": email,
                    # Store the hash. If your model is still `password`, set "password": pwd_hash
                    "password": pwd_hash,
                    # Optionally copy username into display name at first registration
                    "first_name": first_name,
                    "last_name": last_name,
                    # status defaults to PENDING; you can keep it until email verification finishes
                    # created_at/updated_at default to now()
                }
            )

    except UniqueViolationError:
        # Race condition safety: DB unique constraint fired despite pre-check
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Email already exists")

    # Tokens (subject should be a stable unique id)
    access_token = auth.create_access_token(data={"sub": str(entity.entity_id), "type": "access"})
    refresh_token = auth.create_refresh_token(data={"sub": str(entity.entity_id), "type": "refresh"})

    # Set refresh cookie: secure defaults for banking
    response.set_cookie(
        key="rp_refresh",
        value=refresh_token,
        httponly=True,
        samesite="strict",   # stricter than lax for banking
        secure=True,         # must be True in production (HTTPS)
        max_age=24 * 60 * 60,  # 24 hours
        path="/",
    )

    # Optional: include Location header for the created resource
    response.headers["Location"] = f"/api/v1/entities/{entity.entity_id}"

    safe_user = {
        "entity_id": str(entity.entity_id) if hasattr(entity, "entity_id") else None,
        "external_entity_id": entity.external_entity_id if hasattr(entity, "external_entity_id") else None,
        "entity_type": str(entity.entity_type) if hasattr(entity, "entity_type") else None,
        "email": entity.email if hasattr(entity, "email") else None,
        "first_name": entity.first_name if hasattr(entity, "first_name") else None,
        "last_name": entity.last_name if hasattr(entity, "last_name") else None,
        "email_verified": entity.email_verified if hasattr(entity, "email_verified") else None,
        "last_login_at": entity.last_login_at.isoformat() if getattr(entity, "last_login_at", None) else None,
        "login_attempts": entity.login_attempts if hasattr(entity, "login_attempts") else None,
        "locked_until": entity.locked_until.isoformat() if getattr(entity, "locked_until", None) else None,
        "status": str(entity.status) if hasattr(entity, "status") else None,
        "created_at": entity.created_at.isoformat() if getattr(entity, "created_at", None) else None,
        "updated_at": entity.updated_at.isoformat() if getattr(entity, "updated_at", None) else None,
    }

    print(f"Signup response: access_token={access_token}, refresh_token={refresh_token}, user={safe_user}")

    return {
        "success": True,
        "message": "Signup successful",
        "data": {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "bearer",
            "user": safe_user,
        },
        "error": None,
        "meta": {},
    }

@router.post("/signin", response_model=schemas.AuthResponse, status_code=status.HTTP_200_OK)
async def signin(payload: schemas.SignInInput, response: Response):
    """
    Authenticate an entity using email + password.
    - Returns access & refresh tokens.
    - Sets refresh token as HttpOnly cookie.
    - Enforces account lockout after repeated failures.
    - Requires email_verified (tweak as needed).
    """

    # email = payload.email.strip()
    email = normalize_email(payload.email)
    password = payload.password

    # Fetch entity by exact email match (you chose not to lowercase)
    user = await db.entities.find_unique(where={"email": email})

    # Uniform error for nonexistent users (avoid user enumeration)
    def invalid_credentials():
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
        )

    # If no user, do NOT reveal which part failed
    if not user:
        invalid_credentials()

    # Check locked state
    now = datetime.now(timezone.utc)
    if user.locked_until and user.locked_until > now:
        # 423 Locked with Retry-After-ish hint
        remaining = int((user.locked_until - now).total_seconds())
        # Optional header; clients can use it for UX
        response.headers["X-Account-Unlock-In"] = str(remaining)
        raise HTTPException(
            status_code=status.HTTP_423_LOCKED,
            detail="Account locked due to multiple failed attempts. Try again later.",
        )

    # (Optional) Require verified email before login
    # if user.email_verified is not True:
    #     raise HTTPException(
    #         status_code=status.HTTP_403_FORBIDDEN,
    #         detail="Email not verified",
    #     )

    # (Optional) Enforce allowed statuses
    # if str(user.status).upper() in {"SUSPENDED", "BLOCKED", "DEACTIVATED"}:
    #     raise HTTPException(
    #         status_code=status.HTTP_403_FORBIDDEN,
    #         detail="Account is not allowed to sign in",
    #     )

    # Verify password (your `password` column stores the hash)
    try:
        ok = pwd_context.verify(password, user.password)
    except Exception:
        # Any verification error should be treated as invalid creds
        ok = False

    if not ok:
        # Increment attempts; lock if threshold reached
        attempts = (user.login_attempts or 0) + 1
        lock_until = None
        detail = "Invalid email or password"

        if attempts >= MAX_LOGIN_ATTEMPTS:
            lock_until = now + timedelta(minutes=LOCKOUT_MINUTES)
            detail = "Account locked due to multiple failed attempts. Try again later."

        try:
            await db.entities.update(
                where={"entity_id": user.entity_id},
                data={
                    "login_attempts": attempts,
                    "locked_until": lock_until,
                    "updated_at": now,
                },
            )
        except PrismaError:
            # Do not leak DB errors; still respond with auth error
            pass

        if lock_until:
            response.headers["X-Account-Unlock-In"] = str(int((lock_until - now).total_seconds()))
            raise HTTPException(status_code=status.HTTP_423_LOCKED, detail=detail)

        invalid_credentials()

    # Success: reset attempts, clear lock, update last_login_at
    try:
        await db.entities.update(
            where={"entity_id": user.entity_id},
            data={
                "login_attempts": 0,
                "locked_until": None,
                "last_login_at": now,
                "updated_at": now,
            },
        )
    except PrismaError:
        # Non-fatal; continue issuing tokens
        pass

    # Issue tokens
    access_token = auth.create_access_token(data={"sub": str(user.entity_id), "type": "access"})
    refresh_token = auth.create_refresh_token(data={"sub": str(user.entity_id), "type": "refresh"})

    # Set refresh cookie (banking defaults)
    response.set_cookie(
        key="rp_refresh",
        value=refresh_token,
        httponly=True,
        samesite="strict",
        secure=True,                 # keep True in prod (HTTPS)
        max_age=24 * 60 * 60,        # 24h, align with your refresh TTL policy
        path="/",
    )

    safe_user = {
        "entity_id": str(user.entity_id) if hasattr(user, "entity_id") else None,
        "external_entity_id": user.external_entity_id if hasattr(user, "external_entity_id") else None,
        "entity_type": str(user.entity_type) if hasattr(user, "entity_type") else None,
        "email": user.email if hasattr(user, "email") else None,
        "first_name": user.first_name if hasattr(user, "first_name") else None,
        "last_name": user.last_name if hasattr(user, "last_name") else None,
        "email_verified": user.email_verified if hasattr(user, "email_verified") else None,
        "last_login_at": user.last_login_at.isoformat() if getattr(user, "last_login_at", None) else None,
        "login_attempts": user.login_attempts if hasattr(user, "login_attempts") else None,
        "locked_until": user.locked_until.isoformat() if getattr(user, "locked_until", None) else None,
        "status": str(user.status) if hasattr(user, "status") else None,
        "created_at": user.created_at.isoformat() if getattr(user, "created_at", None) else None,
        "updated_at": user.updated_at.isoformat() if getattr(user, "updated_at", None) else None,
    }

    return {
        "success": True,
        "message": "Signin successful",
        "data": {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "bearer",
            "user": safe_user,
        },
        "error": None,
        "meta": {},
    }

@router.post("/refresh", response_model=schemas.AuthResponse)
async def refresh_token(request: Request, response: Response):
    """
    Issue a new access/refresh token pair using the HttpOnly refresh cookie.
    Returns unified response; sets a fresh refresh cookie.
    """
    rt = request.cookies.get("rp_refresh")
    if not rt:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing refresh token")

    # Validate refresh token
    payload = auth.verify_token_type(rt, "refresh")
    user_id = payload.get("sub")
    if not user_id:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token payload")

    user = await db.entities.find_unique(where={"entity_id": user_id})
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Entity not found")

    access_token = auth.create_access_token({"sub": str(user.entity_id), "type": "access"})
    refresh_token = auth.create_refresh_token({"sub": str(user.entity_id), "type": "refresh"})

    response.set_cookie(
        key="rp_refresh",
        value=refresh_token,
        httponly=True,
        samesite="strict",
        secure=True,
        max_age=24 * 60 * 60,
        path="/",
    )

    safe_user = {
        "entity_id": str(user.entity_id) if hasattr(user, "entity_id") else None,
        "external_entity_id": user.external_entity_id if hasattr(user, "external_entity_id") else None,
        "entity_type": str(user.entity_type) if hasattr(user, "entity_type") else None,
        "email": user.email if hasattr(user, "email") else None,
        "first_name": user.first_name if hasattr(user, "first_name") else None,
        "last_name": user.last_name if hasattr(user, "last_name") else None,
        "email_verified": user.email_verified if hasattr(user, "email_verified") else None,
        "last_login_at": user.last_login_at.isoformat() if getattr(user, "last_login_at", None) else None,
        "login_attempts": user.login_attempts if hasattr(user, "login_attempts") else None,
        "locked_until": user.locked_until.isoformat() if getattr(user, "locked_until", None) else None,
        "status": str(user.status) if hasattr(user, "status") else None,
        "created_at": user.created_at.isoformat() if getattr(user, "created_at", None) else None,
        "updated_at": user.updated_at.isoformat() if getattr(user, "updated_at", None) else None,
    }

    return {
        "success": True,
        "message": "Token refreshed",
        "data": {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "bearer",
            "user": safe_user,
        },
        "error": None,
        "meta": {},
    }

@router.post("/logout", response_model=schemas.ApiResponse)
async def logout(response: Response):
    """Clear the refresh cookie and return unified response."""
    response.delete_cookie("rp_refresh", path="/")
    return {
        "success": True,
        "message": "Logged out",
        "data": None,
        "error": None,
        "meta": {},
    }
    
