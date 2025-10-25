from fastapi import APIRouter, HTTPException, status, Response, Request
from datetime import datetime, timedelta, timezone
from .. import auth, schemas
from ..database import db
from prisma.errors import UniqueViolationError, PrismaError
from passlib.context import CryptContext

# from prisma.models import entities  # prisma python generates models from schema
from .security import (
    normalize_username, normalize_email,
    validate_username, validate_password,
    hash_password,
)

MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_MINUTES = 15

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
router = APIRouter(
    prefix="/api/v1/auth",
    tags=["auth"],
)

@router.post("/signup", response_model=schemas.Token, status_code=status.HTTP_201_CREATED)
async def signup(user_in: schemas.UserCreate, response: Response):
    """
    Create a new entity (user) with username, email, password.
    Returns access & refresh tokens and sets refresh token as HttpOnly cookie.
    """
    # Normalize inputs
    name = normalize_username(user_in.name)
    email = normalize_email(user_in.email)
    password = user_in.password

    # Validate semantics
    try:
        validate_username(name)
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
                    "name": user_in.name,
                    # status defaults to PENDING; you can keep it until email verification finishes
                    # created_at/updated_at default to now()
                }
            )

            # If you also create an account row, do it here.
            # Guard with try/except or check if `account` model exists.
            # await tx.account.create(data={"entityId": entity.entity_id, "balance": 0})

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

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
    }

@router.post("/signin", response_model=schemas.Token, status_code=status.HTTP_200_OK)
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

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
    }
    
# @router.post("/signup", response_model=schemas.Token)
# async def signup(user_in: schemas.entities, response: Response):
    # existing_user = await db.user.find_unique(where={"username": user_in.username})
    # if existing_user:
    #     raise HTTPException(
    #         status_code=status.HTTP_409_CONFLICT,
    #         detail="Email already registered",
    #     )

    # hashed_password = auth.get_password_hash(user_in.password)

    # user = await db.user.create(
    #     data={
    #         "username": user_in.username,
    #         "password_hash": hashed_password,
    #         "first_name": user_in.firstName,
    #         "last_name": user_in.lastName,
    #     }
    # )

    # await db.account.create(
    #     data={
    #         "userId": user.id,
    #         "balance": round(1 + random.random() * 9999, 2)
    #     }
    # )

    # access_token = auth.create_access_token(data={"sub": user.id, "type": "access"})
    # refresh_token = auth.create_refresh_token(data={"sub": user.id, "type": "refresh"})
    # # HttpOnly cookie for refresh token
    # response.set_cookie(
    #     key="rp_refresh",
    #     value=refresh_token,
    #     httponly=True,
    #     samesite="lax",
    #     secure=False,  # set True in production behind HTTPS
    #     max_age=30 * 24 * 60 * 60,
    #     path="/",
    # )
    # return {"access_token": access_token, "refresh_token": refresh_token, "token_type": "bearer"}


# @router.post("/signin", response_model=schemas.Token)
# async def signin(credentials: schemas.UserLogin, response: Response):
#     user = await db.user.find_unique(where={"username": credentials.username})
#     if not user or not auth.verify_password(credentials.password, user.password_hash):
#         raise HTTPException(
#             status_code=status.HTTP_401_UNAUTHORIZED,
#             detail="Incorrect username or password",
#             headers={"WWW-Authenticate": "Bearer"},
#         )

#     access_token = auth.create_access_token({"sub": user.id, "type": "access"})
#     refresh_token = auth.create_refresh_token({"sub": user.id, "type": "refresh"})
#     response.set_cookie(
#         key="rp_refresh",
#         value=refresh_token,
#         httponly=True,
#         samesite="lax",
#         secure=False,
#         max_age=30 * 24 * 60 * 60,
#         path="/",
#     )
#     return {"access_token": access_token, "refresh_token": refresh_token, "token_type": "bearer"}


# @router.post("/refresh", response_model=schemas.Token)
# async def refresh_token(request: Request, body: schemas.RefreshRequest | None = None, response: Response = None):
#     # Take refresh token from body or HttpOnly cookie
#     rt = (body.refresh_token if body else None) or request.cookies.get("rp_refresh")
#     if not rt:
#         raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing refresh token")
#     # Validate refresh token type and expiry; no DB lookup
#     payload = auth.verify_token_type(rt, "refresh")
#     user_id = payload.get("sub")
#     if not user_id:
#         raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token payload")

#     access_token = auth.create_access_token({"sub": user_id, "type": "access"})
#     refresh_token = auth.create_refresh_token({"sub": user_id, "type": "refresh"})
#     if response is not None:
#         response.set_cookie(
#             key="rp_refresh",
#             value=refresh_token,
#             httponly=True,
#             samesite="lax",
#             secure=False,
#             max_age=30 * 24 * 60 * 60,
#             path="/",
#         )
#     return {"access_token": access_token, "refresh_token": refresh_token, "token_type": "bearer"}


# @router.post("/logout")
# async def logout(response: Response):
#     # Clear HttpOnly refresh cookie and instruct client to delete tokens
#     response.delete_cookie("rp_refresh", path="/")
#     return {"message": "Logged out. Tokens cleared."}
