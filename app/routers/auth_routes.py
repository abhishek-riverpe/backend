import random
from fastapi import APIRouter, HTTPException, status, Response, Request

from .. import auth, schemas
from ..database import db

router = APIRouter(
    prefix="/api/v1/auth",
    tags=["auth"],
)


@router.post("/signup", response_model=schemas.Token)
async def signup(user_in: schemas.UserCreate, response: Response):
    existing_user = await db.user.find_unique(where={"username": user_in.username})
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Email already registered",
        )

    hashed_password = auth.get_password_hash(user_in.password)

    user = await db.user.create(
        data={
            "username": user_in.username,
            "password_hash": hashed_password,
            "first_name": user_in.firstName,
            "last_name": user_in.lastName,
        }
    )

    await db.account.create(
        data={
            "userId": user.id,
            "balance": round(1 + random.random() * 9999, 2)
        }
    )

    access_token = auth.create_access_token(data={"sub": user.id, "type": "access"})
    refresh_token = auth.create_refresh_token(data={"sub": user.id, "type": "refresh"})
    # HttpOnly cookie for refresh token
    response.set_cookie(
        key="rp_refresh",
        value=refresh_token,
        httponly=True,
        samesite="lax",
        secure=False,  # set True in production behind HTTPS
        max_age=30 * 24 * 60 * 60,
        path="/",
    )
    return {"access_token": access_token, "refresh_token": refresh_token, "token_type": "bearer"}


@router.post("/signin", response_model=schemas.Token)
async def signin(credentials: schemas.UserLogin, response: Response):
    user = await db.user.find_unique(where={"username": credentials.username})
    if not user or not auth.verify_password(credentials.password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    access_token = auth.create_access_token({"sub": user.id, "type": "access"})
    refresh_token = auth.create_refresh_token({"sub": user.id, "type": "refresh"})
    response.set_cookie(
        key="rp_refresh",
        value=refresh_token,
        httponly=True,
        samesite="lax",
        secure=False,
        max_age=30 * 24 * 60 * 60,
        path="/",
    )
    return {"access_token": access_token, "refresh_token": refresh_token, "token_type": "bearer"}


@router.post("/refresh", response_model=schemas.Token)
async def refresh_token(request: Request, body: schemas.RefreshRequest | None = None, response: Response = None):
    # Take refresh token from body or HttpOnly cookie
    rt = (body.refresh_token if body else None) or request.cookies.get("rp_refresh")
    if not rt:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing refresh token")
    # Validate refresh token type and expiry; no DB lookup
    payload = auth.verify_token_type(rt, "refresh")
    user_id = payload.get("sub")
    if not user_id:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token payload")

    access_token = auth.create_access_token({"sub": user_id, "type": "access"})
    refresh_token = auth.create_refresh_token({"sub": user_id, "type": "refresh"})
    if response is not None:
        response.set_cookie(
            key="rp_refresh",
            value=refresh_token,
            httponly=True,
            samesite="lax",
            secure=False,
            max_age=30 * 24 * 60 * 60,
            path="/",
        )
    return {"access_token": access_token, "refresh_token": refresh_token, "token_type": "bearer"}


@router.post("/logout")
async def logout(response: Response):
    # Clear HttpOnly refresh cookie and instruct client to delete tokens
    response.delete_cookie("rp_refresh", path="/")
    return {"message": "Logged out. Tokens cleared."}
