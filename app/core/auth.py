from datetime import datetime, timedelta
from typing import Optional

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, ExpiredSignatureError, jwt
from passlib.context import CryptContext

from .config import settings
from .database import prisma

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/signin")

ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE = timedelta(hours=24)
REFRESH_TOKEN_EXPIRE = timedelta(days=30)

def get_password_hash(password):
    return pwd_context.hash(password)

def _encode_jwt(payload: dict) -> str:
    return jwt.encode(payload, settings.jwt_secret, algorithm=ALGORITHM)

def create_access_token(data: dict, expires_delta: timedelta = ACCESS_TOKEN_EXPIRE) -> str:
    to_encode = data.copy()
    # Ensure required claims
    if "sub" not in to_encode:
        raise ValueError("access token requires 'sub' claim")
    to_encode.setdefault("type", "access")
    to_encode.update({"exp": datetime.utcnow() + expires_delta})
    return _encode_jwt(to_encode)

def create_refresh_token(data: dict, expires_delta: timedelta = REFRESH_TOKEN_EXPIRE) -> str:
    to_encode = data.copy()
    if "sub" not in to_encode:
        raise ValueError("refresh token requires 'sub' claim")
    to_encode.setdefault("type", "refresh")
    to_encode.update({"exp": datetime.utcnow() + expires_delta})
    return _encode_jwt(to_encode)

def decode_token(token: str) -> dict:
    try:
        return jwt.decode(token, settings.jwt_secret, algorithms=[ALGORITHM])
    except ExpiredSignatureError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token expired")
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")

def verify_token_type(token: str, expected_type: str) -> dict:
    payload = decode_token(token)
    token_type = payload.get("type")
    if token_type != expected_type:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token type")
    return payload


async def get_current_entity(token: str = Depends(oauth2_scheme)):
    # Validate access token and extract entity id (sub)
    payload = verify_token_type(token, "access")
    entity_id: Optional[str] = payload.get("sub")
    if not entity_id:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token payload")

    entity = await prisma.entities.find_unique(where={"id": entity_id})
    if entity is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Entity not found")
    return entity

