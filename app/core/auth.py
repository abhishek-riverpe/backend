from datetime import datetime, timedelta, timezone
from typing import Optional
from types import SimpleNamespace

from fastapi import Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, ExpiredSignatureError, jwt
from passlib.context import CryptContext
from prisma.errors import DataError

from .config import settings
from .database import prisma

# LOW-07: Explicitly configure bcrypt rounds for consistent security
# bcrypt__rounds=12 provides good security-performance balance (2^12 = 4096 iterations)
pwd_context = CryptContext(
    schemes=["bcrypt"],
    deprecated="auto",
    bcrypt__rounds=12
)
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/signin")

ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE = timedelta(minutes=15)
REFRESH_TOKEN_EXPIRE = timedelta(hours=24)  # 24 hours as requested

# JWT Algorithm Whitelist - Only these algorithms are allowed
# Explicitly rejects "none" algorithm and prevents algorithm confusion attacks
ALLOWED_ALGORITHMS = settings.jwt_allowed_algorithms if hasattr(settings, 'jwt_allowed_algorithms') else ["HS256"]

# Explicitly forbidden algorithms
FORBIDDEN_ALGORITHMS = ["none", "NONE", "None"]

# JWT Algorithm Whitelist - Only these algorithms are allowed
# Explicitly rejects "none" algorithm and prevents algorithm confusion attacks
ALLOWED_ALGORITHMS = settings.jwt_allowed_algorithms if hasattr(settings, 'jwt_allowed_algorithms') else ["HS256"]

# Explicitly forbidden algorithms
FORBIDDEN_ALGORITHMS = ["none", "NONE", "None"]

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
    to_encode.update({"exp": datetime.now(timezone.utc) + expires_delta})
    return _encode_jwt(to_encode)

def create_refresh_token(data: dict, expires_delta: timedelta = REFRESH_TOKEN_EXPIRE) -> str:
    to_encode = data.copy()
    if "sub" not in to_encode:
        raise ValueError("refresh token requires 'sub' claim")
    to_encode.setdefault("type", "refresh")
    to_encode.update({"exp": datetime.now(timezone.utc) + expires_delta})
    return _encode_jwt(to_encode)

def decode_token(token: str) -> dict:
    try:
        return jwt.decode(
            token,
            settings.jwt_secret,
            algorithms=ALLOWED_ALGORITHMS,
            options={"verify_signature": True}
        )
    except ExpiredSignatureError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token expired")
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token"
        )

def verify_token_type(token: str, expected_type: str) -> dict:
    payload = decode_token(token)
    token_type = payload.get("type")
    if token_type != expected_type:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token type")
    return payload


async def get_current_entity(request: Request, token: Optional[str] = Depends(oauth2_scheme)):
    """
    Get current authenticated entity.
    Reads access token from HttpOnly cookie (rp_access) first, then falls back to Authorization header.
    This provides secure cookie-based auth while maintaining backward compatibility.
    """
    # Try to get token from HttpOnly cookie first (secure method)
    access_token = request.cookies.get("rp_access")
    
    # Fallback to Authorization header for backward compatibility
    if not access_token and token:
        access_token = token
    
    if not access_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Validate access token and extract entity id (sub)
    payload = verify_token_type(access_token, "access")
    entity_id: Optional[str] = payload.get("sub")
    if not entity_id:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token payload")

    # Try Prisma first, fallback to raw SQL if DataError (corrupted date_of_birth)
    entity = None
    try:
        entity = await prisma.entities.find_unique(where={"id": entity_id})
    except DataError as e:
        # Handle database data inconsistency (e.g., date_of_birth stored as string)
        # Fallback to raw SQL if Prisma fails due to data inconsistency
        raw_query = """
            SELECT
                id, zynk_entity_id, entity_type, email, first_name, last_name, password,
                CASE
                    WHEN date_of_birth ~ '^\d{2}/\d{2}/\d{4}$' THEN TO_TIMESTAMP(date_of_birth, 'MM/DD/YYYY')::timestamptz
                    ELSE NULL
                END AS date_of_birth,
                nationality, phone_number, country_code, email_verified, last_login_at,
                login_attempts, locked_until, encrypted_data, encryption_key_id, status,
                created_at, updated_at, deleted_at
            FROM entities
            WHERE id = $1
        """
        raw_user_data = await prisma.query_raw(raw_query, entity_id)
        if raw_user_data:
            # Convert raw result to a SimpleNamespace object for compatibility
            entity = SimpleNamespace(**raw_user_data[0])
            # Manually convert date_of_birth if it's still a string (should be handled by SQL now)
            if isinstance(entity.date_of_birth, str):
                try:
                    entity.date_of_birth = datetime.strptime(entity.date_of_birth, '%Y-%m-%dT%H:%M:%S.%fZ').replace(tzinfo=timezone.utc)
                except ValueError:
                    entity.date_of_birth = None
    
    if entity is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Entity not found")
    return entity

