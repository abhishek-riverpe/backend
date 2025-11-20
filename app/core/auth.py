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
ACCESS_TOKEN_EXPIRE = timedelta(minutes=15)
REFRESH_TOKEN_EXPIRE = timedelta(days=7)

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
    to_encode.update({"exp": datetime.utcnow() + expires_delta})
    return _encode_jwt(to_encode)

def create_refresh_token(data: dict, expires_delta: timedelta = REFRESH_TOKEN_EXPIRE) -> str:
    to_encode = data.copy()
    if "sub" not in to_encode:
        raise ValueError("refresh token requires 'sub' claim")
    to_encode.setdefault("type", "refresh")
    to_encode.update({"exp": datetime.utcnow() + expires_delta})
    return _encode_jwt(to_encode)

def _validate_jwt_algorithm(token: str) -> None:
    """
    Validate JWT algorithm before decoding to prevent algorithm confusion attacks.
    Explicitly rejects 'none' algorithm and ensures algorithm is in whitelist.
    
    Raises:
        HTTPException: If algorithm is forbidden or not in whitelist
    """
    try:
        # Decode header without verification to check algorithm
        unverified_header = jwt.get_unverified_header(token)
        algorithm = unverified_header.get("alg")
        
        if not algorithm:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token missing algorithm in header"
            )
        
        # Explicitly reject "none" algorithm (critical security check)
        if algorithm in FORBIDDEN_ALGORITHMS:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"Forbidden algorithm: {algorithm}. Algorithm confusion attack detected."
            )
        
        # Ensure algorithm is in whitelist
        if algorithm not in ALLOWED_ALGORITHMS:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"Algorithm '{algorithm}' not allowed. Allowed algorithms: {', '.join(ALLOWED_ALGORITHMS)}"
            )
    except JWTError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid token header: {str(e)}"
        )

def decode_token(token: str) -> dict:
    """
    Decode and verify JWT token with algorithm whitelist enforcement.
    
    Security features:
    - Validates algorithm before decoding (prevents algorithm confusion)
    - Explicitly rejects "none" algorithm
    - Only allows algorithms from whitelist
    - Enforces signature validation
    """
    # Validate algorithm first (before any decoding)
    _validate_jwt_algorithm(token)
    
    try:
        # Decode with explicit algorithm whitelist
        # This prevents algorithm confusion attacks (e.g., RS256 -> HS256 swap)
        return jwt.decode(
            token,
            settings.jwt_secret,
            algorithms=ALLOWED_ALGORITHMS,  # Use whitelist, not single algorithm
            options={"verify_signature": True}  # Explicitly require signature verification
        )
    except ExpiredSignatureError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token expired")
    except JWTError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid token signature or format: {str(e)}"
        )

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

