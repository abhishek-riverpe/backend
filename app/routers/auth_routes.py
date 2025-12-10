from fastapi import APIRouter, HTTPException, status, Response, Request, Depends
from datetime import datetime, timedelta, timezone
from typing import Tuple, Optional, Any
import logging
import httpx
import asyncio
import random
from slowapi import Limiter
from slowapi.util import get_remote_address
from ..core import auth
from ..core.database import prisma
from ..core.config import settings
from .. import schemas
from prisma.errors import UniqueViolationError, PrismaError, DataError
from prisma.enums import LoginMethodEnum
from passlib.context import CryptContext
from app.services.otp_service import OTPService
from app.services.otp_service import OTPService
from app.services.session_service import SessionService
from app.services.captcha_service import captcha_service
from app.services.email_service import email_service
from app.utils.device_parser import parse_device_from_headers
from app.utils.location_service import get_location_from_client
from app.utils.errors import internal_error, upstream_error

from .security import (
    normalize_email,
    validate_password,
    hash_password,
)
from app.routers.transformer import _create_entity_in_zynk
from app.core.auth import get_current_entity

MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_MINUTES = 15
CAPTCHA_REQUIRED_ATTEMPTS = 3  # Require CAPTCHA after 3 failed attempts

# Constants for URL and authentication
LOCALHOST_URL = "http://localhost"
BEARER_PREFIX = "bearer "

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
router = APIRouter(
    prefix="/api/v1/auth",
    tags=["auth"],
)

logger = logging.getLogger(__name__)

# FIXED: HIGH-04 - Rate limiter for preventing resource exhaustion attacks
limiter = Limiter(key_func=get_remote_address)


async def _email_exists_in_zynk(email: str) -> bool:
    """
    Check with ZynkLabs API if an entity already exists for the email.
    Falls back to local DB only when Zynk credentials are not configured.
    """
    if not settings.zynk_base_url or not settings.zynk_api_key:
        logger.warning("[AUTH] Zynk credentials missing, falling back to local DB email lookup.")
        existing = await prisma.entities.find_first(where={"email": email})
        return existing is not None

    url = f"{settings.zynk_base_url}/api/v1/transformer/entity/email/{email}"
    headers = {
        "x-api-token": settings.zynk_api_key,
        "Accept": "application/json",
    }

    try:
        async with httpx.AsyncClient(timeout=settings.zynk_timeout_s) as client:
            resp = await client.get(url, headers=headers)
    except httpx.RequestError as exc:
        logger.error("[AUTH] Zynk email lookup failed: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Unable to verify email at the moment. Please try again later.",
        )

    try:
        body = resp.json()
    except ValueError:
        body = {}

    if resp.status_code == 404:
        return False

    if 200 <= resp.status_code < 300:
        # Treat success response as entity existing
        return True

    error_detail = "Unknown upstream error"
    if isinstance(body, dict):
        error_detail = body.get("message") or body.get("error") or error_detail

    logger.error("[AUTH] Zynk email lookup returned %s: %s", resp.status_code, error_detail)
    raise HTTPException(
        status_code=status.HTTP_502_BAD_GATEWAY,
        detail=f"Upstream email lookup failed: {error_detail}",
    )


# Check if CAPTCHA is required for login (based on failed attempts)
@router.post("/check-captcha-required")
async def check_captcha_required(data: dict):
    """
    Check if CAPTCHA is required for a given email.
    Returns: {"captcha_required": true/false, "login_attempts": int}
    """
    email = data.get("email", "").strip()
    
    if not email:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email is required"
        )
    
    email = normalize_email(email)
    user = await prisma.entities.find_unique(where={"email": email})
    
    # Don't reveal if email exists - return captcha_required: false for non-existent emails
    if not user:
        return {
            "captcha_required": False,
            "login_attempts": 0,
        }
    
    current_attempts = user.login_attempts or 0
    captcha_required = current_attempts >= CAPTCHA_REQUIRED_ATTEMPTS
    
    return {
        "captcha_required": captcha_required,
        "login_attempts": current_attempts,
    }


@router.post("/check-email")
@limiter.limit("10/minute")  # FIXED: HIGH-04 - Rate limit to prevent email enumeration
async def check_email(data: dict, request: Request):
    email = data.get("email", "").strip()
    
    if not email:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email is required"
        )
    
    # Validate email format
    if "@" not in email or "." not in email.split("@")[1]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid email format"
        )
    
    # Check against Zynk Labs (with local DB fallback if Zynk is not configured)
    # This ensures we fail fast on the first step of signup when the email is
    # already registered either in our database or in Zynk Labs.
    exists = await _email_exists_in_zynk(email)

    if exists:
        # Email already registered (either locally or upstream in Zynk)
        return {
            "available": False,
            "message": "This email is already registered. Please sign in instead.",
        }

    # Email not found in Zynk/DB
    return {
        "available": True,
        "message": "Email is available.",
    }

def _parse_date_of_birth(date_of_birth: str, email: str) -> Tuple[Optional[datetime], str]:
    """Parse date of birth from MM/DD/YYYY format. Returns (prisma_date, zynk_date)."""
    if not date_of_birth:
        return None, date_of_birth
    
    try:
        month, day, year = date_of_birth.split('/')
        zynk_date_of_birth = f"{year}-{month.zfill(2)}-{day.zfill(2)}"
        prisma_date_of_birth = datetime(int(year), int(month), int(day), tzinfo=timezone.utc)
        return prisma_date_of_birth, zynk_date_of_birth
    except (ValueError, TypeError) as e:
        raise internal_error(
            log_message=f"[SIGNUP] Invalid date format for email {email}: {date_of_birth}. Error: {e}",
            user_message="Invalid date format. Please use MM/DD/YYYY format.",
            status_code=400,
        )


def _validate_signup_input(user_in: schemas.UserCreate, email: str) -> None:
    """Validate CAPTCHA and password for signup."""
    captcha_id = user_in.captcha_id.strip()
    captcha_code = user_in.captcha_code.strip()
    
    is_valid, error_message = captcha_service.validate_captcha(
        captcha_id=captcha_id,
        user_input=captcha_code,
    )
    
    if not is_valid:
        logger.warning(f"[AUTH] Signup blocked: Invalid CAPTCHA for email {email}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=error_message or "Invalid CAPTCHA code. Please try again.",
        )
    
    try:
        validate_password(user_in.password)
    except ValueError as ve:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(ve))


async def _create_entity_with_zynk(
    email: str,
    first_name: str,
    last_name: str,
    pwd_hash: str,
    prisma_date_of_birth: Optional[datetime],
    zynk_date_of_birth: str,
    nationality: str,
    phone_number: str,
    country_code: str,
    phone_prefix: str,
) -> Any:
    """Create entity in database and Zynk Labs. Returns created entity."""
    entity = None
    try:
        async with prisma.tx() as tx:
            entity = await tx.entities.create(
                data={
                    "email": email,
                    "password": pwd_hash,
                    "first_name": first_name,
                    "last_name": last_name,
                    "date_of_birth": prisma_date_of_birth,
                    "nationality": nationality,
                    "phone_number": phone_number,
                    "country_code": country_code,
                    "status": "PENDING",
                }
            )

        zynk_payload = {
            "firstName": first_name,
            "lastName": last_name,
            "email": email,
            "dateOfBirth": zynk_date_of_birth,
            "nationality": nationality,
            "phoneNumber": phone_number,
            "phoneNumberPrefix": phone_prefix,
            "countryCode": country_code,
            "type": "individual"
        }

        logger.info(f"[SIGNUP] Creating entity in Zynk Labs for email={email[:3]}***")
        try:
            zynk_response = await _create_entity_in_zynk(zynk_payload)
            zynk_entity_id = zynk_response.get("data", {}).get("entityId")

            if not zynk_entity_id:
                raise HTTPException(status_code=502, detail="Failed to get entity ID from Zynk Labs")

            async with prisma.tx() as tx:
                entity = await tx.entities.update(
                    where={"id": entity.id},
                    data={
                        "zynk_entity_id": zynk_entity_id,
                        "status": "ACTIVE",
                    }
                )
            
            await _create_kyc_session_for_entity(entity.id, email)
        except Exception as e:
            try:
                await prisma.entities.delete(where={"id": entity.id})
                logger.warning(f"[SIGNUP] Cleaned up placeholder record for {email} after Zynk API failure")
            except Exception as cleanup_error:
                logger.error(f"[SIGNUP] Failed to cleanup placeholder record: {cleanup_error}")
            
            if isinstance(e, HTTPException):
                raise
            raise upstream_error(
                log_message=f"[SIGNUP] Failed to create entity in Zynk Labs for email {email}: {e}",
                user_message="Failed to create account with verification service. Please try again later.",
            )

    except UniqueViolationError:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Email already registered")
    
    return entity


async def _create_kyc_session_for_entity(entity_id: str, email: str) -> None:
    """Create KYC session for newly created entity."""
    try:
        await prisma.kyc_sessions.create(
            data={
                "entity_id": entity_id,
                "status": "NOT_STARTED",
                "routing_enabled": False,
            }
        )
        logger.info(f"[SIGNUP] Created KYC session for entity_id={entity_id}, email={email[:3]}***")
    except Exception as kyc_error:
        logger.warning(
            f"[SIGNUP] Failed to create KYC session for entity_id={entity_id}: {kyc_error}. "
            "User can still signup and KYC session will be created on first KYC access."
        )


# Return unified response with tokens + user
@router.post("/signup", response_model=schemas.AuthResponse, status_code=status.HTTP_201_CREATED)
@limiter.limit("3/minute")  # FIXED: HIGH-04 - Rate limit to prevent signup flooding and Zynk API exhaustion
async def signup(user_in: schemas.UserCreate, response: Response, request: Request):
    """
    Create a new entity (user) with username, email, password.
    Returns access & refresh tokens and sets refresh token as HttpOnly cookie.
    """
    first_name = user_in.first_name.strip()
    last_name = user_in.last_name.strip()
    email = normalize_email(user_in.email)
    password = user_in.password
    date_of_birth = user_in.date_of_birth.strip()
    nationality = user_in.nationality.strip()
    phone_number = user_in.phone_number.strip()
    country_code = user_in.country_code.strip()
    phone_prefix = country_code.replace('+', '')

    logger.info(f"[SIGNUP] Signup initiated for email={email[:3]}***")

    prisma_date_of_birth, zynk_date_of_birth = _parse_date_of_birth(date_of_birth, email)
    _validate_signup_input(user_in, email)

    if await _email_exists_in_zynk(email):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Email already registered",
        )

    pwd_hash = hash_password(password)
    entity = await _create_entity_with_zynk(
        email, first_name, last_name, pwd_hash,
        prisma_date_of_birth, zynk_date_of_birth,
        nationality, phone_number, country_code, phone_prefix
    )

    access_token = auth.create_access_token(data={"sub": str(entity.id), "type": "access"})
    refresh_token = auth.create_refresh_token(data={"sub": str(entity.id), "type": "refresh"})
    _set_auth_cookies(response, access_token, refresh_token)

    # Optional: include Location header for the created resource
    response.headers["Location"] = f"/api/v1/entities/{entity.id}"

    # MED-04: Minimal profile - removed sensitive security fields (login_attempts, locked_until)
    # Also removed last_login_at, created_at, updated_at to prevent reconnaissance
    # LOW-05: Removed unnecessary hasattr() calls - Prisma models have defined fields
    safe_user = {
        "id": str(entity.id),
        "email": entity.email,
        "first_name": entity.first_name,
        "last_name": entity.last_name,
        "email_verified": entity.email_verified,
        "external_entity_id": getattr(entity, "zynk_entity_id", None) or getattr(entity, "external_entity_id", None),
        "entity_type": str(entity.entity_type) if entity.entity_type else None,
        "status": str(entity.status) if entity.status else None,
    }

    # print(f"Signup response: access_token={access_token}, refresh_token={refresh_token}, user={safe_user}")

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

async def _get_user_for_signin(email: str):
    """Get user entity for signin, with fallback to raw SQL if DataError occurs."""
    try:
        return await prisma.entities.find_unique(where={"email": email})
    except DataError as e:
        logger.warning(f"[AUTH] Database data error when fetching user {email}: {e}. Attempting raw SQL query.")
        try:
            result = await prisma.query_raw(
                """
                SELECT id, email, first_name, last_name, password, 
                       email_verified, last_login_at, login_attempts, locked_until, 
                       status, created_at, updated_at, zynk_entity_id, entity_type,
                       CASE 
                           WHEN date_of_birth IS NULL THEN NULL
                           WHEN date_of_birth::text LIKE '%/%' THEN 
                               TO_TIMESTAMP(date_of_birth::text, 'MM/DD/YYYY')
                           ELSE date_of_birth::timestamp
                       END as date_of_birth,
                       nationality, phone_number, country_code
                FROM entities 
                WHERE email = $1
                """,
                email
            )
            if not result or len(result) == 0:
                return None
            
            from types import SimpleNamespace
            row = result[0]
            return SimpleNamespace(
                id=row['id'],
                email=row['email'],
                first_name=row['first_name'],
                last_name=row['last_name'],
                password=row['password'],
                email_verified=row['email_verified'],
                last_login_at=row['last_login_at'],
                login_attempts=row['login_attempts'],
                locked_until=row['locked_until'],
                status=row['status'],
                created_at=row['created_at'],
                updated_at=row['updated_at'],
                zynk_entity_id=row.get('zynk_entity_id'),
                entity_type=row.get('entity_type'),
                date_of_birth=row['date_of_birth'],
                nationality=row.get('nationality'),
                phone_number=row.get('phone_number'),
                country_code=row.get('country_code'),
            )
        except Exception as raw_sql_error:
            logger.error(f"[AUTH] Raw SQL query also failed for user {email}: {raw_sql_error}")
            return None


def _validate_captcha_if_required(
    payload: schemas.SignInInput,
    current_attempts: int,
    email: str,
    response: Response,
) -> None:
    """Validate CAPTCHA if required based on login attempts."""
    captcha_required = current_attempts >= CAPTCHA_REQUIRED_ATTEMPTS
    
    if captcha_required:
        if not payload.captcha_id or not payload.captcha_code:
            response.headers["X-CAPTCHA-Required"] = "true"
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="CAPTCHA verification required after multiple failed attempts. Please complete the CAPTCHA and try again.",
            )
        
        is_valid, error_message = captcha_service.validate_captcha(
            captcha_id=payload.captcha_id.strip(),
            user_input=payload.captcha_code.strip(),
        )
        
        if not is_valid:
            logger.warning(f"[AUTH] Signin blocked: Invalid CAPTCHA for email {email} (attempts: {current_attempts})")
            response.headers["X-CAPTCHA-Required"] = "true"
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=error_message or "Invalid CAPTCHA code. Please try again.",
            )


def _verify_password(password: str, hashed_password: str, email: str) -> bool:
    """Verify password against hash."""
    try:
        logger.info(f"[AUTH] Attempting password verification for user: {email}")
        ok = pwd_context.verify(password, hashed_password)
        logger.info(f"[AUTH] Password verification result: {'SUCCESS' if ok else 'FAILED'}")
        return ok
    except Exception as e:
        logger.error(f"[AUTH] Password verification exception: {type(e).__name__}: {str(e)}")
        return False


async def _handle_failed_login(
    user: Any,
    now: datetime,
    request: Request,
    response: Response,
) -> None:
    """Handle failed login: increment attempts, send email, set headers."""
    attempts = (user.login_attempts or 0) + 1
    lock_until = None

    try:
        await prisma.entities.update(
            where={"id": user.id},
            data={
                "login_attempts": attempts,
                "locked_until": lock_until,
                "updated_at": now,
            },
        )
    except PrismaError:
        pass

    if attempts == CAPTCHA_REQUIRED_ATTEMPTS:
        try:
            ip_address = getattr(request.client, "host", None)
            device_info = parse_device_from_headers(request)
            location_info = await get_location_from_client(request)
            user_name = f"{user.first_name or ''} {user.last_name or ''}".strip() or user.email
            
            await email_service.send_failed_login_notification(
                email=user.email,
                user_name=user_name,
                failed_attempts=attempts,
                device_info=device_info,
                location_info=location_info,
                ip_address=ip_address,
                timestamp=now
            )
            logger.info(f"[AUTH] Failed login notification email sent to {user.email} after {attempts} attempts")
        except Exception as e:
            logger.warning(f"[AUTH] Failed to send failed login notification email: {e}")

    if lock_until:
        response.headers["X-Account-Unlock-In"] = str(int((lock_until - now).total_seconds()))
        raise HTTPException(status_code=status.HTTP_423_LOCKED, detail="Invalid email or password")

    if attempts >= CAPTCHA_REQUIRED_ATTEMPTS:
        response.headers["X-CAPTCHA-Required"] = "true"
        response.headers["X-Login-Attempts"] = str(attempts)


async def _handle_successful_login(
    user: Any,
    now: datetime,
    request: Request,
    response: Response,
) -> Tuple[str, str]:
    """Handle successful login: reset attempts, create session, return tokens."""
    try:
        await prisma.entities.update(
            where={"id": user.id},
            data={
                "login_attempts": 0,
                "locked_until": None,
                "last_login_at": now,
                "updated_at": now,
            },
        )
    except PrismaError:
        pass

    access_token = auth.create_access_token(data={"sub": str(user.id), "type": "access"})
    refresh_token = auth.create_refresh_token(data={"sub": str(user.id), "type": "refresh"})
    
    _set_auth_cookies(response, access_token, refresh_token)

    try:
        user_agent = request.headers.get("user-agent")
        ip_address = getattr(request.client, "host", None)
        device_info = parse_device_from_headers(request)
        location_info = await get_location_from_client(request)
        
        session_service = SessionService(prisma)
        await session_service.create_session(
            entity_id=str(user.id),
            session_token=access_token,
            login_method=LoginMethodEnum.EMAIL_PASSWORD,
            ip_address=ip_address,
            user_agent=user_agent,
            device_info=device_info,
            location_info=location_info,
        )
        logger.info(f"[AUTH] Login session created for user_id={user.id}")
    except Exception as e:
        logger.warning(f"[AUTH] Failed to create login session: {e}")
    
    return access_token, refresh_token


@router.post("/signin", response_model=schemas.AuthResponse, status_code=status.HTTP_200_OK)
@limiter.limit("10/minute")  # Rate limit signin attempts
async def signin(payload: schemas.SignInInput, request: Request, response: Response):
    """
    Authenticate an entity using email + password.
    - Returns access & refresh tokens.
    - Sets refresh token as HttpOnly cookie.
    - Enforces account lockout after repeated failures.
    - Requires email_verified (tweak as needed).
    """
    logger.info(f"[AUTH] Signin attempt for email: {payload.email}")
    
    def invalid_credentials():
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
        )
    
    try:
        email = normalize_email(payload.email)
        password = payload.password
    except Exception as e:
        logger.error(f"[AUTH] Error processing signin payload: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid request payload",
        )

    user = await _get_user_for_signin(email)
    if not user:
        logger.warning(f"[AUTH] User not found for email: {email}")
        invalid_credentials()

    logger.info(f"[AUTH] User found: {email} (ID: {user.id}, Status: {user.status})")
    now = datetime.now(timezone.utc)
    current_attempts = user.login_attempts or 0
    
    _validate_captcha_if_required(payload, current_attempts, email, response)
    
    ok = _verify_password(password, user.password, email)
    if not ok:
        logger.warning(f"[AUTH] Signin failed - Invalid credentials for email: {email}")
        await _handle_failed_login(user, now, request, response)
        invalid_credentials()

    access_token, refresh_token = await _handle_successful_login(user, now, request, response)
    # MED-04: Minimal profile - removed sensitive security fields (login_attempts, locked_until)
    # Also removed last_login_at, created_at, updated_at to prevent reconnaissance
    # LOW-05: Removed unnecessary hasattr() calls - Prisma models have defined fields
    safe_user = {
        "id": str(user.id),
        "email": user.email,
        "first_name": user.first_name,
        "last_name": user.last_name,
        "email_verified": user.email_verified,
        "zynk_entity_id": getattr(user, "zynk_entity_id", None) or getattr(user, "external_entity_id", None),
        "entity_type": str(user.entity_type) if user.entity_type else None,
        "status": str(user.status) if user.status else None,
    }
    # MED-06: Use logger instead of print, avoid logging full user data
    logger.debug(f"[AUTH] User profile data prepared for user_id={user.id}")
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


@router.post("/forgot-password/request", response_model=schemas.ApiResponse)
async def request_password_reset(payload: schemas.ForgotPasswordRequest):
    """
    Initiate password reset by sending an OTP to the user's email.
    Always responds with success to avoid leaking account existence.
    MED-03: Fixed timing attack by simulating same delay regardless of user existence.
    """
    email = normalize_email(payload.email)
    user = await prisma.entities.find_unique(where={"email": email})

    if user:
        otp_service = OTPService(prisma)
        success, message, _ = await otp_service.send_password_reset_otp(email=email)

        if not success:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=message,
            )
    else:
        # MED-03: Simulate same delay to prevent timing attack
        # This prevents attackers from determining if an email exists based on response time
        await asyncio.sleep(random.uniform(0.5, 1.5))

    # ALWAYS return same response regardless of user existence
    return {
        "success": True,
        "message": "If that email exists, a reset code has been sent.",
        "data": None,
        "error": None,
        "meta": {},
    }


@router.post("/forgot-password/confirm", response_model=schemas.ApiResponse)
async def confirm_password_reset(payload: schemas.ForgotPasswordConfirm):
    """
    Verify the password reset OTP and set a new password.
    """
    email = normalize_email(payload.email)
    otp_service = OTPService(prisma)

    success, message, _ = await otp_service.verify_password_reset_otp(
        email=email,
        otp_code=payload.otp_code,
    )

    if not success:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=message,
        )

    try:
        validate_password(payload.new_password)
    except ValueError as ve:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(ve),
        )

    pwd_hash = hash_password(payload.new_password)
    now = datetime.now(timezone.utc)

    try:
        await prisma.entities.update(
            where={"email": email},
            data={
                "password": pwd_hash,
                "login_attempts": 0,
                "locked_until": None,
                "updated_at": now,
            },
        )
    except PrismaError as exc:
        logger.error("[AUTH] Failed to reset password: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Unable to reset password. Please try again later.",
        )

    return {
        "success": True,
        "message": "Password reset successfully",
        "data": {"email": email},
        "error": None,
        "meta": {},
    }

def _set_auth_cookies(response: Response, access_token: str, refresh_token: str) -> None:
    """Set access and refresh tokens as HttpOnly cookies with appropriate security settings."""
    is_production = not settings.frontend_url.startswith(LOCALHOST_URL)
    
    # Set access token as HttpOnly cookie (15 minutes expiry)
    response.set_cookie(
        key="rp_access",
        value=access_token,
        httponly=True,
        samesite="lax" if not is_production else "strict",
        secure=is_production,
        max_age=15 * 60,
        path="/",
    )
    
    # Set refresh token as HttpOnly cookie (24 hours expiry)
    response.set_cookie(
        key="rp_refresh",
        value=refresh_token,
        httponly=True,
        samesite="lax" if not is_production else "strict",
        secure=is_production,
        max_age=24 * 60 * 60,
        path="/",
    )


async def _get_refresh_token_from_request(request: Request, body: dict = None) -> str:
    """Extract refresh token from cookies or request body."""
    rt = request.cookies.get("rp_refresh")
    
    if not rt:
        try:
            body_data = await request.json() if body is None else body
            rt = body_data.get("refresh_token")
        except Exception:
            pass
    
    if not rt:
        logger.warning("[AUTH] Refresh token missing from both cookies and request body")
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing refresh token")
    
    return rt


async def _validate_refresh_token_and_get_user(refresh_token: str):
    """Validate refresh token and return user entity."""
    payload = auth.verify_token_type(refresh_token, "refresh")
    user_id = payload.get("sub")
    if not user_id:
        logger.warning(f"[AUTH] Invalid token payload - missing 'sub': {payload}")
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token payload")

    user = await prisma.entities.find_unique(where={"id": user_id})
    if not user:
        logger.warning(f"[AUTH] Entity not found for user_id: {user_id}")
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Entity not found")
    
    return user


async def _create_refresh_session(
    request: Request, user, access_token: str
) -> None:
    """Create a new login session for the refreshed access token."""
    try:
        user_agent = request.headers.get("user-agent")
        ip_address = getattr(request.client, "host", None)
        device_info = parse_device_from_headers(request)
        location_info = await get_location_from_client(request)
        
        session_service = SessionService(prisma)
        await session_service.create_session(
            entity_id=str(user.id),
            session_token=access_token,
            login_method=LoginMethodEnum.EMAIL_PASSWORD,
            ip_address=ip_address,
            user_agent=user_agent,
            device_info=device_info,
            location_info=location_info,
        )
    except Exception as e:
        logger.warning(f"[AUTH] Failed to create login session on refresh: {e}")


@router.post("/refresh", response_model=schemas.AuthResponse)
async def refresh_token(request: Request, response: Response, body: dict = None):
    """
    Issue a new access/refresh token pair using the HttpOnly refresh cookie or request body.
    Supports both web (cookies) and mobile (request body) clients.
    Returns unified response; sets a fresh refresh cookie.
    """
    try:
        rt = await _get_refresh_token_from_request(request, body)
        user = await _validate_refresh_token_and_get_user(rt)
        
        access_token = auth.create_access_token({"sub": str(user.id), "type": "access"})
        refresh_token = auth.create_refresh_token({"sub": str(user.id), "type": "refresh"})
        
        _set_auth_cookies(response, access_token, refresh_token)
        await _create_refresh_session(request, user, access_token)
    except HTTPException:
        raise
    except Exception as e:
        raise internal_error(
            log_message=f"[AUTH] Error during token refresh: {e}",
            user_message="Token refresh failed. Please log in again.",
            status_code=status.HTTP_401_UNAUTHORIZED,
        )

    # MED-04: Minimal profile - removed sensitive security fields (login_attempts, locked_until)
    # Also removed last_login_at, created_at, updated_at to prevent reconnaissance
    # LOW-05: Removed unnecessary hasattr() calls - Prisma models have defined fields
    safe_user = {
        "id": str(user.id),
        "email": user.email,
        "first_name": user.first_name,
        "last_name": user.last_name,
        "email_verified": user.email_verified,
        "zynk_entity_id": getattr(user, "zynk_entity_id", None) or getattr(user, "external_entity_id", None),
        "entity_type": str(user.entity_type) if user.entity_type else None,
        "status": str(user.status) if user.status else None,
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
async def logout(request: Request, response: Response):
    """
    Logout the current session.
    - Updates session logout_at timestamp
    - Marks session as LOGGED_OUT
    - Clears refresh cookie
    """
    # Extract access token from Authorization header to update session
    auth_header = request.headers.get("authorization") or request.headers.get("Authorization")
    session_token = None
    
    if auth_header and auth_header.lower().startswith(BEARER_PREFIX):
        session_token = auth_header.split(" ", 1)[1].strip()
        
        # Update session logout_at and status
        try:
            session_service = SessionService(prisma)
            await session_service.logout_session(session_token=session_token)
            logger.info(f"[AUTH] Session logged out: {session_token[:16]}...")
        except Exception as e:
            # Log error but don't fail logout (token might be expired/invalid)
            logger.warning(f"[AUTH] Failed to update session on logout: {e}")
    
    # Clear both access and refresh cookies
    response.delete_cookie("rp_access", path="/")
    response.delete_cookie("rp_refresh", path="/")
    
    return {
        "success": True,
        "message": "Logged out",
        "data": None,
        "error": None,
        "meta": {},
    }
    
@router.post("/change-password", response_model=schemas.ApiResponse)
async def change_password(
    payload: schemas.ChangePasswordRequest,
    request: Request,
    current_user = Depends(get_current_entity)
):
    """
    Change password for authenticated user.
    - Validates current password
    - Updates to new password
    - Revokes all other sessions (keeps current session active)
    - Sends email notification with security details
    """
    now = datetime.now(timezone.utc)
    
    # Validate current password
    try:
        password_valid = pwd_context.verify(payload.current_password, current_user.password)
    except Exception:
        password_valid = False
    
    if not password_valid:
        logger.warning(f"[AUTH] Change password failed: Invalid current password for user {current_user.email}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Current password is incorrect",
        )
    
    # Validate new password
    if payload.current_password == payload.new_password:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="New password must be different from current password",
        )
    
    # Password history check: Currently not implemented
    # Future enhancement: Store last 5 password hashes and prevent reuse
    # This would require a password_history table with entity_id, password_hash, created_at
    
    try:
        validate_password(payload.new_password)
    except ValueError as ve:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(ve),
        )
    
    # Hash new password
    new_password_hash = hash_password(payload.new_password)
    
    # Update password in database
    try:
        await prisma.entities.update(
            where={"id": current_user.id},
            data={
                "password": new_password_hash,
                "login_attempts": 0,  # Reset login attempts on password change
                "locked_until": None,  # Clear any lockouts
                "updated_at": now,
            },
        )
        logger.info(f"[AUTH] Password changed successfully for user {current_user.email}")
    except PrismaError as exc:
        logger.error(f"[AUTH] Failed to update password: {exc}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Unable to change password. Please try again later.",
        )
    
    # Revoke all other sessions (except current session)
    try:
        # Get current session token from Authorization header
        auth_header = request.headers.get("authorization") or request.headers.get("Authorization")
        current_session_token = None
        if auth_header and auth_header.lower().startswith(BEARER_PREFIX):
            current_session_token = auth_header.split(" ", 1)[1].strip()
        
        session_service = SessionService(prisma)
        revoked_count = await session_service.revoke_all_sessions(
            entity_id=str(current_user.id),
            except_token=current_session_token
        )
        logger.info(f"[AUTH] Revoked {revoked_count} sessions after password change for user {current_user.email}")
    except Exception as e:
        logger.warning(f"[AUTH] Failed to revoke sessions after password change: {e}")
        # Don't fail password change if session revocation fails
    
    # Send email notification with security details
    try:
        # Extract device and location information
        ip_address = getattr(request.client, "host", None)
        
        # Parse device information
        device_info = parse_device_from_headers(request)
        
        # Get location information
        location_info = await get_location_from_client(request)
        
        # Get user's full name
        user_name = f"{current_user.first_name or ''} {current_user.last_name or ''}".strip() or current_user.email
        
        # Send email notification
        await email_service.send_password_change_notification(
            email=current_user.email,
            user_name=user_name,
            device_info=device_info,
            location_info=location_info,
            ip_address=ip_address,
            timestamp=now
        )
        logger.info(f"[AUTH] Password change notification email sent to {current_user.email}")
    except Exception as e:
        logger.warning(f"[AUTH] Failed to send password change notification email: {e}")
        # Don't fail password change if email fails
    
    return {
        "success": True,
        "message": "Password changed successfully",
        "data": {
            "email": current_user.email,
            "password_changed_at": now.isoformat(),
        },
        "error": None,
        "meta": {},
    }


@router.get("/ping")
async def auth_ping(request: Request):
    """
    Simple authenticated ping to exercise middleware/session activity updates.
    Requires Authorization: Bearer <access_token> header.
    """
    auth_header = request.headers.get("authorization") or request.headers.get("Authorization")
    if not auth_header or not auth_header.lower().startswith(BEARER_PREFIX):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing bearer token")
    token = auth_header.split(" ", 1)[1].strip()
    # Validate token type
    auth.verify_token_type(token, "access")
    return {"success": True, "message": "pong", "data": {"time": datetime.now(timezone.utc).isoformat()}}

@router.post("/logout-all", response_model=schemas.ApiResponse)
async def logout_all_devices(request: Request, response: Response, current_user=Depends(get_current_entity)):
    """
    Revoke all active sessions for the current user and clear refresh cookie.
    Note: Existing refresh tokens on other devices will be cleared only when they refresh the page;
    server will not issue new access tokens for expired/idle sessions, but refresh JWTs are not tracked server-side.
    
    FIXED: HIGH-02 - BOLA Protection
    - Only uses authenticated user's ID from token (current_user.id)
    - No entity_id parameter accepted from request
    - Prevents unauthorized session revocation
    """
    try:
        session_service = SessionService(prisma)
        # FIXED: HIGH-02 - Explicit BOLA protection: Only use authenticated user's ID
        # Never accept entity_id from request parameters - always use current_user.id
        revoked = await session_service.revoke_all_sessions(entity_id=str(current_user.id))
        # Clear current refresh cookie
        response.delete_cookie("rp_access", path="/")
        response.delete_cookie("rp_refresh", path="/")
        return {
            "success": True,
            "message": f"Logged out from all devices ({revoked} sessions revoked)",
            "data": {"revoked": revoked},
            "error": None,
            "meta": {},
        }
    except Exception as e:
        logger.error(f"[AUTH] Logout all devices failed: {e}")
        raise HTTPException(status_code=500, detail="Failed to logout from all devices")
