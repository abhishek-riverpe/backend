from fastapi import APIRouter, HTTPException, status, Response, Request, Depends
from datetime import datetime, timedelta, timezone
import logging
import httpx
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

# from prisma.models import entities  # prisma python generates models from schema
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


# Check if email is available
# SECURITY: Always returns generic success to prevent account enumeration
# Actual email validation happens during signup
@router.post("/check-email")
@limiter.limit("10/minute")  # FIXED: HIGH-04 - Rate limit to prevent email enumeration
async def check_email(data: dict, request: Request):
    """
    DEPRECATED: This endpoint is kept for backwards compatibility but always returns success.
    Email validation now happens during actual signup to prevent account enumeration attacks.
    
    Returns: {"available": true, "message": "..."} (always)
    """
    email = data.get("email", "").strip()
    
    if not email:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email is required"
        )
    
    # Validate email format
    if not "@" in email or "." not in email.split("@")[1]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid email format"
        )
    
    # SECURITY: Always return generic success message to prevent account enumeration
    # The actual email check happens during signup (handled by UniqueViolationError)
    # This prevents attackers from enumerating valid email addresses
    logger.info(f"[AUTH] check-email called for {email} (returning generic response to prevent enumeration)")
    
    return {
        "available": True,
        "message": "If this email is available, you'll receive a verification code."
    }

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
    # Extract phone prefix (numeric part without +)
    phone_prefix = country_code.replace('+', '')

    # Convert date from MM/DD/YYYY to YYYY-MM-DD format for Zynk Labs and DateTime for Prisma
    prisma_date_of_birth = None
    if date_of_birth:
        try:
            month, day, year = date_of_birth.split('/')
            zynk_date_of_birth = f"{year}-{month.zfill(2)}-{day.zfill(2)}"
            # Convert to DateTime for Prisma (ISO-8601 format)
            prisma_date_of_birth = datetime(int(year), int(month), int(day), tzinfo=timezone.utc)
        except (ValueError, TypeError) as e:
            raise HTTPException(status_code=400, detail=f"Invalid date format. Please use MM/DD/YYYY format. Error: {str(e)}")
    else:
        zynk_date_of_birth = date_of_birth

    print(f"Signup request: first_name={first_name}, last_name={last_name}, email={email}, date_of_birth={date_of_birth}, nationality={nationality}, phone={country_code}{phone_number}")

    # Validate CAPTCHA first
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

    # Validate semantics
    try:
        validate_password(password)
    except ValueError as ve:
        # 400 for client input that fails our policy
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(ve))

    # Hash password
    pwd_hash = hash_password(password)

    # FIXED: TOCTOU Race Condition - Create placeholder record FIRST in transaction
    # This uses the database unique constraint as a lock mechanism
    # The transaction ensures atomicity: if external API fails, record is rolled back
    entity = None
    try:
        async with prisma.tx() as tx:
            # Create placeholder record with PENDING status
            # This will fail with UniqueViolationError if email already exists
            # The unique constraint acts as the lock, preventing race conditions
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
                    "status": "PENDING",  # Placeholder status until Zynk API succeeds (PENDING = user created but zynk entity not created)
                    # zynk_entity_id will be set after Zynk API call
                }
            )
            # Transaction commits here, entity is now locked by unique constraint

        # Now call external API (outside transaction to avoid long-running transaction)
        # If this fails, we'll need to clean up the placeholder record
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

        print(f"[SIGNUP] Creating entity in Zynk Labs with payload: {zynk_payload}")
        try:
            zynk_response = await _create_entity_in_zynk(zynk_payload)
            zynk_entity_id = zynk_response.get("data", {}).get("entityId")

            if not zynk_entity_id:
                raise HTTPException(status_code=502, detail="Failed to get entity ID from Zynk Labs")

            # Update record with external ID and set status to ACTIVE
            async with prisma.tx() as tx:
                entity = await tx.entities.update(
                    where={"id": entity.id},
                    data={
                        "zynk_entity_id": zynk_entity_id,
                        "status": "ACTIVE",  # Set to ACTIVE after successful Zynk creation
                    }
                )
        except Exception as e:
            # Cleanup: Delete placeholder record if external API fails
            try:
                await prisma.entities.delete(where={"id": entity.id})
                logger.warning(f"[SIGNUP] Cleaned up placeholder record for {email} after Zynk API failure")
            except Exception as cleanup_error:
                logger.error(f"[SIGNUP] Failed to cleanup placeholder record: {cleanup_error}")
            # Re-raise the original exception
            if isinstance(e, HTTPException):
                raise
            raise HTTPException(status_code=502, detail=f"Failed to create entity in Zynk Labs: {str(e)}")

    except UniqueViolationError:
        # Email already exists - caught by unique constraint
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Email already registered")

    # Tokens (subject should be a stable unique id)
    access_token = auth.create_access_token(data={"sub": str(entity.id), "type": "access"})
    refresh_token = auth.create_refresh_token(data={"sub": str(entity.id), "type": "refresh"})

    # Set refresh cookie: secure defaults for banking
    # Use secure=True only in production (HTTPS), False for localhost development
    # Use samesite="lax" in development for cross-port cookies, "strict" in production
    is_production = not settings.frontend_url.startswith("http://localhost")
    response.set_cookie(
        key="rp_refresh",
        value=refresh_token,
        httponly=True,       # ✅ HttpOnly set to True for security
        samesite="lax" if not is_production else "strict",  # Lax for dev, strict for prod
        secure=is_production,  # True in production (HTTPS), False in development
        max_age=24 * 60 * 60,  # 24 hours (86400 seconds) to match refresh token expiry
        path="/",
    )

    # Optional: include Location header for the created resource
    response.headers["Location"] = f"/api/v1/entities/{entity.id}"

    safe_user = {
        "id": str(entity.id) if hasattr(entity, "id") else None,
        "external_entity_id": getattr(entity, "zynk_entity_id", None) or getattr(entity, "external_entity_id", None),
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
    logger.info(f"[AUTH] Request method: {request.method}, URL: {request.url}")
    logger.info(f"[AUTH] Request headers: {dict(request.headers)}")
    
    # Uniform error for nonexistent users (avoid user enumeration)
    def invalid_credentials():
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
        )
    
    try:
        # email = payload.email.strip()
        email = normalize_email(payload.email)
        password = payload.password
    except Exception as e:
        logger.error(f"[AUTH] Error processing signin payload: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid request payload",
        )

    # Fetch entity by exact email match (you chose not to lowercase)
    # Use raw SQL query to handle date_of_birth stored as string (legacy data issue)
    try:
        user = await prisma.entities.find_unique(where={"email": email})
    except DataError as e:
        # Handle database data inconsistency (e.g., date_of_birth stored as string)
        logger.warning(f"[AUTH] Database data error when fetching user {email}: {e}. Attempting raw SQL query.")
        try:
            # Use raw SQL to fetch user and handle date conversion
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
                invalid_credentials()
            
            # Convert raw result to a dict-like object for compatibility
            row = result[0]
            from types import SimpleNamespace
            user = SimpleNamespace(
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
            logger.info(f"[AUTH] Successfully fetched user {email} using raw SQL query")
        except Exception as raw_sql_error:
            logger.error(f"[AUTH] Raw SQL query also failed for user {email}: {raw_sql_error}")
            invalid_credentials()

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

    # Check if CAPTCHA is required (after 3 failed attempts)
    current_attempts = user.login_attempts or 0
    captcha_required = current_attempts >= CAPTCHA_REQUIRED_ATTEMPTS
    
    if captcha_required:
        # CAPTCHA is required - validate it before password check
        if not payload.captcha_id or not payload.captcha_code:
            response.headers["X-CAPTCHA-Required"] = "true"
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="CAPTCHA verification required after multiple failed attempts. Please complete the CAPTCHA and try again.",
            )
        
        # Validate CAPTCHA
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
            await prisma.entities.update(
                where={"id": user.id},
                data={
                    "login_attempts": attempts,
                    "locked_until": lock_until,
                    "updated_at": now,
                },
            )
        except PrismaError:
            # Do not leak DB errors; still respond with auth error
            pass

        # Send email notification when attempts reach 3 (CAPTCHA required threshold)
        if attempts == CAPTCHA_REQUIRED_ATTEMPTS:
            try:
                # Extract device and location information
                user_agent = request.headers.get("user-agent")
                ip_address = getattr(request.client, "host", None)
                
                # Parse device information
                device_info = parse_device_from_headers(request)
                
                # Get location information
                location_info = await get_location_from_client(request)
                
                # Get user's full name
                user_name = f"{user.first_name or ''} {user.last_name or ''}".strip() or user.email
                
                # Send email notification
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
                # Don't fail login if email fails

        if lock_until:
            response.headers["X-Account-Unlock-In"] = str(int((lock_until - now).total_seconds()))
            raise HTTPException(status_code=status.HTTP_423_LOCKED, detail=detail)

        # If attempts >= 3, indicate CAPTCHA is required for next attempt
        if attempts >= CAPTCHA_REQUIRED_ATTEMPTS:
            response.headers["X-CAPTCHA-Required"] = "true"
            response.headers["X-Login-Attempts"] = str(attempts)

        invalid_credentials()

    # Success: reset attempts, clear lock, update last_login_at
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
        # Non-fatal; continue issuing tokens
        pass

    # Issue tokens
    access_token = auth.create_access_token(data={"sub": str(user.id), "type": "access"})
    refresh_token = auth.create_refresh_token(data={"sub": str(user.id), "type": "refresh"})

    # Set refresh cookie (banking defaults)
    # Use secure=True only in production (HTTPS), False for localhost development
    # Use samesite="lax" in development for cross-port cookies, "strict" in production
    is_production = not settings.frontend_url.startswith("http://localhost")
    response.set_cookie(
        key="rp_refresh",
        value=refresh_token,
        httponly=True,               # ✅ HttpOnly set to True for security
        samesite="lax" if not is_production else "strict",  # Lax for dev, strict for prod
        secure=is_production,        # True in production (HTTPS), False in development
        max_age=24 * 60 * 60,   # 24 hours (86400 seconds) to match refresh token expiry
        path="/",
    )

    # Create login session for access token (used for inactivity tracking)
    try:
        # Extract device and location information
        user_agent = request.headers.get("user-agent")
        ip_address = getattr(request.client, "host", None)
        
        # Parse device information (from custom headers for mobile app, or user-agent for web)
        device_info = parse_device_from_headers(request)
        
        # Get location information (from client headers or IP geolocation)
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
        logger.warning(f"[AUTH] Failed to create login session: {e}")
    print(f"[AUTH] Login session created for user {user}")
    
    # Helper function to safely convert datetime to ISO format string
    def to_iso_string(dt_value):
        """Convert datetime to ISO string, handling both datetime objects and strings."""
        if dt_value is None:
            return None
        if isinstance(dt_value, str):
            # Already a string (from raw SQL), return as-is
            return dt_value
        if hasattr(dt_value, 'isoformat'):
            # It's a datetime object
            return dt_value.isoformat()
        return str(dt_value) if dt_value else None
    
    safe_user = {
        "id": str(user.id) if hasattr(user, "id") else None,
        "zynk_entity_id": getattr(user, "zynk_entity_id", None) or getattr(user, "external_entity_id", None),
        "entity_type": str(user.entity_type) if hasattr(user, "entity_type") else None,
        "email": user.email if hasattr(user, "email") else None,
        "first_name": user.first_name if hasattr(user, "first_name") else None,
        "last_name": user.last_name if hasattr(user, "last_name") else None,
        "email_verified": user.email_verified if hasattr(user, "email_verified") else None,
        "last_login_at": to_iso_string(getattr(user, "last_login_at", None)),
        "login_attempts": user.login_attempts if hasattr(user, "login_attempts") else None,
        "locked_until": to_iso_string(getattr(user, "locked_until", None)),
        "status": str(user.status) if hasattr(user, "status") else None,
        "created_at": to_iso_string(getattr(user, "created_at", None)),
        "updated_at": to_iso_string(getattr(user, "updated_at", None)),
    }
    print(f"[AUTH] Safe user: {safe_user}")
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
    """
    email = normalize_email(payload.email)
    user = await prisma.entities.find_unique(where={"email": email})

    if not user:
        return {
            "success": True,
            "message": "If that email exists, a reset code has been sent.",
            "data": None,
            "error": None,
            "meta": {},
        }

    otp_service = OTPService(prisma)
    success, message, data = await otp_service.send_password_reset_otp(email=email)

    if not success:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=message,
        )

    return {
        "success": True,
        "message": message,
        "data": data,
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

@router.post("/refresh", response_model=schemas.AuthResponse)
async def refresh_token(request: Request, response: Response):
    """
    Issue a new access/refresh token pair using the HttpOnly refresh cookie.
    Returns unified response; sets a fresh refresh cookie.
    """
    rt = request.cookies.get("rp_refresh")
    if not rt:
        logger.warning("[AUTH] Refresh token missing from cookies")
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing refresh token")

    try:
        # Validate refresh token
        payload = auth.verify_token_type(rt, "refresh")
        user_id = payload.get("sub")
        if not user_id:
            logger.warning(f"[AUTH] Invalid token payload - missing 'sub': {payload}")
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token payload")

        user = await prisma.entities.find_unique(where={"id": user_id})
        if not user:
            logger.warning(f"[AUTH] Entity not found for user_id: {user_id}")
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Entity not found")

        access_token = auth.create_access_token({"sub": str(user.id), "type": "access"})
        refresh_token = auth.create_refresh_token({"sub": str(user.id), "type": "refresh"})

        # Use secure=True only in production (HTTPS), False for localhost development
        # Use samesite="lax" in development for cross-port cookies, "strict" in production
        is_production = not settings.frontend_url.startswith("http://localhost")
        response.set_cookie(
            key="rp_refresh",
            value=refresh_token,
            httponly=True,               # ✅ HttpOnly set to True for security
            samesite="lax" if not is_production else "strict",  # Lax for dev, strict for prod
            secure=is_production,        # True in production (HTTPS), False in development
            max_age=24 * 60 * 60,   # 24 hours (86400 seconds) to match refresh token expiry
            path="/",
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"[AUTH] Error during token refresh: {e}", exc_info=True)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=f"Token refresh failed: {str(e)}")

    # Create a new login session for the new access token
    try:
        # Extract device and location information
        user_agent = request.headers.get("user-agent")
        ip_address = getattr(request.client, "host", None)
        
        # Parse device information (from custom headers for mobile app, or user-agent for web)
        device_info = parse_device_from_headers(request)
        
        # Get location information (from client headers or IP geolocation)
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

    safe_user = {
        "id": str(user.id) if hasattr(user, "id") else None,
        "zynk_entity_id": getattr(user, "zynk_entity_id", None) or getattr(user, "external_entity_id", None),
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
    
    if auth_header and auth_header.lower().startswith("bearer "):
        session_token = auth_header.split(" ", 1)[1].strip()
        
        # Update session logout_at and status
        try:
            session_service = SessionService(prisma)
            await session_service.logout_session(session_token=session_token)
            logger.info(f"[AUTH] Session logged out: {session_token[:16]}...")
        except Exception as e:
            # Log error but don't fail logout (token might be expired/invalid)
            logger.warning(f"[AUTH] Failed to update session on logout: {e}")
    
    # Clear refresh cookie
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
        if auth_header and auth_header.lower().startswith("bearer "):
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
        user_agent = request.headers.get("user-agent")
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
    if not auth_header or not auth_header.lower().startswith("bearer "):
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
