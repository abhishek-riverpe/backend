from fastapi import APIRouter, HTTPException, status, Response, Request, Depends
from datetime import datetime, timezone
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
from ..utils.enums import LoginMethodEnum
from ..services.zynk_client import _auth_header
from passlib.context import CryptContext # type: ignore
from ..services.otp_service import OTPService
from ..services.session_service import SessionService
from ..services.captcha_service import captcha_service
from ..services.email_service import email_service
from ..utils.device_parser import parse_device_from_headers
from ..utils.location_service import get_location_from_client
from ..utils.errors import internal_error, upstream_error

from .security import (
    normalize_email,
    validate_password,
    hash_password,
)
from .transformer import _create_entity_in_zynk
from ..core.auth import get_current_entity

MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_MINUTES = 15
CAPTCHA_REQUIRED_ATTEMPTS = 3  

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
router = APIRouter(
    prefix="/api/v1/auth",
    tags=["auth"],
)

limiter = Limiter(key_func=get_remote_address)

def _set_auth_cookies(response: Response, access_token: str, refresh_token: str):
    is_production = not settings.frontend_url.startswith("http://localhost")
    
    response.set_cookie(
        key="rp_access",
        value=access_token,
        httponly=True,
        samesite="lax" if not is_production else "strict",
        secure=is_production,
        max_age=15 * 60,
        path="/",
    )
    
    response.set_cookie(
        key="rp_refresh",
        value=refresh_token,
        httponly=True,
        samesite="lax" if not is_production else "strict",
        secure=is_production,
        max_age=24 * 60 * 60,
        path="/",
    )

def _create_safe_user_dict(user) -> dict:
    return {
        "id": str(user.id),
        "email": user.email,
        "first_name": user.first_name,
        "last_name": user.last_name,
        "email_verified": user.email_verified,
        "zynk_entity_id": getattr(user, "zynk_entity_id", None) or getattr(user, "external_entity_id", None),
        "entity_type": str(user.entity_type) if user.entity_type else None,
        "status": str(user.status) if user.status else None,
    }

async def _create_session_for_user(user, access_token: str, request: Request):
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
    except Exception:
        pass

def _extract_bearer_token(request: Request) -> str | None:
    auth_header = request.headers.get("authorization") or request.headers.get("Authorization")
    if auth_header and auth_header.lower().startswith("bearer "):
        return auth_header.split(" ", 1)[1].strip()
    return None

async def _email_exists_in_zynk(email: str) -> bool:
    if not settings.zynk_base_url or not settings.zynk_api_key:
        existing = await prisma.entities.find_first(where={"email": email})
        return existing is not None

    url = f"{settings.zynk_base_url}/api/v1/transformer/entity/email/{email}"
    headers = _auth_header()

    try:
        async with httpx.AsyncClient(timeout=settings.zynk_timeout_s) as client:
            resp = await client.get(url, headers=headers)
    except httpx.RequestError:
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
        return True

    error_detail = "Unknown upstream error"
    if isinstance(body, dict):
        error_detail = body.get("message") or body.get("error") or error_detail

    raise HTTPException(
        status_code=status.HTTP_502_BAD_GATEWAY,
        detail=f"Upstream email lookup failed: {error_detail}",
    )

@router.post("/check-captcha-required")
async def check_captcha_required(data: dict):
    email = data.get("email", "").strip()
    
    if not email:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email is required"
        )
    
    email = normalize_email(email)
    user = await prisma.entities.find_unique(where={"email": email})
    
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
@limiter.limit("10/minute") 
async def check_email(data: dict, request: Request):
    email = data.get("email", "").strip()
    
    if not email:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email is required"
        )

    if not "@" in email or "." not in email.split("@")[1]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid email format"
        )

    exists = await _email_exists_in_zynk(email)

    if exists:
        return {
            "available": False,
            "message": "This email is already registered. Please sign in instead.",
        }
        
    return {
        "available": True,
        "message": "Email is available.",
    }

@router.post("/signup", response_model=schemas.AuthResponse, status_code=status.HTTP_201_CREATED)
@limiter.limit("3/minute")
async def signup(user_in: schemas.UserCreate, response: Response, request: Request):

    first_name = user_in.first_name.strip()
    last_name = user_in.last_name.strip()
    email = normalize_email(user_in.email)
    password = user_in.password
    date_of_birth = user_in.date_of_birth.strip()
    nationality = user_in.nationality.strip()
    phone_number = user_in.phone_number.strip()
    country_code = user_in.country_code.strip()
    phone_prefix = country_code.replace('+', '')

    prisma_date_of_birth = None
    if date_of_birth:
        try:
            month, day, year = date_of_birth.split('/')
            zynk_date_of_birth = f"{year}-{month.zfill(2)}-{day.zfill(2)}"
            prisma_date_of_birth = datetime(int(year), int(month), int(day), tzinfo=timezone.utc)
        except (ValueError, TypeError):
            raise internal_error(
                user_message="Invalid date format. Please use MM/DD/YYYY format.",
                status_code=400,
            )
    else:
        zynk_date_of_birth = date_of_birth

    captcha_id = user_in.captcha_id.strip()
    captcha_code = user_in.captcha_code.strip()
    
    is_valid, error_message = captcha_service.validate_captcha(
        captcha_id=captcha_id,
        user_input=captcha_code,
    )
    
    if not is_valid:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=error_message or "Invalid CAPTCHA code. Please try again.",
        )

    try:
        validate_password(password)
    except ValueError as ve:
      
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(ve))

    if await _email_exists_in_zynk(email):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Email already registered",
        )

    pwd_hash = hash_password(password)

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

            try:
                await prisma.kyc_sessions.create(
                    data={
                        "entity_id": entity.id,
                        "status": "NOT_STARTED",
                        "routing_enabled": False,
                    }
                )
            except Exception:
                pass
        except Exception as e:
            try:
                await prisma.entities.delete(where={"id": entity.id})
            except Exception:
                pass
            if isinstance(e, HTTPException):
                raise
            raise upstream_error(
                user_message="Failed to create account with verification service. Please try again later.",
            )

    except UniqueViolationError:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Email already registered")

    access_token = auth.create_access_token(data={"sub": str(entity.id), "type": "access"})
    refresh_token = auth.create_refresh_token(data={"sub": str(entity.id), "type": "refresh"})

    _set_auth_cookies(response, access_token, refresh_token)
    response.headers["Location"] = f"/api/v1/entities/{entity.id}"
    safe_user = _create_safe_user_dict(entity)

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
@limiter.limit("10/minute")
async def signin(payload: schemas.SignInInput, request: Request, response: Response):

    def invalid_credentials():
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
        )
    
    try:
        email = normalize_email(payload.email)
        password = payload.password
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid request payload",
        )
        
    try:
        user = await prisma.entities.find_unique(where={"email": email})
    except DataError:

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
                invalid_credentials()
            
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
        except Exception:
            invalid_credentials()

    if not user:
        invalid_credentials()

    now = datetime.now(timezone.utc)
    captcha_required = False
    
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
            response.headers["X-CAPTCHA-Required"] = "true"
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=error_message or "Invalid CAPTCHA code. Please try again.",
            )

    try:
        ok = pwd_context.verify(password, user.password)
    except Exception:
        ok = False

    if not ok:
        attempts = (user.login_attempts or 0) + 1
        lock_until = None
        detail = "Invalid email or password"

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
            except Exception:
                pass

        if lock_until:
            response.headers["X-Account-Unlock-In"] = str(int((lock_until - now).total_seconds()))
            raise HTTPException(status_code=status.HTTP_423_LOCKED, detail=detail)

        if attempts >= CAPTCHA_REQUIRED_ATTEMPTS:
            response.headers["X-CAPTCHA-Required"] = "true"
            response.headers["X-Login-Attempts"] = str(attempts)

        invalid_credentials()

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
    await _create_session_for_user(user, access_token, request)
    safe_user = _create_safe_user_dict(user)
   
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
    email = normalize_email(payload.email)
    user = await prisma.entities.find_unique(where={"email": email})

    if user:
        otp_service = OTPService(prisma)
        success, message, data = await otp_service.send_password_reset_otp(email=email)

        if not success:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=message,
            )
    else:
        await asyncio.sleep(random.uniform(0.5, 1.5))
    return {
        "success": True,
        "message": "If that email exists, a reset code has been sent.",
        "data": None,
        "error": None,
        "meta": {},
    }

@router.post("/forgot-password/confirm", response_model=schemas.ApiResponse)
async def confirm_password_reset(payload: schemas.ForgotPasswordConfirm):
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
    except PrismaError:
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
async def refresh_token(request: Request, response: Response, body: dict = None):
    rt = request.cookies.get("rp_refresh")
    
    if not rt:
        try:
            body_data = await request.json() if body is None else body
            rt = body_data.get("refresh_token")
        except Exception:
            pass
    
    if not rt:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing refresh token")

    try:
        payload = auth.verify_token_type(rt, "refresh")
        user_id = payload.get("sub")
        if not user_id:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token payload")

        user = await prisma.entities.find_unique(where={"id": user_id})
        if not user:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Entity not found")

        access_token = auth.create_access_token({"sub": str(user.id), "type": "access"})
        refresh_token = auth.create_refresh_token({"sub": str(user.id), "type": "refresh"})

        _set_auth_cookies(response, access_token, refresh_token)
    except HTTPException:
        raise
    except Exception:
        raise internal_error(
            user_message="Token refresh failed. Please log in again.",
            status_code=status.HTTP_401_UNAUTHORIZED,
        )

    await _create_session_for_user(user, access_token, request)
    safe_user = _create_safe_user_dict(user)

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
    session_token = _extract_bearer_token(request)
    
    if session_token:
        try:
            session_service = SessionService(prisma)
            await session_service.logout_session(session_token=session_token)
        except Exception:
            pass
    
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
    current_user=Depends(get_current_entity)
):
    now = datetime.now(timezone.utc)

    password_valid = pwd_context.verify(payload.current_password, current_user.password)
    if not password_valid:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Current password is incorrect"
        )

    if payload.current_password == payload.new_password:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="New password must be different from current password"
        )

    try:
        validate_password(payload.new_password)
    except ValueError as ve:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(ve)
        )

    new_password_hash = hash_password(payload.new_password)

    try:
        await prisma.entities.update(
            where={"id": current_user.id},
            data={
                "password": new_password_hash,
                "login_attempts": 0,
                "locked_until": None,
                "updated_at": now,
            },
        )
    except PrismaError:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Unable to change password. Please try again later."
        )

    try:
        current_session_token = _extract_bearer_token(request)
        session_service = SessionService(prisma)
        await session_service.revoke_all_sessions(
            entity_id=str(current_user.id),
            except_token=current_session_token
        )
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to revoke active sessions after password change."
        )

    try:
        ip_address = getattr(request.client, "host", None)
        device_info = parse_device_from_headers(request)
        location_info = await get_location_from_client(request)
        user_name = f"{current_user.first_name or ''} {current_user.last_name or ''}".strip() or current_user.email

        await email_service.send_password_change_notification(
            email=current_user.email,
            user_name=user_name,
            device_info=device_info,
            location_info=location_info,
            ip_address=ip_address,
            timestamp=now
        )
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Password was changed, but notification email could not be sent."
        )

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
    token = _extract_bearer_token(request)
    if not token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing bearer token")
    auth.verify_token_type(token, "access")
    return {"success": True, "message": "pong", "data": {"time": datetime.now(timezone.utc).isoformat()}}

@router.post("/logout-all", response_model=schemas.ApiResponse)
async def logout_all_devices(request: Request, response: Response, current_user=Depends(get_current_entity)):

    try:
        session_service = SessionService(prisma)
        revoked = await session_service.revoke_all_sessions(entity_id=str(current_user.id))
        response.delete_cookie("rp_access", path="/")
        response.delete_cookie("rp_refresh", path="/")
        return {
            "success": True,
            "message": f"Logged out from all devices ({revoked} sessions revoked)",
            "data": {"revoked": revoked},
            "error": None,
            "meta": {},
        }
    except Exception:
        raise HTTPException(status_code=500, detail="Failed to logout from all devices")
