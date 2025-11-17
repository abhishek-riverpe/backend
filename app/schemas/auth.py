from pydantic import BaseModel, EmailStr, Field
from typing import Optional, Any, Dict

class SignInInput(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=1)
    captcha_id: Optional[str] = Field(None, description="CAPTCHA identifier (required if login_attempts >= 3)")
    captcha_code: Optional[str] = Field(None, min_length=5, max_length=5, description="CAPTCHA code entered by user (required if login_attempts >= 3)")
    
class UserCreate(BaseModel):
    first_name: str = Field(..., min_length=1, max_length=60)
    last_name: str = Field(..., min_length=1, max_length=60)
    email: EmailStr
    password: str = Field(..., min_length=8, max_length=128)
    date_of_birth: str = Field(..., min_length=1)
    nationality: str = Field(..., min_length=1, max_length=3)  # Country code like 'US', 'IN'
    phone_number: str = Field(..., min_length=1)
    country_code: str = Field(..., min_length=1)
    captcha_id: str = Field(..., description="CAPTCHA identifier")
    captcha_code: str = Field(..., min_length=5, max_length=5, description="CAPTCHA code entered by user")

class ForgotPasswordRequest(BaseModel):
    email: EmailStr


class ForgotPasswordConfirm(BaseModel):
    email: EmailStr
    otp_code: str = Field(..., min_length=6, max_length=6)
    new_password: str = Field(..., min_length=8, max_length=128)


class CaptchaGenerateResponse(BaseModel):
    captcha_id: str
    captcha_code: str
    expires_in_seconds: int


class CaptchaValidateRequest(BaseModel):
    captcha_id: str
    captcha_code: str = Field(..., min_length=5, max_length=5)


class ChangePasswordRequest(BaseModel):
    current_password: str = Field(..., min_length=1, description="Current password")
    new_password: str = Field(..., min_length=8, max_length=128, description="New password")


# -----------------------------
# Unified API response schemas
# -----------------------------

class UserOut(BaseModel):
    entity_id: Optional[str] = None
    zynk_entity_id: Optional[str] = None
    entity_type: Optional[str] = None
    email: Optional[EmailStr] = None
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    email_verified: Optional[bool] = None
    last_login_at: Optional[str] = None
    login_attempts: Optional[int] = None
    locked_until: Optional[str] = None
    status: Optional[str] = None
    created_at: Optional[str] = None
    updated_at: Optional[str] = None

class AuthData(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    user: UserOut

class ApiResponse(BaseModel):
    success: bool
    message: str
    data: Optional[Any] = None
    error: Optional[Dict[str, Any]] = None
    meta: Optional[Dict[str, Any]] = None

class AuthResponse(ApiResponse):
    data: AuthData

