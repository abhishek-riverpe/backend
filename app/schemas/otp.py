from pydantic import BaseModel, Field, field_validator, EmailStr
from typing import Optional, Dict, Any
from datetime import datetime


class OtpSendRequest(BaseModel):
    phone_number: str = Field(..., description="Phone number to send OTP to")
    country_code: str = Field(..., description="Country code (e.g., +1, +91)")

    @field_validator('phone_number')
    @classmethod
    def validate_phone(cls, v):
        cleaned = ''.join(filter(str.isdigit, v))
        if len(cleaned) < 7 or len(cleaned) > 15:
            raise ValueError('Phone number must be between 7 and 15 digits')
        return cleaned

    @field_validator('country_code')
    @classmethod
    def validate_country_code(cls, v):
        if not v.startswith('+'):
            v = f'+{v}'
        cleaned = '+' + ''.join(filter(str.isdigit, v))
        if len(cleaned) < 2 or len(cleaned) > 5:
            raise ValueError('Invalid country code')
        return cleaned


class OtpVerifyRequest(BaseModel):
    phone_number: str = Field(..., description="Phone number that received the OTP")
    country_code: str = Field(..., description="Country code (e.g., +1, +91)")
    otp_code: str = Field(..., description="6-digit OTP code")

    @field_validator('otp_code')
    @classmethod
    def validate_otp_code(cls, v):
        if not v.isdigit():
            raise ValueError('OTP must contain only digits')
        if len(v) != 6:
            raise ValueError('OTP must be exactly 6 digits')
        return v

    @field_validator('phone_number')
    @classmethod
    def validate_phone(cls, v):
        cleaned = ''.join(filter(str.isdigit, v))
        if len(cleaned) < 7 or len(cleaned) > 15:
            raise ValueError('Phone number must be between 7 and 15 digits')
        return cleaned


class OtpSendResponse(BaseModel):
    success: bool
    message: str
    data: Optional[Dict[str, Any]] = None
    meta: Dict[str, Any] = Field(default_factory=dict)


class OtpVerifyResponse(BaseModel):
    success: bool
    message: str
    data: Optional[Dict[str, Any]] = None
    meta: Dict[str, Any] = Field(default_factory=dict)


class OtpData(BaseModel):
    id: str
    phone_number: str
    country_code: str
    expires_at: datetime
    attempts_remaining: int
    can_resend: bool


class EmailOtpSendRequest(BaseModel):
    email: EmailStr = Field(..., description="Email address to send OTP to")


class EmailOtpVerifyRequest(BaseModel):
    email: EmailStr = Field(..., description="Email address that received the OTP")
    otp_code: str = Field(..., description="6-digit OTP code")

    @field_validator('otp_code')
    @classmethod
    def validate_otp_code(cls, v):
        if not v.isdigit():
            raise ValueError('OTP must contain only digits')
        if len(v) != 6:
            raise ValueError('OTP must be exactly 6 digits')
        return v

