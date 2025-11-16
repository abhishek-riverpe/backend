"""
OTP Verification Schemas

Defines the data structures for OTP generation, verification, and responses.
"""

from pydantic import BaseModel, Field, validator, EmailStr
from typing import Optional, Dict, Any
from datetime import datetime


class OtpSendRequest(BaseModel):
    """Request payload for sending OTP"""
    phone_number: str = Field(..., description="Phone number to send OTP to")
    country_code: str = Field(..., description="Country code (e.g., +1, +91)")

    @validator('phone_number')
    def validate_phone(cls, v):
        """Validate phone number format"""
        # Remove any spaces, dashes, or parentheses
        cleaned = ''.join(filter(str.isdigit, v))
        if len(cleaned) < 7 or len(cleaned) > 15:
            raise ValueError('Phone number must be between 7 and 15 digits')
        return cleaned

    @validator('country_code')
    def validate_country_code(cls, v):
        """Validate country code format"""
        if not v.startswith('+'):
            v = f'+{v}'
        # Remove any non-digit characters except +
        cleaned = '+' + ''.join(filter(str.isdigit, v))
        if len(cleaned) < 2 or len(cleaned) > 5:
            raise ValueError('Invalid country code')
        return cleaned


class OtpVerifyRequest(BaseModel):
    """Request payload for verifying OTP"""
    phone_number: str = Field(..., description="Phone number that received the OTP")
    country_code: str = Field(..., description="Country code (e.g., +1, +91)")
    otp_code: str = Field(..., description="6-digit OTP code")

    @validator('otp_code')
    def validate_otp_code(cls, v):
        """Validate OTP code format"""
        if not v.isdigit():
            raise ValueError('OTP must contain only digits')
        if len(v) != 6:
            raise ValueError('OTP must be exactly 6 digits')
        return v

    @validator('phone_number')
    def validate_phone(cls, v):
        """Validate phone number format"""
        cleaned = ''.join(filter(str.isdigit, v))
        if len(cleaned) < 7 or len(cleaned) > 15:
            raise ValueError('Phone number must be between 7 and 15 digits')
        return cleaned


class OtpSendResponse(BaseModel):
    """Response after sending OTP"""
    success: bool
    message: str
    data: Optional[Dict[str, Any]] = None
    meta: Dict[str, Any] = Field(default_factory=dict)


class OtpVerifyResponse(BaseModel):
    """Response after verifying OTP"""
    success: bool
    message: str
    data: Optional[Dict[str, Any]] = None
    meta: Dict[str, Any] = Field(default_factory=dict)


class OtpData(BaseModel):
    """OTP session data"""
    id: str
    phone_number: str
    country_code: str
    expires_at: datetime
    attempts_remaining: int
    can_resend: bool


# Email OTP Schemas
class EmailOtpSendRequest(BaseModel):
    """Request payload for sending email OTP"""
    email: EmailStr = Field(..., description="Email address to send OTP to")


class EmailOtpVerifyRequest(BaseModel):
    """Request payload for verifying email OTP"""
    email: EmailStr = Field(..., description="Email address that received the OTP")
    otp_code: str = Field(..., description="6-digit OTP code")

    @validator('otp_code')
    def validate_otp_code(cls, v):
        """Validate OTP code format"""
        if not v.isdigit():
            raise ValueError('OTP must contain only digits')
        if len(v) != 6:
            raise ValueError('OTP must be exactly 6 digits')
        return v

