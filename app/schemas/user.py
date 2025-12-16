"""
Schemas for user profile and onboarding endpoints.
"""

from pydantic import BaseModel, EmailStr, Field
from typing import Optional, Any, Dict, List
from datetime import datetime
from enum import Enum


class UserStatusEnum(str, Enum):
    REGISTERED = "REGISTERED"
    PENDING = "PENDING"
    ACTIVE = "ACTIVE"
    SUSPENDED = "SUSPENDED"
    CLOSED = "CLOSED"


class EntityTypeEnum(str, Enum):
    INDIVIDUAL = "INDIVIDUAL"
    BUSINESS = "BUSINESS"


class OnboardingStep(BaseModel):
    complete: bool
    required_fields: Optional[List[str]] = None
    status: Optional[str] = None


class OnboardingSteps(BaseModel):
    auth: OnboardingStep
    profile: OnboardingStep
    zynk_entity: OnboardingStep
    kyc: OnboardingStep


class NextActionEnum(str, Enum):
    COMPLETE_PROFILE = "COMPLETE_PROFILE"
    COMPLETE_KYC = "COMPLETE_KYC"
    NONE = "NONE"


# ----------------------
# Response Models
# ----------------------

class UserProfile(BaseModel):
    """User profile data returned from API."""
    id: str
    auth0_sub: str
    email: EmailStr
    email_verified: Optional[bool] = None
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    phone_number: Optional[str] = None
    country_code: Optional[str] = None
    date_of_birth: Optional[str] = None
    nationality: Optional[str] = None
    entity_type: EntityTypeEnum = EntityTypeEnum.INDIVIDUAL
    status: UserStatusEnum
    zynk_entity_id: Optional[str] = None
    last_login_at: Optional[str] = None
    created_at: Optional[str] = None
    updated_at: Optional[str] = None

    class Config:
        from_attributes = True


class OnboardingStatus(BaseModel):
    """Onboarding progress status."""
    status: UserStatusEnum
    steps: OnboardingSteps
    next_action: NextActionEnum


class ApiResponse(BaseModel):
    """Standard API response wrapper."""
    success: bool
    message: str
    data: Optional[Any] = None
    error: Optional[Dict[str, Any]] = None
    meta: Optional[Dict[str, Any]] = None


class UserProfileResponse(ApiResponse):
    """Response for user profile endpoints."""
    data: Optional[UserProfile] = None


class OnboardingStatusResponse(ApiResponse):
    """Response for onboarding status endpoint."""
    data: Optional[OnboardingStatus] = None


# ----------------------
# Request Models
# ----------------------

class CompleteProfileRequest(BaseModel):
    """
    Request body for completing profile and creating Zynk entity.
    All fields are required to proceed with Zynk entity creation.
    """
    first_name: str = Field(..., min_length=1, max_length=60, description="User's first name")
    last_name: str = Field(..., min_length=1, max_length=60, description="User's last name")
    date_of_birth: str = Field(
        ...,
        min_length=10,
        max_length=10,
        description="Date of birth in YYYY-MM-DD format",
        pattern=r"^\d{4}-\d{2}-\d{2}$"
    )
    nationality: str = Field(
        ...,
        min_length=2,
        max_length=3,
        description="ISO 3166-1 alpha-2 or alpha-3 country code"
    )
    phone_number: str = Field(
        ...,
        min_length=5,
        max_length=20,
        description="Phone number without country code"
    )
    country_code: str = Field(
        ...,
        min_length=1,
        max_length=5,
        description="Phone country code (e.g., '+1', '+91')"
    )
    entity_type: EntityTypeEnum = Field(
        default=EntityTypeEnum.INDIVIDUAL,
        description="Entity type: INDIVIDUAL or BUSINESS"
    )


class UpdateProfileRequest(BaseModel):
    """
    Request body for updating user profile.
    All fields are optional - only provided fields will be updated.
    """
    first_name: Optional[str] = Field(None, min_length=1, max_length=60)
    last_name: Optional[str] = Field(None, min_length=1, max_length=60)
    phone_number: Optional[str] = Field(None, min_length=5, max_length=20)
    country_code: Optional[str] = Field(None, min_length=1, max_length=5)
