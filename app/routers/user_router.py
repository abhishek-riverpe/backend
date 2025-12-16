"""
User profile and onboarding routes.

These routes handle:
- Getting current user profile (with JIT creation on first Auth0 login)
- Completing profile to create Zynk entity (REGISTERED -> PENDING)
- Updating profile
- Getting onboarding status
"""

from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, status, Request
from slowapi import Limiter
from slowapi.util import get_remote_address
from prisma.models import entities as Entities  # type: ignore

from ..core.database import prisma
from ..core.auth0 import get_current_user
from ..core.config import settings
from ..schemas.user import (
    UserProfile,
    UserProfileResponse,
    OnboardingStatus,
    OnboardingStatusResponse,
    OnboardingStep,
    OnboardingSteps,
    CompleteProfileRequest,
    UpdateProfileRequest,
    UserStatusEnum,
    NextActionEnum,
    ApiResponse,
)
from ..utils.errors import upstream_error, internal_error
from .transformer import _create_entity_in_zynk

limiter = Limiter(key_func=get_remote_address)

router = APIRouter(
    prefix="/api/v1/users",
    tags=["users"],
)


def _entity_to_profile(entity: Entities) -> UserProfile:
    """Convert database entity to UserProfile response model."""
    return UserProfile(
        id=str(entity.id),
        auth0_sub=entity.auth0_sub,
        email=entity.email,
        email_verified=entity.email_verified,
        first_name=entity.first_name,
        last_name=entity.last_name,
        phone_number=entity.phone_number,
        country_code=entity.country_code,
        date_of_birth=entity.date_of_birth.strftime("%Y-%m-%d") if entity.date_of_birth else None,
        nationality=entity.nationality,
        entity_type=entity.entity_type,
        status=entity.status,
        zynk_entity_id=entity.zynk_entity_id,
        last_login_at=entity.last_login_at.isoformat() if entity.last_login_at else None,
        created_at=entity.created_at.isoformat() if entity.created_at else None,
        updated_at=entity.updated_at.isoformat() if entity.updated_at else None,
    )


def _get_onboarding_status(entity: Entities) -> OnboardingStatus:
    """Calculate onboarding status from entity."""
    status_value = UserStatusEnum(entity.status)

    # Auth step - always complete if we have an entity
    auth_step = OnboardingStep(complete=True)

    # Profile step - check required fields
    profile_required_fields = ["first_name", "last_name", "date_of_birth", "nationality", "phone_number", "country_code"]
    missing_fields = [f for f in profile_required_fields if not getattr(entity, f, None)]
    profile_complete = len(missing_fields) == 0
    profile_step = OnboardingStep(
        complete=profile_complete,
        required_fields=missing_fields if missing_fields else None
    )

    # Zynk entity step
    zynk_complete = entity.zynk_entity_id is not None
    zynk_step = OnboardingStep(complete=zynk_complete)

    # KYC step - check status
    kyc_complete = entity.status == "ACTIVE"
    kyc_status = None
    if entity.status == "PENDING":
        kyc_status = "IN_PROGRESS"
    elif entity.status == "ACTIVE":
        kyc_status = "APPROVED"
    kyc_step = OnboardingStep(complete=kyc_complete, status=kyc_status)

    # Determine next action
    if status_value == UserStatusEnum.REGISTERED:
        next_action = NextActionEnum.COMPLETE_PROFILE
    elif status_value == UserStatusEnum.PENDING:
        next_action = NextActionEnum.COMPLETE_KYC
    else:
        next_action = NextActionEnum.NONE

    return OnboardingStatus(
        status=status_value,
        steps=OnboardingSteps(
            auth=auth_step,
            profile=profile_step,
            zynk_entity=zynk_step,
            kyc=kyc_step
        ),
        next_action=next_action
    )


@router.get("/me", response_model=UserProfileResponse)
@limiter.limit("60/minute")
async def get_me(
    request: Request,
    current_user: Entities = Depends(get_current_user)
):
    """
    Get current user profile.

    This endpoint:
    - Verifies the Auth0 access token
    - Creates user on first login (JIT provisioning)
    - Returns user profile with current status
    """
    profile = _entity_to_profile(current_user)

    return UserProfileResponse(
        success=True,
        message="User profile retrieved successfully",
        data=profile
    )


@router.get("/me/onboarding-status", response_model=OnboardingStatusResponse)
@limiter.limit("60/minute")
async def get_onboarding_status(
    request: Request,
    current_user: Entities = Depends(get_current_user)
):
    """
    Get current onboarding progress.

    Returns:
    - Current status (REGISTERED, PENDING, ACTIVE, etc.)
    - Completion status of each onboarding step
    - Next action required
    """
    onboarding = _get_onboarding_status(current_user)

    return OnboardingStatusResponse(
        success=True,
        message="Onboarding status retrieved successfully",
        data=onboarding
    )


@router.post("/me/profile", response_model=UserProfileResponse, status_code=status.HTTP_200_OK)
@limiter.limit("10/minute")
async def complete_profile(
    request: Request,
    payload: CompleteProfileRequest,
    current_user: Entities = Depends(get_current_user)
):
    """
    Complete user profile and create Zynk entity.

    This endpoint:
    1. Validates that user is in REGISTERED status
    2. Updates profile with provided data
    3. Creates entity in Zynk Labs
    4. Updates status to PENDING
    5. Creates initial KYC session

    Required fields:
    - first_name, last_name
    - date_of_birth (YYYY-MM-DD)
    - nationality (ISO country code)
    - phone_number, country_code
    """
    # Verify user is in REGISTERED status
    if current_user.status != "REGISTERED":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Profile already completed. Current status: {current_user.status}"
        )

    # Parse date of birth
    try:
        dob_parts = payload.date_of_birth.split("-")
        prisma_dob = datetime(int(dob_parts[0]), int(dob_parts[1]), int(dob_parts[2]))
        # Format for Zynk API (DD/MM/YYYY)
        zynk_dob = f"{dob_parts[2]}/{dob_parts[1]}/{dob_parts[0]}"
    except (ValueError, IndexError):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid date_of_birth format. Use YYYY-MM-DD"
        )

    # Prepare phone prefix (ensure it starts with +)
    phone_prefix = payload.country_code
    if not phone_prefix.startswith("+"):
        phone_prefix = f"+{phone_prefix}"

    # Update entity with profile data first
    try:
        entity = await prisma.entities.update(
            where={"id": current_user.id},
            data={
                "first_name": payload.first_name,
                "last_name": payload.last_name,
                "date_of_birth": prisma_dob,
                "nationality": payload.nationality,
                "phone_number": payload.phone_number,
                "country_code": payload.country_code,
                "entity_type": payload.entity_type.value,
            }
        )
    except Exception as e:
        raise internal_error(user_message="Failed to update profile. Please try again.")

    # Create entity in Zynk
    zynk_payload = {
        "firstName": payload.first_name,
        "lastName": payload.last_name,
        "email": current_user.email,
        "dateOfBirth": zynk_dob,
        "nationality": payload.nationality,
        "phoneNumber": payload.phone_number,
        "phoneNumberPrefix": phone_prefix,
        "countryCode": payload.country_code,
        "type": "individual" if payload.entity_type.value == "INDIVIDUAL" else "business"
    }

    try:
        zynk_response = await _create_entity_in_zynk(zynk_payload)
        zynk_entity_id = zynk_response.get("data", {}).get("entityId")

        if not zynk_entity_id:
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail="Failed to get entity ID from verification service"
            )

        # Update entity with Zynk ID and change status to PENDING
        # Also create initial KYC session
        async with prisma.tx() as tx:
            entity = await tx.entities.update(
                where={"id": current_user.id},
                data={
                    "zynk_entity_id": zynk_entity_id,
                    "status": "PENDING",
                }
            )

            # Create KYC session
            await tx.kyc_sessions.create(
                data={
                    "entity_id": current_user.id,
                    "routing_id": settings.zynk_default_routing_id,
                    "status": "NOT_STARTED",
                }
            )

    except HTTPException:
        # Re-raise HTTP exceptions (from Zynk client)
        raise
    except Exception as e:
        # Revert profile update on failure
        await prisma.entities.update(
            where={"id": current_user.id},
            data={
                "first_name": current_user.first_name,
                "last_name": current_user.last_name,
                "date_of_birth": current_user.date_of_birth,
                "nationality": current_user.nationality,
                "phone_number": current_user.phone_number,
                "country_code": current_user.country_code,
                "entity_type": current_user.entity_type,
            }
        )
        raise upstream_error(
            user_message="Failed to create entity in verification service. Please try again."
        )

    profile = _entity_to_profile(entity)

    return UserProfileResponse(
        success=True,
        message="Profile completed successfully. Please proceed with KYC verification.",
        data=profile
    )


@router.patch("/me", response_model=UserProfileResponse)
@limiter.limit("30/minute")
async def update_profile(
    request: Request,
    payload: UpdateProfileRequest,
    current_user: Entities = Depends(get_current_user)
):
    """
    Update user profile.

    Only certain fields can be updated:
    - first_name, last_name (if status is REGISTERED)
    - phone_number, country_code

    Note: date_of_birth and nationality cannot be changed after profile completion.
    """
    update_data = {}

    # Only allow name changes if still in REGISTERED status
    if payload.first_name is not None:
        if current_user.status != "REGISTERED":
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Cannot change name after profile completion"
            )
        update_data["first_name"] = payload.first_name

    if payload.last_name is not None:
        if current_user.status != "REGISTERED":
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Cannot change name after profile completion"
            )
        update_data["last_name"] = payload.last_name

    # Phone can always be updated
    if payload.phone_number is not None:
        update_data["phone_number"] = payload.phone_number

    if payload.country_code is not None:
        update_data["country_code"] = payload.country_code

    if not update_data:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No valid fields to update"
        )

    try:
        entity = await prisma.entities.update(
            where={"id": current_user.id},
            data=update_data
        )
    except Exception as e:
        raise internal_error(user_message="Failed to update profile. Please try again.")

    profile = _entity_to_profile(entity)

    return UserProfileResponse(
        success=True,
        message="Profile updated successfully",
        data=profile
    )
