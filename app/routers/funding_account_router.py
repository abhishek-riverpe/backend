"""
Funding Account Router

Handles funding account creation, retrieval, and management.
"""
import logging
from datetime import datetime, timezone
from typing import Any, Dict

from fastapi import APIRouter, Depends, HTTPException, Request, status
from slowapi import Limiter
from slowapi.util import get_remote_address
from prisma.errors import DataError
from prisma.models import entities as Entities
from prisma.enums import KycStatusEnum

from ..core.database import prisma
from ..core import auth
from ..core.config import settings
from ..schemas.funding_account import FundingAccountData, FundingAccountResponse
from ..services.zynk_client import create_funding_account_from_zynk
from ..services.email_service import email_service
from ..services.funding_account_service import save_funding_account_to_db, US_FUNDING_JURISDICTION_ID
from ..utils.errors import upstream_error

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/account", tags=["funding_account"])

# FIXED: HIGH-04 - Rate limiter for preventing resource exhaustion attacks
limiter = Limiter(key_func=get_remote_address)


def _build_error_response(
    message: str,
    code: str,
    *,
    status_code: int,
    error_details: Dict[str, Any] | None = None,
) -> HTTPException:
    """Build a standardized error response for the API"""
    return HTTPException(
        status_code=status_code,
        detail={
            "success": False,
            "data": None,
            "error": {"code": code, "message": message, "details": error_details or {}},
            "meta": {},
        },
    )


async def _check_kyc_status(entity_id: str) -> bool:
    """
    Check if user's KYC is COMPLETED (APPROVED status).
    
    Returns:
        True if KYC is APPROVED, False otherwise
    """
    try:
        kyc_session = await prisma.kyc_sessions.find_first(
            where={"entity_id": entity_id, "deleted_at": None}
        )
        
        if not kyc_session:
            return False
        
        return kyc_session.status == KycStatusEnum.APPROVED
    except Exception as exc:
        logger.error(f"[FUNDING] Error checking KYC status for entity_id={entity_id}", exc_info=exc)
        return False


def _map_funding_account_to_response(funding_account: Any) -> FundingAccountData:
    """Map Prisma funding account model to Pydantic response schema"""
    return FundingAccountData(
        id=str(funding_account.id),
        entity_id=str(funding_account.entity_id),
        jurisdiction_id=funding_account.jurisdiction_id,
        provider_id=funding_account.provider_id,
        status=str(funding_account.status),
        currency=funding_account.currency,
        bank_name=funding_account.bank_name,
        bank_address=funding_account.bank_address,
        bank_routing_number=funding_account.bank_routing_number,
        bank_account_number=funding_account.bank_account_number,
        bank_beneficiary_name=funding_account.bank_beneficiary_name or "",
        bank_beneficiary_address=funding_account.bank_beneficiary_address,
        payment_rail=funding_account.payment_rail,
        created_at=funding_account.created_at,
        updated_at=funding_account.updated_at,
    )


async def _create_and_save_funding_account(
    entity: Entities,
    zynk_entity_id: str
) -> Any:
    """
    Create funding account via Zynk Labs API and save to database.
    
    Returns:
        Created funding account record from database
    """
    logger.info(f"[FUNDING] Creating funding account via Zynk Labs for entity_id={entity.id}, zynk_entity_id={zynk_entity_id}")
    
    # Call Zynk Labs API to create funding account
    zynk_response_data = await create_funding_account_from_zynk(
        zynk_entity_id,
        US_FUNDING_JURISDICTION_ID
    )
    
    # Save to database
    funding_account = await save_funding_account_to_db(str(entity.id), zynk_response_data)
    
    # Send email notification
    try:
        account_info = zynk_response_data.get("accountInfo", {})
        user_name = f"{entity.first_name or ''} {entity.last_name or ''}".strip() or "User"
        email_sent = await email_service.send_funding_account_created_notification(
            email=entity.email,
            user_name=user_name,
            bank_name=account_info.get("bank_name", ""),
            bank_account_number=account_info.get("bank_account_number", ""),
            bank_routing_number=account_info.get("bank_routing_number", ""),
            currency=account_info.get("currency", "USD").upper(),
            timestamp=datetime.now(timezone.utc),
        )
        if email_sent:
            logger.info(f"[FUNDING] Funding account creation email sent to {entity.email}")
        else:
            logger.warning(f"[FUNDING] Failed to send funding account creation email to {entity.email}")
    except Exception as email_exc:
        # Don't fail the request if email fails
        logger.error(f"[FUNDING] Error sending funding account creation email: {email_exc}", exc_info=email_exc)
    
    return funding_account


@router.get("/funding", response_model=FundingAccountResponse, status_code=status.HTTP_200_OK)
@limiter.limit("30/minute")
async def get_funding_account(
    request: Request,  # pyright: ignore[reportUnusedParameter]
    current_entity: Entities = Depends(auth.get_current_entity),
) -> FundingAccountResponse:
    """
    Get funding account for the authenticated user.
    
    Flow:
    1. Check if user's KYC is COMPLETED (APPROVED status)
    2. Check if funding account exists in local DB
    3. If exists → return account details
    4. If not exists → attempt to create via Zynk Labs API
       - If creation succeeds: save to DB, send email, return details
       - If creation fails: return "system under maintenance" message
    """
    entity_id = current_entity.id
    zynk_entity_id = current_entity.zynk_entity_id
    
    logger.info(
        f"[FUNDING] Funding account request received - entity_id={entity_id}, "
        f"zynk_entity_id={zynk_entity_id}"
    )
    
    # Check KYC status - must be APPROVED
    kyc_completed = await _check_kyc_status(str(entity_id))
    if not kyc_completed:
        logger.warning(
            f"[FUNDING] KYC not completed for entity_id={entity_id}. Cannot access funding account."
        )
        raise _build_error_response(
            "KYC verification must be completed before accessing funding account",
            code="KYC_NOT_COMPLETED",
            status_code=status.HTTP_403_FORBIDDEN,
        )
    
    # Check if entity is linked to Zynk Labs
    if not zynk_entity_id:
        logger.warning(
            f"[FUNDING] Entity {entity_id} not linked to ZynkLabs. "
            f"User must complete profile setup first."
        )
        raise _build_error_response(
            "Please complete your profile setup before accessing funding account",
            code="ENTITY_NOT_LINKED",
            status_code=status.HTTP_400_BAD_REQUEST,
        )
    
    # Check if funding account exists in local DB
    try:
        funding_account = await prisma.funding_accounts.find_first(
            where={"entity_id": str(entity_id), "deleted_at": None}
        )
    except DataError as exc:
        logger.error(
            f"[FUNDING] DataError while fetching funding account for entity_id={entity_id}",
            exc_info=exc,
        )
        raise _build_error_response(
            "Invalid entity identifier",
            code="BAD_REQUEST",
            status_code=status.HTTP_400_BAD_REQUEST,
        )
    except Exception as exc:
        logger.error(
            f"[FUNDING] Unexpected error while fetching funding account for entity_id={entity_id}",
            exc_info=exc,
        )
        raise _build_error_response(
            "Unable to fetch funding account. Please try again later.",
            code="INTERNAL_ERROR",
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )
    
    # If funding account exists, return it
    if funding_account:
        logger.info(
            f"[FUNDING] Returning existing funding account - id={funding_account.id}, entity_id={entity_id}"
        )
        account_data = _map_funding_account_to_response(funding_account)
        return FundingAccountResponse(
            success=True,
            data=account_data,
            error=None,
            meta={},
        )
    
    # No funding account exists - return empty response (don't auto-create)
    logger.info(
        f"[FUNDING] No funding account found for entity_id={entity_id}. "
        f"Returning empty response."
    )
    
    return FundingAccountResponse(
        success=True,
        data=None,
        error=None,
        meta={},
    )


@router.post("/funding/create", response_model=FundingAccountResponse, status_code=status.HTTP_201_CREATED)
@limiter.limit("10/minute")
async def create_funding_account(
    request: Request,  # pyright: ignore[reportUnusedParameter]
    current_entity: Entities = Depends(auth.get_current_entity),
) -> FundingAccountResponse:
    """
    Manually create funding account for the authenticated user.
    
    This endpoint allows users to manually trigger funding account creation
    when clicking a button in the UI.
    
    Flow:
    1. Check if user's KYC is COMPLETED
    2. Check if funding account already exists
    3. Call Zynk Labs API to create funding account
    4. Save to database
    5. Send email notification
    6. Return account details
    """
    entity_id = current_entity.id
    zynk_entity_id = current_entity.zynk_entity_id
    
    logger.info(
        f"[FUNDING] Manual funding account creation request - entity_id={entity_id}, "
        f"zynk_entity_id={zynk_entity_id}"
    )
    
    # Check KYC status - must be APPROVED
    kyc_completed = await _check_kyc_status(str(entity_id))
    if not kyc_completed:
        logger.warning(
            f"[FUNDING] KYC not completed for entity_id={entity_id}. Cannot create funding account."
        )
        raise _build_error_response(
            "KYC verification must be completed before creating funding account",
            code="KYC_NOT_COMPLETED",
            status_code=status.HTTP_403_FORBIDDEN,
        )
    
    # Check if entity is linked to Zynk Labs
    if not zynk_entity_id:
        logger.warning(
            f"[FUNDING] Entity {entity_id} not linked to ZynkLabs. "
            f"User must complete profile setup first."
        )
        raise _build_error_response(
            "Please complete your profile setup before creating funding account",
            code="ENTITY_NOT_LINKED",
            status_code=status.HTTP_400_BAD_REQUEST,
        )
    
    # Check if funding account already exists
    try:
        existing_account = await prisma.funding_accounts.find_first(
            where={"entity_id": str(entity_id), "deleted_at": None}
        )
    except Exception as exc:
        logger.error(
            f"[FUNDING] Error checking existing funding account for entity_id={entity_id}",
            exc_info=exc,
        )
        raise _build_error_response(
            "Unable to check existing funding account. Please try again later.",
            code="INTERNAL_ERROR",
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )
    
    if existing_account:
        logger.info(
            f"[FUNDING] Funding account already exists for entity_id={entity_id}. "
            f"Returning existing account."
        )
        account_data = _map_funding_account_to_response(existing_account)
        return FundingAccountResponse(
            success=True,
            data=account_data,
            error=None,
            meta={},
        )
    
    # Create funding account
    try:
        funding_account = await _create_and_save_funding_account(current_entity, zynk_entity_id)
        
        logger.info(
            f"[FUNDING] Successfully created funding account via manual request - "
            f"id={funding_account.id}, entity_id={entity_id}"
        )
        
        account_data = _map_funding_account_to_response(funding_account)
        return FundingAccountResponse(
            success=True,
            data=account_data,
            error=None,
            meta={},
        )
        
    except HTTPException:
        # Re-raise HTTP exceptions as-is
        raise
    except Exception as exc:
        logger.error(
            f"[FUNDING] Failed to create funding account for entity_id={entity_id}",
            exc_info=exc,
        )
        raise _build_error_response(
            "Failed to create funding account. Please try again later.",
            code="CREATION_FAILED",
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )
