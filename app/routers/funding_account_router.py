from datetime import datetime, timezone
from typing import Any, Dict

from fastapi import APIRouter, Depends, HTTPException, Request, status
from slowapi import Limiter # type: ignore
from slowapi.util import get_remote_address # type: ignore
from prisma.errors import DataError
from prisma.models import entities as Entities # type: ignore
from prisma.enums import KycStatusEnum # type: ignore

from ..core.database import prisma
from ..core import auth
from ..core.config import settings
from ..schemas.funding_account import FundingAccountData, FundingAccountResponse
from ..services.zynk_client import create_funding_account_from_zynk
from ..services.email_service import email_service
from ..services.funding_account_service import save_funding_account_to_db, US_FUNDING_JURISDICTION_ID

router = APIRouter(prefix="/api/v1/account", tags=["funding_account"])

limiter = Limiter(key_func=get_remote_address)


def _build_error_response(
    message: str,
    code: str,
    *,
    status_code: int,
    error_details: Dict[str, Any] | None = None,
) -> HTTPException:
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
    try:
        kyc_session = await prisma.kyc_sessions.find_first(
            where={"entity_id": entity_id, "deleted_at": None}
        )
        
        if not kyc_session:
            return False
        
        return kyc_session.status == KycStatusEnum.APPROVED
    except Exception:
        return False


def _map_funding_account_to_response(funding_account: Any) -> FundingAccountData:
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
    zynk_response_data = await create_funding_account_from_zynk(
        zynk_entity_id,
        US_FUNDING_JURISDICTION_ID
    )
    
    funding_account = await save_funding_account_to_db(str(entity.id), zynk_response_data)
    
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
    except Exception:
        pass
    
    return funding_account


@router.get("/funding", response_model=FundingAccountResponse, status_code=status.HTTP_200_OK)
@limiter.limit("30/minute")
async def get_funding_account(
    request: Request,
    current_entity: Entities = Depends(auth.get_current_entity),
) -> FundingAccountResponse:
    entity_id = current_entity.id
    zynk_entity_id = current_entity.zynk_entity_id
    
    kyc_completed = await _check_kyc_status(str(entity_id))
    if not kyc_completed:
        raise _build_error_response(
            "KYC verification must be completed before accessing funding account",
            code="KYC_NOT_COMPLETED",
            status_code=status.HTTP_403_FORBIDDEN,
        )
    
    if not zynk_entity_id:
        raise _build_error_response(
            "Please complete your profile setup before accessing funding account",
            code="ENTITY_NOT_LINKED",
            status_code=status.HTTP_400_BAD_REQUEST,
        )
    
    try:
        funding_account = await prisma.funding_accounts.find_first(
            where={"entity_id": str(entity_id), "deleted_at": None}
        )
    except DataError:
        raise _build_error_response(
            "Invalid entity identifier",
            code="BAD_REQUEST",
            status_code=status.HTTP_400_BAD_REQUEST,
        )
    except Exception:
        raise _build_error_response(
            "Unable to fetch funding account. Please try again later.",
            code="INTERNAL_ERROR",
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )
    
    if funding_account:
        account_data = _map_funding_account_to_response(funding_account)
        return FundingAccountResponse(
            success=True,
            data=account_data,
            error=None,
            meta={},
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
    request: Request,
    current_entity: Entities = Depends(auth.get_current_entity),
) -> FundingAccountResponse:
    entity_id = current_entity.id
    zynk_entity_id = current_entity.zynk_entity_id
    
    kyc_completed = await _check_kyc_status(str(entity_id))
    if not kyc_completed:
        raise _build_error_response(
            "KYC verification must be completed before creating funding account",
            code="KYC_NOT_COMPLETED",
            status_code=status.HTTP_403_FORBIDDEN,
        )
    
    if not zynk_entity_id:
        raise _build_error_response(
            "Please complete your profile setup before creating funding account",
            code="ENTITY_NOT_LINKED",
            status_code=status.HTTP_400_BAD_REQUEST,
        )
    
    try:
        existing_account = await prisma.funding_accounts.find_first(
            where={"entity_id": str(entity_id), "deleted_at": None}
        )
    except Exception:
        raise _build_error_response(
            "Unable to check existing funding account. Please try again later.",
            code="INTERNAL_ERROR",
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )
    
    if existing_account:
        account_data = _map_funding_account_to_response(existing_account)
        return FundingAccountResponse(
            success=True,
            data=account_data,
            error=None,
            meta={},
        )
    
    try:
        funding_account = await _create_and_save_funding_account(current_entity, zynk_entity_id)
        
        account_data = _map_funding_account_to_response(funding_account)
        return FundingAccountResponse(
            success=True,
            data=account_data,
            error=None,
            meta={},
        )
        
    except HTTPException:
        raise
    except Exception:
        raise _build_error_response(
            "Failed to create funding account. Please try again later.",
            code="CREATION_FAILED",
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )
