from datetime import datetime, timezone
from typing import Any, Dict

from fastapi import APIRouter, Depends, HTTPException, status, Request
from slowapi import Limiter
from slowapi.util import get_remote_address
from prisma.errors import DataError
from prisma.models import entities as Entities # type: ignore

from ..core.database import prisma
from ..core import auth
from ..schemas.kyc import KycLinkData, KycLinkResponse, KycStatusData, KycStatusResponse
from ..services.zynk_client import get_kyc_link_from_zynk
from ..services.email_service import email_service

router = APIRouter(prefix="/api/v1/kyc", tags=["kyc"])

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


US_KYC_ROUTING_ID = "infrap_f2a15c0b_89cf_4041_83fb_8ba064083706"


@router.get("/status", response_model=KycStatusResponse, status_code=status.HTTP_200_OK)
@limiter.limit("30/minute") 
async def get_kyc_status(
    request: Request,
    current_entity: Entities = Depends(auth.get_current_entity),
) -> KycStatusResponse:
    entity_id = current_entity.id

    try:
        kyc_session = await prisma.kyc_sessions.find_first(
            where={"entity_id": entity_id, "deleted_at": None}
        )
    except DataError:
        raise _build_error_response(
            "Invalid entity identifier",
            code="BAD_REQUEST",
            status_code=status.HTTP_400_BAD_REQUEST,
        )
    except Exception:
        raise _build_error_response(
            "Unable to fetch KYC status. Please try again later.",
            code="INTERNAL_ERROR",
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )

    if not kyc_session:
        try:
            kyc_session = await prisma.kyc_sessions.create(
                data={
                    "entity_id": entity_id,
                    "status": "NOT_STARTED",
                    "routing_enabled": False,
                }
            )
        except Exception:
            return KycStatusResponse(
                success=True,
                data=KycStatusData(
                    status="NOT_STARTED",
                    routing_id=None,
                    kyc_link=None,
                    initiated_at=None,
                    completed_at=None,
                    rejection_reason=None,
                ),
                error=None,
                meta={},
            )

    return KycStatusResponse(
        success=True,
        data=KycStatusData(
            status=str(kyc_session.status),
            routing_id=kyc_session.routing_id,
            kyc_link=kyc_session.kyc_link,
            initiated_at=kyc_session.initiated_at,
            completed_at=kyc_session.completed_at,
            rejection_reason=kyc_session.rejection_reason,
        ),
        error=None,
        meta={},
    )


@router.get("/link", response_model=KycLinkResponse, status_code=status.HTTP_200_OK)
@limiter.limit("30/minute")
async def get_kyc_link(
    request: Request,
    current_entity: Entities = Depends(auth.get_current_entity),
) -> KycLinkResponse:
    if not current_entity.zynk_entity_id:
        raise _build_error_response(
            "Please complete your profile setup before starting KYC verification",
            code="ENTITY_NOT_LINKED",
            status_code=status.HTTP_400_BAD_REQUEST,
        )

    zynk_entity_id = current_entity.zynk_entity_id
    entity_id = current_entity.id

    try:
        kyc_session = await prisma.kyc_sessions.find_first(
            where={"entity_id": entity_id, "deleted_at": None}
        )
    except DataError:
        raise _build_error_response(
            "Invalid entity identifier",
            code="BAD_REQUEST",
            status_code=status.HTTP_400_BAD_REQUEST,
        )
    except Exception:
        raise _build_error_response(
            "Unable to look up KYC session. Please try again later.",
            code="INTERNAL_ERROR",
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )

    if not kyc_session:
        try:
            kyc_session = await prisma.kyc_sessions.create(
                data={
                    "entity_id": entity_id,
                    "status": "NOT_STARTED",
                    "routing_enabled": False,
                }
            )
        except Exception:
            raise _build_error_response(
                "Failed to initialize KYC session. Please try again later.",
                code="INTERNAL_ERROR",
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

    status_value = str(kyc_session.status)

    if status_value == "NOT_STARTED":
        routing_id = US_KYC_ROUTING_ID

        try:
            kyc_data = await get_kyc_link_from_zynk(zynk_entity_id, routing_id)
        except HTTPException:
            raise
        except Exception:
            raise _build_error_response(
                "Failed to generate KYC link. Please try again later.",
                code="INTERNAL_ERROR",
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

        if kyc_data.get("kycCompleted"):
            now = datetime.now(timezone.utc)
            try:
                kyc_session = await prisma.kyc_sessions.update(
                    where={"id": kyc_session.id},
                    data={
                        "status": "APPROVED",
                        "completed_at": now,
                    },
                )
            except Exception:
                pass
            return KycLinkResponse(
                success=True,
                data=KycLinkData(
                    message=kyc_data.get(
                        "message", "KYC is already completed for this user."
                    ),
                    kycLink=None,
                    tosLink=None,
                    kycStatus="approved",
                    tosStatus="accepted",
                ),
                error=None,
            )

        now = datetime.now(timezone.utc)
        try:
            kyc_session = await prisma.kyc_sessions.update(
                where={"id": kyc_session.id},
                data={
                    "status": "INITIATED",
                    "routing_id": routing_id,
                    "kyc_link": kyc_data["kycLink"],
                    "initiated_at": now,
                },
            )
        except Exception:
            raise _build_error_response(
                "Failed to persist KYC session. Please try again later.",
                code="INTERNAL_ERROR",
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

        try:
            user_name = f"{current_entity.first_name or ''} {current_entity.last_name or ''}".strip() or "User"
            await email_service.send_kyc_link_email(
                email=current_entity.email,
                user_name=user_name,
                kyc_link=kyc_data["kycLink"],
                timestamp=now,
            )
        except Exception:
            pass

        return KycLinkResponse(
            success=True,
            data=KycLinkData(
                message=kyc_data.get("message", "KYC link generated successfully"),
                kycLink=kyc_data["kycLink"],
                tosLink=kyc_data.get("tosLink"),
                kycStatus=kyc_data.get("kycStatus", "initiated"),
                tosStatus=kyc_data.get("tosStatus", "pending"),
            ),
            error=None,
        )

    if status_value == "INITIATED" and kyc_session.kyc_link:
        return KycLinkResponse(
            success=True,
            data=KycLinkData(
                message="KYC link retrieved successfully",
                kycLink=kyc_session.kyc_link,
                tosLink=None,
                kycStatus=status_value.lower(),
                tosStatus="pending",
            ),
            error=None,
        )

    if status_value == "APPROVED":
        return KycLinkResponse(
            success=True,
            data=KycLinkData(
                message="KYC verification is already completed for this user.",
                kycLink=None,
                tosLink=None,
                kycStatus="approved",
                tosStatus="accepted",
            ),
            error=None,
        )

    if status_value == "REVIEWING":
        return KycLinkResponse(
            success=True,
            data=KycLinkData(
                message="Your KYC verification is currently under review. We will notify you once it's complete.",
                kycLink=None,
                tosLink=None,
                kycStatus=status_value.lower(),
                tosStatus="pending",
            ),
            error=None,
        )

    if status_value == "REJECTED":
        rejection_msg = "Your KYC verification was rejected."
        if kyc_session.rejection_reason:
            rejection_msg += f" Reason: {kyc_session.rejection_reason}"
        return KycLinkResponse(
            success=True,
            data=KycLinkData(
                message=rejection_msg,
                kycLink=None,
                tosLink=None,
                kycStatus=status_value.lower(),
                tosStatus="pending",
            ),
            error=None,
        )

    raise _build_error_response(
        "No active KYC link found for this user",
        code="KYC_LINK_NOT_FOUND",
        status_code=status.HTTP_404_NOT_FOUND,
    )


async def _get_or_create_kyc_session(entity_id: str):
    try:
        kyc_session = await prisma.kyc_sessions.find_first(
            where={"entity_id": entity_id, "deleted_at": None}
        )
        
        if kyc_session:
            return kyc_session
            
        create_data = {
            "entity_id": entity_id,
            "status": "NOT_STARTED",
            "routing_enabled": False,
        }
        
        kyc_session = await prisma.kyc_sessions.create(data=create_data)
        return kyc_session
        
    except DataError:
        raise _build_error_response(
            "Invalid entity identifier",
            code="BAD_REQUEST",
            status_code=status.HTTP_400_BAD_REQUEST,
        )
    except Exception:
        raise