from datetime import datetime, timezone
import logging
from typing import Any, Dict

from fastapi import APIRouter, Depends, HTTPException, status, Request
from slowapi import Limiter
from slowapi.util import get_remote_address
from prisma.errors import DataError
from prisma.models import entities as Entities

from ..core.database import prisma
from ..core import auth
from ..schemas.kyc import KycLinkData, KycLinkResponse, KycStatusData, KycStatusResponse
from ..services.zynk_client import get_kyc_link_from_zynk
from ..services.email_service import email_service

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/kyc", tags=["kyc"])

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


# Fixed routing id for US-based KYC flow
US_KYC_ROUTING_ID = "infrap_f2a15c0b_89cf_4041_83fb_8ba064083706"


@router.get("/status", response_model=KycStatusResponse, status_code=status.HTTP_200_OK)
@limiter.limit("30/minute")  # Reuse KYC rate limiting to avoid status polling abuse
async def get_kyc_status(
    request: Request,  # pyright: ignore[reportUnusedParameter]
    current_entity: Entities = Depends(auth.get_current_entity),
) -> KycStatusResponse:
    entity_id = current_entity.id
    logger.info(f"[KYC] KYC status request received - entity_id={entity_id}")

    try:
        kyc_session = await prisma.kyc_sessions.find_first(
            where={"entity_id": entity_id, "deleted_at": None}
        )
    except DataError as exc:
        logger.error(
            f"[KYC] DataError while fetching KYC status for entity_id={entity_id}",
            exc_info=exc,
        )
        raise _build_error_response(
            "Invalid entity identifier",
            code="BAD_REQUEST",
            status_code=status.HTTP_400_BAD_REQUEST,
        )
    except Exception as exc:
        logger.error(
            f"[KYC] Unexpected error while fetching KYC status for entity_id={entity_id}",
            exc_info=exc,
        )
        raise _build_error_response(
            "Unable to fetch KYC status. Please try again later.",
            code="INTERNAL_ERROR",
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )

    if not kyc_session:
        logger.info(
            f"[KYC] No KYC session found for entity_id={entity_id}. Returning NOT_STARTED."
        )
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

    logger.info(
        "[KYC] Returning KYC status for entity_id=%s, session_id=%s, status=%s",
        entity_id,
        kyc_session.id,
        kyc_session.status,
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


@router.get("", response_model=KycLinkResponse, status_code=status.HTTP_200_OK)
@router.get("/link", response_model=KycLinkResponse, status_code=status.HTTP_200_OK)
@limiter.limit("30/minute")  # FIXED: HIGH-04 - Rate limit to prevent KYC resource exhaustion
async def get_kyc_link(
    request: Request,  # pyright: ignore[reportUnusedParameter]
    current_entity: Entities = Depends(auth.get_current_entity),
) -> KycLinkResponse:
    """
    Get KYC verification link for the authenticated user.

    Behaviour:
    - If no KYC session exists: call Zynk to generate a link, create a session
      with status INITIATED, and return the link.
    - If a session exists with status INITIATED: return the stored link.
    - Otherwise: return 404 (no active KYC link).
    """
    logger.info(
        f"[KYC] KYC link request received - id={current_entity.id}, "
        f"email={current_entity.email}, zynk_entity_id={current_entity.zynk_entity_id}"
    )
    
    # Ensure entity is linked to ZyncLabs
    if not current_entity.zynk_entity_id:
        logger.warning(
            f"[KYC] Entity {current_entity.id} not linked to ZyncLabs. "
            f"User must complete profile setup first."
        )
        raise _build_error_response(
            "Please complete your profile setup before starting KYC verification",
            code="ENTITY_NOT_LINKED",
            status_code=status.HTTP_400_BAD_REQUEST,
        )

    zynk_entity_id = current_entity.zynk_entity_id
    entity_id = current_entity.id

    logger.info(
        "[KYC] KYC link request - entity_id=%s, email=%s, zynk_entity_id=%s",
        entity_id,
        current_entity.email,
        zynk_entity_id,
    )

    # Look up existing KYC session (normally created at entity creation time)
    try:
        kyc_session = await prisma.kyc_sessions.find_first(
            where={"entity_id": entity_id, "deleted_at": None}
        )
    except DataError as exc:
        logger.error(
            "[KYC] DataError while looking up KYC session for entity_id=%s", entity_id, exc_info=exc
        )
        raise _build_error_response(
            "Invalid entity identifier",
            code="BAD_REQUEST",
            status_code=status.HTTP_400_BAD_REQUEST,
        )
    except Exception as exc:
        logger.error(
            "[KYC] Unexpected error while looking up KYC session for entity_id=%s",
            entity_id,
            exc_info=exc,
        )
        raise _build_error_response(
            "Unable to look up KYC session. Please try again later.",
            code="INTERNAL_ERROR",
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )

    # If no session exists (should be rare), treat as NOT_STARTED and create one
    if not kyc_session:
        logger.info(
            "[KYC] No KYC session found for entity_id=%s. Creating NOT_STARTED session.",
            entity_id,
        )
        try:
            kyc_session = await prisma.kyc_sessions.create(
                data={
                    "entity_id": entity_id,
                    "status": "NOT_STARTED",
                    "routing_enabled": False,
                }
            )
        except Exception as exc:
            logger.error(
                "[KYC] Failed to create initial KYC session for entity_id=%s",
                entity_id,
                exc_info=exc,
            )
            raise _build_error_response(
                "Failed to initialize KYC session. Please try again later.",
                code="INTERNAL_ERROR",
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

    status_value = str(kyc_session.status)

    # If KYC has not started yet, trigger Zynk and move to INITIATED
    if status_value == "NOT_STARTED":
        routing_id = US_KYC_ROUTING_ID
        logger.info(
            "[KYC] Status NOT_STARTED - generating new KYC link from Zynk "
            "- entity_id=%s, zynk_entity_id=%s, routing_id=%s",
            entity_id,
            zynk_entity_id,
            routing_id,
        )

        try:
            kyc_data = await get_kyc_link_from_zynk(zynk_entity_id, routing_id)
        except HTTPException:
            raise
        except Exception as exc:
            logger.error(
                "[KYC] Failed to generate KYC link from Zynk for zynk_entity_id=%s",
                zynk_entity_id,
                exc_info=exc,
            )
            raise _build_error_response(
                "Failed to generate KYC link. Please try again later.",
                code="INTERNAL_ERROR",
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
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
            logger.info(
                "[KYC] Updated KYC session to INITIATED - entity_id=%s, session_id=%s",
                entity_id,
                kyc_session.id,
            )
        except Exception as exc:
            logger.error(
                "[KYC] Failed to update KYC session to INITIATED for entity_id=%s",
                entity_id,
                exc_info=exc,
            )
            raise _build_error_response(
                "Failed to persist KYC session. Please try again later.",
                code="INTERNAL_ERROR",
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

        # Send email notification with KYC link
        try:
            user_name = f"{current_entity.first_name or ''} {current_entity.last_name or ''}".strip() or "User"
            email_sent = await email_service.send_kyc_link_email(
                email=current_entity.email,
                user_name=user_name,
                kyc_link=kyc_data["kycLink"],
                timestamp=now,
            )
            if email_sent:
                logger.info(
                    "[KYC] KYC link email sent successfully to %s for entity_id=%s",
                    current_entity.email,
                    entity_id,
                )
            else:
                logger.warning(
                    "[KYC] Failed to send KYC link email to %s for entity_id=%s (but link was generated)",
                    current_entity.email,
                    entity_id,
                )
        except Exception as email_exc:
            # Log error but don't fail the request if email sending fails
            # The KYC link was successfully generated and stored, so we should return it
            logger.error(
                "[KYC] Error sending KYC link email to %s for entity_id=%s: %s",
                current_entity.email,
                entity_id,
                str(email_exc),
                exc_info=email_exc,
            )

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

    # If already INITIATED with a link, just return it
    if status_value == "INITIATED" and kyc_session.kyc_link:
        logger.info(
            "[KYC] Returning existing INITIATED KYC link - entity_id=%s, session_id=%s",
            entity_id,
            kyc_session.id,
        )
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

    # Any other status: do not expose link
    logger.info(
        "[KYC] KYC session is not eligible for link - entity_id=%s, session_id=%s, status=%s",
        entity_id,
        kyc_session.id,
        status_value,
    )
    raise _build_error_response(
        "No active KYC link found for this user",
        code="KYC_LINK_NOT_FOUND",
        status_code=status.HTTP_404_NOT_FOUND,
    )


async def _get_or_create_kyc_session(entity_id: str):
    """
    Get existing KYC session or create a new one.
    Returns the KYC session object.
    """
    logger.info(f"[KYC] Looking up KYC session for entity_id={entity_id}")
    
    try:
        kyc_session = await prisma.kyc_sessions.find_first(
            where={"entity_id": entity_id, "deleted_at": None}
        )
        
        if kyc_session:
            logger.info(
                f"[KYC] Found existing KYC session: session_id={kyc_session.id}, "
                f"status={kyc_session.status}, has_link={bool(kyc_session.kyc_link)}"
            )
            return kyc_session
            
        # Create new KYC session
        logger.info(f"[KYC] No existing session found. Creating new KYC session for entity_id={entity_id}")
        
        create_data = {
            "entity_id": entity_id,
            "status": "NOT_STARTED",  # Match the actual database enum (V005 migration)
            "routing_enabled": False,
        }
        logger.info(f"[KYC] Create data: {create_data}")
        
        kyc_session = await prisma.kyc_sessions.create(data=create_data)
        logger.info(f"[KYC] Successfully created KYC session: session_id={kyc_session.id}")
        return kyc_session
        
    except DataError as exc:
        logger.error(f"[KYC] DataError while accessing KYC session for entity_id={entity_id}", exc_info=exc)
        raise _build_error_response(
            "Invalid entity identifier",
            code="BAD_REQUEST",
            status_code=status.HTTP_400_BAD_REQUEST,
        )
    except Exception as exc:
        logger.error(
            f"[KYC] Unexpected error in _get_or_create_kyc_session for entity_id={entity_id}",
            exc_info=exc,
        )
        raise