import logging
from typing import Any, Dict

import httpx
from fastapi import APIRouter, HTTPException, status
from prisma.errors import DataError

from ..core.database import prisma
from ..schemas.kyc import KycLinkData, KycLinkRequest, KycLinkResponse

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/kyc", tags=["kyc"])


def _build_error_response(message: str, code: str, *, status_code: int, error_details: Dict[str, Any] | None = None) -> HTTPException:
    return HTTPException(
        status_code=status_code,
        detail={
            "success": False,
            "message": message,
            "data": None,
            "error": {"code": code, "details": error_details or message},
            "meta": {},
        },
    )


@router.post("/link", response_model=KycLinkResponse, status_code=status.HTTP_200_OK)
async def get_kyc_link(payload: KycLinkRequest) -> KycLinkResponse:
    entity_id = str(payload.entity_id).strip()
    routing_id = payload.routing_id.strip()

    if not entity_id:
        raise _build_error_response("Entity ID is required", code="BAD_REQUEST", status_code=status.HTTP_400_BAD_REQUEST)
    if not routing_id:
        raise _build_error_response("Routing ID is required", code="BAD_REQUEST", status_code=status.HTTP_400_BAD_REQUEST)

    try:
        kyc_session = await prisma.kyc_sessions.find_first(
            where={"entity_id": entity_id, "routing_id": routing_id}
        )
    except DataError as exc:
        logger.warning("Invalid identifiers for KYC session lookup", exc_info=exc)
        raise _build_error_response(
            "Invalid entity or routing identifier",
            code="BAD_REQUEST",
            status_code=status.HTTP_400_BAD_REQUEST,
        )
    except Exception as exc:
        logger.exception("Failed to fetch KYC session", exc_info=exc)
        raise _build_error_response("Unable to fetch KYC session", code="INTERNAL_ERROR", status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)

    if not kyc_session:
        raise _build_error_response("KYC session not found", code="NOT_FOUND", status_code=status.HTTP_404_NOT_FOUND)

    if kyc_session.kyc_link:
        return KycLinkResponse(
            success=True,
            message="KYC link fetched successfully",
            data=KycLinkData(kyc_link=kyc_session.kyc_link),
            error=None,
        )

    logger.info("KYC link not found for entity_id=%s, routing_id=%s. Generating new one.", entity_id, routing_id)

    try:
        kyc_link = await _generate_kyc_link(entity_id, routing_id)
        await prisma.kyc_sessions.update(
            where={"kyc_session_id": kyc_session.kyc_session_id},
            data={"kyc_link": kyc_link},
        )
    except HTTPException:
        raise
    except Exception as exc:
        logger.exception("Failed to generate/update KYC link", exc_info=exc)
        raise _build_error_response("Failed to generate KYC link", code="INTERNAL_ERROR", status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)

    return KycLinkResponse(
        success=True,
        message="KYC link generated successfully",
        data=KycLinkData(kyc_link=kyc_link),
        error=None,
    )


async def _generate_kyc_link(entity_id: str, routing_id: str) -> str:
    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"https://qaapi.zynklabs.xyz/api/v1/transformer/entity/kyc/{entity_id}/{routing_id}"
            )
            if response.status_code != status.HTTP_200_OK:
                details = response.json().get("message", "Failed to generate KYC link")
                raise _build_error_response(details, code="UPSTREAM_ERROR", status_code=status.HTTP_502_BAD_GATEWAY)
            kyc_link = response.json()["data"]["kyc_link"]
            logger.info("KYC link generated successfully for entity_id=%s, routing_id=%s.", entity_id, routing_id)
            return kyc_link
    except HTTPException:
        raise
    except Exception as exc:
        logger.exception("Unexpected error while generating KYC link", exc_info=exc)
        raise _build_error_response("Internal server error", code="INTERNAL_ERROR", status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)