import logging
from typing import Any, Dict

import httpx
from fastapi import APIRouter, Depends, HTTPException, status
from prisma.errors import DataError
from prisma.models import entities as Entities

from ..core.database import prisma
from ..core import auth
from ..core.config import settings
from ..schemas.kyc import KycLinkData, KycLinkResponse

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/kyc", tags=["kyc"])


def _build_error_response(
    message: str, 
    code: str, 
    *, 
    status_code: int, 
    error_details: Dict[str, Any] | None = None
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


def _auth_header() -> Dict[str, str]:
    """Generate authentication header for ZyncLabs API"""
    if not settings.zynk_api_key:
        raise HTTPException(
            status_code=500, 
            detail="ZyncLabs API key not configured"
        )
    return {"x-api-token": settings.zynk_api_key}


@router.get("", response_model=KycLinkResponse, status_code=status.HTTP_200_OK)
async def get_kyc_link(
    current_entity: Entities = Depends(auth.get_current_entity)
) -> KycLinkResponse:
    """
    Get KYC verification link for the authenticated user.
    
    This endpoint:
    1. Checks if user has external_entity_id (linked to ZyncLabs)
    2. Finds or creates a KYC session
    3. Returns existing KYC link or generates a new one from ZyncLabs
    
    Returns KYC link, TOS link, and their respective statuses.
    """
    logger.info(
        f"[KYC] KYC link request received - id={current_entity.id}, "
        f"email={current_entity.email}, external_entity_id={current_entity.external_entity_id}"
    )
    
    # Ensure entity is linked to ZyncLabs
    if not current_entity.external_entity_id:
        logger.warning(
            f"[KYC] Entity {current_entity.id} not linked to ZyncLabs. "
            f"User must complete profile setup first."
        )
        raise _build_error_response(
            "Please complete your profile setup before starting KYC verification",
            code="ENTITY_NOT_LINKED",
            status_code=status.HTTP_400_BAD_REQUEST,
        )

    external_entity_id = current_entity.external_entity_id
    entity_id = current_entity.id
    
    logger.info(f"[KYC] Using external_entity_id={external_entity_id} for ZyncLabs API")

    # Find or create KYC session
    try:
        kyc_session = await _get_or_create_kyc_session(entity_id)
    except HTTPException:
        raise
    except Exception as exc:
        logger.error(f"[KYC] Failed to get/create KYC session for entity_id={entity_id}", exc_info=exc)
        raise _build_error_response(
            "Unable to initialize KYC session. Please try again later.",
            code="INTERNAL_ERROR",
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )

    # If KYC link already exists, return it
    if kyc_session.kyc_link:
        logger.info(
            f"[KYC] Returning existing KYC link - entity_id={entity_id}, "
            f"session_id={kyc_session.id}, status={kyc_session.status}"
        )
        return KycLinkResponse(
            success=True,
            data=KycLinkData(
                message="KYC link retrieved successfully",
                kycLink=kyc_session.kyc_link,
                tosLink=None,  # TOS link would come from the same response
                kycStatus=kyc_session.status.lower(),
                tosStatus="pending",  # Default status
            ),
            error=None,
        )

    # Generate new KYC link from ZyncLabs
    # Use routing_id from session, or fall back to default from config
    routing_id = kyc_session.routing_id or settings.zynk_default_routing_id
    
    logger.info(
        f"[KYC] No existing KYC link found. Generating new link from ZyncLabs - "
        f"external_entity_id={external_entity_id}, routing_id={routing_id}"
    )
    
    try:
        kyc_data = await _generate_kyc_link_from_upstream(
            external_entity_id, 
            routing_id
        )
        
        logger.info(f"[KYC] Successfully received KYC data from ZyncLabs: {list(kyc_data.keys())}")
        
        # Update KYC session with new link and routing_id
        await prisma.kyc_sessions.update(
            where={"id": kyc_session.id},
            data={
                "kyc_link": kyc_data["kycLink"],
                "routing_id": routing_id,  # Save routing_id for future use
            },
        )
        logger.info(f"[KYC] Updated KYC session {kyc_session.id} with new link and routing_id")
        
        return KycLinkResponse(
            success=True,
            data=KycLinkData(
                message="KYC link generated successfully",
                kycLink=kyc_data["kycLink"],
                tosLink=kyc_data.get("tosLink"),
                kycStatus=kyc_data.get("kycStatus", kyc_session.status.lower()),
                tosStatus=kyc_data.get("tosStatus", "pending"),
            ),
            error=None,
        )
        
    except HTTPException:
        raise
    except Exception as exc:
        logger.error(f"[KYC] Failed to generate KYC link for external_entity_id={external_entity_id}", exc_info=exc)
        raise _build_error_response(
            "Failed to generate KYC link. Please try again later.",
            code="INTERNAL_ERROR",
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
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
        logger.error(f"[KYC] Unexpected error in _get_or_create_kyc_session for entity_id={entity_id}", exc_info=exc)
        raise


async def _generate_kyc_link_from_upstream(
    external_entity_id: str, 
    routing_id: str
) -> Dict[str, Any]:
    """
    Call ZyncLabs API to generate KYC verification link.
    
    Returns dict with kycLink, tosLink, kycStatus, tosStatus
    """
    # Always include routing_id in the URL
    url = f"{settings.zynk_base_url}/api/v1/transformer/entity/kyc/{external_entity_id}/{routing_id}"
    
    logger.info(f"[KYC] Calling ZyncLabs API: POST {url}")
    
    headers = {
        **_auth_header(), 
        "Content-Type": "application/json",
        "Accept": "application/json"
    }

    # Retry logic for network resilience
    for attempt in range(2):
        logger.info(f"[KYC] ZyncLabs API call attempt {attempt + 1}/2")
        
        try:
            async with httpx.AsyncClient(timeout=settings.zynk_timeout_s) as client:
                response = await client.post(url, headers=headers, json={})
                logger.info(f"[KYC] ZyncLabs response: status_code={response.status_code}")
                
        except httpx.RequestError as exc:
            logger.warning(
                f"[KYC] Network error calling ZyncLabs (attempt {attempt + 1}/2): {str(exc)}", 
                exc_info=exc
            )
            if attempt == 0:
                continue
            raise _build_error_response(
                "Unable to reach verification service. Please try again.",
                code="UPSTREAM_UNREACHABLE",
                status_code=status.HTTP_502_BAD_GATEWAY,
            )

        # Parse response
        try:
            body = response.json()
            logger.info(f"[KYC] ZyncLabs response body keys: {list(body.keys()) if isinstance(body, dict) else 'not a dict'}")
        except ValueError:
            logger.error(f"[KYC] Invalid JSON from ZyncLabs: {response.text[:200]}")
            raise _build_error_response(
                "Received invalid response from verification service",
                code="UPSTREAM_ERROR",
                status_code=status.HTTP_502_BAD_GATEWAY,
            )

        # Handle non-success status codes
        if not (200 <= response.status_code < 300):
            error_msg = body.get("message") or body.get("error") or "Unknown error"
            logger.error(
                f"[KYC] ZyncLabs API error: status={response.status_code}, "
                f"error={error_msg}, body={body}"
            )
            raise _build_error_response(
                f"Verification service error: {error_msg}",
                code="UPSTREAM_ERROR",
                status_code=status.HTTP_502_BAD_GATEWAY,
                error_details=body,
            )

        # Validate response structure
        if not isinstance(body, dict) or not body.get("success"):
            error_msg = body.get("message", "Request was not successful")
            logger.error(f"[KYC] ZyncLabs returned unsuccessful response: {body}")
            raise _build_error_response(
                f"Verification service rejected request: {error_msg}",
                code="UPSTREAM_ERROR",
                status_code=status.HTTP_502_BAD_GATEWAY,
            )

        # Extract KYC data from response
        data = body.get("data", {})
        if not data.get("kycLink"):
            logger.error(f"[KYC] Missing kycLink in ZyncLabs response data: {data}")
            raise _build_error_response(
                "Verification service returned incomplete data",
                code="UPSTREAM_ERROR",
                status_code=status.HTTP_502_BAD_GATEWAY,
            )

        logger.info(
            f"[KYC] Successfully generated KYC link for entity {external_entity_id}. "
            f"Response contains: {list(data.keys())}"
        )
        return data

    # Should never reach here due to raises above, but just in case
    raise _build_error_response(
        "Failed to generate KYC link after multiple attempts",
        code="INTERNAL_ERROR",
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
    )