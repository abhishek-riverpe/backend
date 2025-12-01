import httpx
import logging
from fastapi import APIRouter, Depends, HTTPException, status
from prisma.models import entities as Entities
from ..core import auth
from ..core.config import settings
from ..utils.errors import upstream_error
from ..schemas.teleport import CreateTeleportRequest

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/teleport", tags=["teleport"])

def _auth_header():
    """
    Generate authentication header for ZyncLab API.
    """
    if not settings.zynk_api_key:
        raise HTTPException(status_code=500, detail="ZyncLab API key not configured")
    return {
        "x-api-token": settings.zynk_api_key,
    }

@router.post("", status_code=status.HTTP_201_CREATED)
async def create_teleport(
    payload: CreateTeleportRequest,
    current: Entities = Depends(auth.get_current_entity)
):
    """
    Create a teleport route for the authenticated entity.
    Wraps ZynkLabs API and returns unified response format.
    Ensures that users can only create teleports for their own accounts.
    """
    # Ensure the entity has a zynk_entity_id set (means it's linked to ZyncLab)
    # zynk_entity_id = getattr(current, "zynk_entity_id", None) or getattr(current, "external_entity_id", None)
    # if not zynk_entity_id:
    #     raise HTTPException(
    #         status_code=404, 
    #         detail="Entity not linked to external service. Please complete the entity creation process."
    #     )
    
    # Construct the URL using the zynk_entity_id for the upstream call
    # Based on funding account pattern: /api/v1/transformer/accounts/{entity_id}/funding_accounts
    # Teleport likely follows: /api/v1/transformer/accounts/{entity_id}/teleports
    url = f"{settings.zynk_base_url}/api/v1/transformer/accounts/{zynk_entity_id}/teleports"
    headers = {**_auth_header(), "Content-Type": "application/json", "Accept": "application/json"}
    
    # Prepare request body for ZynkLabs
    request_body = {
        "fundingAccountId": payload.fundingAccountId,
        "externalAccountId": payload.externalAccountId,
    }
    
    logger.info(f"[TELEPORT] Creating teleport for entity {current.id} (zynk_entity_id: {zynk_entity_id})")
    
    # Make the request to ZyncLab with retry logic
    for attempt in range(2):  # 1 retry
        try:
            async with httpx.AsyncClient(timeout=settings.zynk_timeout_s) as client:
                resp = await client.post(url, headers=headers, json=request_body)
        except httpx.RequestError as exc:
            if attempt == 0:
                continue
            raise upstream_error(
                log_message=f"[ZYNK] Request error while creating teleport for entity {current.id} at {url}: {exc}",
                user_message="Verification service is currently unreachable. Please try again later.",
            )
        
        try:
            body = resp.json()
        except ValueError:
            raise upstream_error(
                log_message=f"[ZYNK] Invalid JSON while creating teleport for entity {current.id} at {url}. Response preview: {resp.text[:200]}",
                user_message="Verification service returned an invalid response. Please try again later.",
            )
        
        if not (200 <= resp.status_code < 300):
            error_detail = body.get("message", body.get("error", f"HTTP {resp.status_code}: Unknown upstream error"))
            raise upstream_error(
                log_message=f"[ZYNK] Upstream error {resp.status_code} while creating teleport for entity {current.id} at {url}: {error_detail}",
                user_message="Verification service is currently unavailable. Please try again later.",
            )
        
        if not isinstance(body, dict):
            raise upstream_error(
                log_message=f"[ZYNK] Unexpected response structure while creating teleport for entity {current.id} at {url}: {body}",
                user_message="Verification service returned an unexpected response. Please try again later.",
            )
        
        if body.get("success") is not True:
            error_detail = body.get("message", body.get("error", "Request was not successful"))
            raise upstream_error(
                log_message=f"[ZYNK] Teleport creation rejected by upstream for entity {current.id} at {url}: {error_detail}",
                user_message="Verification service rejected the request. Please contact support if this continues.",
            )
        
        # Transform ZynkLabs response to unified format
        # ZynkLabs response: {"success": true, "data": {"message": "...", "data": {"teleportId": "..."}}}
        # Unified format: {"success": true, "message": "...", "data": {"teleportId": "..."}, "error": None, "meta": {}}
        
        zynk_data = body.get("data", {})
        zynk_inner_data = zynk_data.get("data", {})
        teleport_id = zynk_inner_data.get("teleportId")
        
        if not teleport_id:
            raise upstream_error(
                log_message=f"[ZYNK] Missing teleportId in ZynkLabs response for entity {current.id} at {url}: {body}",
                user_message="Verification service returned an incomplete response. Please try again later.",
            )
        
        logger.info(f"[TELEPORT] Successfully created teleport {teleport_id} for entity {current.id}")
        
        return {
            "success": True,
            "message": zynk_data.get("message", "Teleport created successfully"),
            "data": {
                "teleportId": teleport_id
            },
            "error": None,
            "meta": {},
        }
    
    raise upstream_error(
        log_message=f"[ZYNK] Failed to create teleport for entity {current.id} at {url} after multiple attempts",
        user_message="Verification service is currently unavailable. Please try again later.",
    )

