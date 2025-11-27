import httpx
from fastapi import APIRouter, Depends, HTTPException
from prisma.models import entities as Entities
from ..core import auth
from ..core.config import settings
from ..utils.errors import upstream_error

router = APIRouter(prefix="/api/v1/funding_account", tags=["funding_account"])

def _auth_header():
    """
    Generate authentication header for ZyncLab API.
    """
    if not settings.zynk_api_key:
        raise HTTPException(status_code=500, detail="ZyncLab API key not configured")
    return {
        "x-api-token": settings.zynk_api_key,
    }

@router.get("")
async def get_funding_accounts(
    current: Entities = Depends(auth.get_current_entity)
):
    """
    Fetch all funding accounts for the authenticated entity from ZyncLab via their API.
    Ensures that users can only access their own funding accounts for security.
    Requires authentication and ownership validation in the banking system.
    """
    # Ensure the entity has a zynk_entity_id set (means it's linked to ZyncLab)
    # Try both possible attribute names for compatibility
    zynk_entity_id = getattr(current, "zynk_entity_id", None) or getattr(current, "external_entity_id", None)
    if not zynk_entity_id:
        raise HTTPException(status_code=404, detail="Entity not linked to external service. Please complete the entity creation process.")

    # Construct the URL using the zynk_entity_id for the upstream call
    url = f"{settings.zynk_base_url}/api/v1/transformer/accounts/{zynk_entity_id}/funding_accounts"
    headers = {**_auth_header(), "Accept": "application/json"}
    
    # Make the request to ZyncLab with retry logic
    for attempt in range(2):  # 1 retry
        try:
            async with httpx.AsyncClient(timeout=settings.zynk_timeout_s) as client:
                resp = await client.get(url, headers=headers)
        except httpx.RequestError as exc:
            if attempt == 0:
                continue
            raise upstream_error(
                log_message=f"[ZYNK] Request error while fetching funding accounts for entity {current.id} at {url}: {exc}",
                user_message="Verification service is currently unreachable. Please try again later.",
            )

        try:
            body = resp.json()
        except ValueError:
            raise upstream_error(
                log_message=f"[ZYNK] Invalid JSON while fetching funding accounts for entity {current.id} at {url}. Response preview: {resp.text[:200]}",
                user_message="Verification service returned an invalid response. Please try again later.",
            )

        if not (200 <= resp.status_code < 300):
            error_detail = body.get("message", body.get("error", f"HTTP {resp.status_code}: Unknown upstream error"))
            if resp.status_code == 404:
                # 404 is safe and useful to expose
                raise HTTPException(status_code=404, detail="Funding accounts not found for the entity in external service.")
            raise upstream_error(
                log_message=f"[ZYNK] Upstream error {resp.status_code} while fetching funding accounts for entity {current.id} at {url}: {error_detail}",
                user_message="Verification service is currently unavailable. Please try again later.",
            )

        if not isinstance(body, dict):
            raise upstream_error(
                log_message=f"[ZYNK] Unexpected response structure while fetching funding accounts for entity {current.id} at {url}: {body}",
                user_message="Verification service returned an unexpected response. Please try again later.",
            )

        if body.get("success") is not True:
            error_detail = body.get("message", body.get("error", "Request was not successful"))
            if "not found" in error_detail.lower():
                raise HTTPException(status_code=404, detail="Funding accounts not found for the entity in external service.")
            raise upstream_error(
                log_message=f"[ZYNK] Funding accounts request rejected by upstream for entity {current.id} at {url}: {error_detail}",
                user_message="Verification service rejected the request. Please contact support if this continues.",
            )

        # Return the upstream response as-is
        return body

    raise upstream_error(
        log_message=f"[ZYNK] Failed to fetch funding accounts for entity {current.id} at {url} after multiple attempts",
        user_message="Verification service is currently unavailable. Please try again later.",
    )

