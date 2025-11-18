import httpx
from fastapi import APIRouter, Depends, HTTPException
from prisma.models import entities as Entities
from ..core import auth
from ..core.config import settings
from ..utils.response import standard_response

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
    # Ensure the entity has an zynk_entity_id set (means it's linked to ZyncLab)
    if not current.zynk_entity_id:
        raise HTTPException(status_code=404, detail="Entity not linked to external service. Please complete the entity creation process.")

    # Construct the URL using the zynk_entity_id for the upstream call
    url = f"{settings.zynk_base_url}/api/v1/transformer/accounts/{current.zynk_entity_id}/funding_accounts"
    headers = {**_auth_header(), "Accept": "application/json"}

    # Make the request to ZyncLab with retry logic
    for attempt in range(2):  # 1 retry
        try:
            async with httpx.AsyncClient(timeout=settings.zynk_timeout_s) as client:
                resp = await client.get(url, headers=headers)
        except httpx.RequestError:
            if attempt == 0:
                continue
            raise HTTPException(status_code=502, detail="Upstream service unreachable. Please try again later.")

        try:
            body = resp.json()
        except ValueError:
            raise HTTPException(status_code=502, detail=f"Received invalid response format from upstream service. Response preview: {resp.text[:200]}")

        if not (200 <= resp.status_code < 300):
            # Extract upstream error details for user-friendly messaging
            error_detail = body.get("message", body.get("error", f"HTTP {resp.status_code}: Unknown upstream error"))
            if resp.status_code == 404:
                raise HTTPException(status_code=404, detail="Funding accounts not found for the entity in external service.")
            raise HTTPException(status_code=502, detail=f"Upstream service error: {error_detail}")

        if not isinstance(body, dict):
            raise HTTPException(status_code=502, detail="Upstream service returned unexpected response structure")

        if body.get("success") is not True:
            error_detail = body.get("message", body.get("error", "Request was not successful"))
            if "not found" in error_detail.lower():
                raise HTTPException(status_code=404, detail="Funding accounts not found for the entity in external service.")
            raise HTTPException(status_code=502, detail=f"Upstream service rejected the request: {error_detail}")

        # Upstream already returns unified format, ensure it has error and meta fields
        data = body.get("data", {})
        upstream_message = data.get("message", "Funding accounts fetched successfully") if isinstance(data, dict) else "Funding accounts fetched successfully"
        return standard_response(
            success=body.get("success", True),
            message=body.get("message", upstream_message),
            data=data,  # Keep the nested data structure as-is for frontend compatibility
            error=body.get("error"),
            meta=body.get("meta", {})
        )

    raise HTTPException(status_code=502, detail="Failed to fetch funding accounts from upstream service after multiple attempts")

