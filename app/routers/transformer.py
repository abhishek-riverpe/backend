from datetime import datetime, timezone
import httpx
from fastapi import APIRouter, Depends, HTTPException
from prisma.models import entities as Entities
from ..database import db
from .. import auth
from ..config import settings
from ..schemas_zynk import ZynkEntitiesResponse

router = APIRouter(prefix="/api/v1/transformer", tags=["transformer"])

def _auth_header():
    """
    Generate authentication header for ZyncLab API.
    """
    if not settings.zynk_api_key:
        raise HTTPException(status_code=500, detail="ZyncLab API key not configured")
    return {
        "x-api-token": settings.zynk_api_key,
    }

@router.get("/entity/entities", response_model=ZynkEntitiesResponse)
async def get_all_entities(current: Entities = Depends(auth.get_current_entity)):
    """
    Fetch all entities from ZyncLab via their API.
    Requires authentication to ensure secure access in the banking system.
    """
    url = f"{settings.zynk_base_url}/api/v1/transformer/entity/entities"
    headers = {**_auth_header(), "Accept": "application/json"}

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
            raise HTTPException(status_code=502, detail=f"Upstream service error: {error_detail}")

        if not isinstance(body, dict):
            raise HTTPException(status_code=502, detail="Upstream service returned unexpected response structure")

        if body.get("success") is not True:
            error_detail = body.get("message", body.get("error", "Request was not successful"))
            raise HTTPException(status_code=502, detail=f"Upstream service rejected the request: {error_detail}")

        # Validate that data exists and has required fields for the response schema
        data = body.get("data")
        if data is None or "entities" not in data or "paginationData" not in data or "message" not in data:
            raise HTTPException(status_code=502, detail="Upstream service did not provide the expected data structure")

        # Return the entire upstream response as it matches our schema
        return body

    raise HTTPException(status_code=502, detail="Failed to fetch entities from upstream service after multiple attempts")
