from datetime import datetime, timezone
import httpx
from fastapi import APIRouter, Depends, HTTPException
from prisma.models import entities as Entities
from ..database import db
from .. import auth
from ..config import settings
from ..schemas_zynk import ZynkEntitiesResponse, ZynkEntityResponse, ZynkKycResponse, ZynkKycRequirementsResponse

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

@router.get("/entity/{entity_id}", response_model=ZynkEntityResponse)
async def get_entity_by_id(
    entity_id: str,
    current: Entities = Depends(auth.get_current_entity)
):
    """
    Fetch a single entity by ID from ZyncLab via their API.
    Ensures that users can only access their own entity data for security.
    Requires authentication and ownership validation in the banking system.
    """
    # Ensure the entity has an external_entity_id set (means it's linked to ZyncLab)
    if not current.external_entity_id:
        raise HTTPException(status_code=404, detail="Entity not linked to external service. Please complete the entity creation process.")

    # Security check: Ensure the requested entity belongs to the authenticated user
    if current.external_entity_id != entity_id:
        raise HTTPException(status_code=403, detail="Access denied. You can only access your own entity data.")


    # Construct the URL using the external_entity_id for the upstream call
    url = f"{settings.zynk_base_url}/api/v1/transformer/entity/{current.external_entity_id}"
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
                raise HTTPException(status_code=404, detail="Entity not found in external service.")
            raise HTTPException(status_code=502, detail=f"Upstream service error: {error_detail}")

        if not isinstance(body, dict):
            raise HTTPException(status_code=502, detail="Upstream service returned unexpected response structure")

        if body.get("success") is not True:
            error_detail = body.get("message", body.get("error", "Request was not successful"))
            if "not found" in error_detail.lower():
                raise HTTPException(status_code=404, detail="Entity not found in external service.")
            raise HTTPException(status_code=502, detail=f"Upstream service rejected the request: {error_detail}")

        # Validate that data exists for the response schema
        data = body.get("data")
        if data is None or "entity" not in data:
            raise HTTPException(status_code=502, detail="Upstream service did not provide the expected data structure")

        # Additional validation to ensure entity contains essential fields
        entity = data["entity"]
        required_fields = ["entityId", "type", "firstName", "lastName", "email"]
        for field in required_fields:
            if field not in entity:
                raise HTTPException(status_code=502, detail=f"Upstream service response missing required field: {field}")

        # Return the upstream response as it matches our schema
        return body

    raise HTTPException(status_code=502, detail="Failed to fetch entity from upstream service after multiple attempts")

@router.get("/entity/kyc/{entity_id}", response_model=ZynkKycResponse)
async def get_entity_kyc_status(
    entity_id: str,
    current: Entities = Depends(auth.get_current_entity)
):
    """
    Fetch KYC status for a specific entity from ZyncLab via their API.
    Ensures that users can only access their own KYC data for security.
    Requires authentication and ownership validation in the banking system.
    """
    # Ensure the entity has an external_entity_id set (means it's linked to ZyncLab)
    if not current.external_entity_id:
        raise HTTPException(status_code=404, detail="Entity not linked to external service. Please complete the entity creation process.")

    # Security check: Ensure the requested entity belongs to the authenticated user
    if current.external_entity_id != entity_id:
        raise HTTPException(status_code=403, detail="Access denied. You can only access your own KYC data.")

    # Construct the URL using the external_entity_id for the upstream call
    url = f"{settings.zynk_base_url}/api/v1/transformer/entity/kyc/{current.external_entity_id}"
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
                raise HTTPException(status_code=404, detail="KYC data not found for the entity in external service.")
            raise HTTPException(status_code=502, detail=f"Upstream service error: {error_detail}")

        if not isinstance(body, dict):
            raise HTTPException(status_code=502, detail="Upstream service returned unexpected response structure")

        if body.get("success") is not True:
            error_detail = body.get("message", body.get("error", "Request was not successful"))
            if "not found" in error_detail.lower():
                raise HTTPException(status_code=404, detail="KYC data not found for the entity in external service.")
            raise HTTPException(status_code=502, detail=f"Upstream service rejected the request: {error_detail}")

        # Validate that data exists for the response schema
        data = body.get("data")
        if data is None or "status" not in data:
            raise HTTPException(status_code=502, detail="Upstream service did not provide the expected data structure")

        # Additional validation to ensure status is a list and contains items
        status = data["status"]
        if not isinstance(status, list):
            raise HTTPException(status_code=502, detail="Upstream service response 'status' must be a list")
        if not status:
            raise HTTPException(status_code=502, detail="Upstream service response 'status' list is empty")

        # Return the upstream response as it matches our schema
        return body

    raise HTTPException(status_code=502, detail="Failed to fetch KYC status from upstream service after multiple attempts")

@router.get("/entity/email/{email}", response_model=ZynkEntityResponse)
async def get_entity_by_email(
    email: str,
    current: Entities = Depends(auth.get_current_entity)
):
    """
    Fetch a single entity by email from ZyncLab via their API.
    Ensures that users can only access their own entity data based on email for security.
    Requires authentication and ownership validation in the banking system.
    """
    # Ensure the authenticated user's email matches the requested email
    if current.email != email:
        raise HTTPException(status_code=403, detail="Access denied. You can only access your own entity data.")

    # Ensure the entity has an external_entity_id set (means it's linked to ZyncLab)
    if not current.external_entity_id:
        raise HTTPException(status_code=404, detail="Entity not linked to external service. Please complete the entity creation process.")

    # Construct the URL using the email for the upstream call
    url = f"{settings.zynk_base_url}/api/v1/transformer/entity/email/{email}"
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
                raise HTTPException(status_code=404, detail="Entity not found in external service.")
            raise HTTPException(status_code=502, detail=f"Upstream service error: {error_detail}")

        if not isinstance(body, dict):
            raise HTTPException(status_code=502, detail="Upstream service returned unexpected response structure")

        if body.get("success") is not True:
            error_detail = body.get("message", body.get("error", "Request was not successful"))
            if "not found" in error_detail.lower():
                raise HTTPException(status_code=404, detail="Entity not found in external service.")
            raise HTTPException(status_code=502, detail=f"Upstream service rejected the request: {error_detail}")

        # Validate that data exists for the response schema
        data = body.get("data")
        if data is None or "entity" not in data:
            raise HTTPException(status_code=502, detail="Upstream service did not provide the expected data structure")

        # Additional validation to ensure entity contains essential fields
        entity = data["entity"]
        required_fields = ["entityId", "type", "firstName", "lastName", "email"]
        for field in required_fields:
            if field not in entity:
                raise HTTPException(status_code=502, detail=f"Upstream service response missing required field: {field}")

        # Return the upstream response as it matches our schema
        return body

    raise HTTPException(status_code=502, detail="Failed to fetch entity from upstream service after multiple attempts")
