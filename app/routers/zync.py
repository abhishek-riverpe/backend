# routes/zynk.py
from datetime import datetime, timezone
import httpx
from fastapi import APIRouter, Depends, HTTPException, Response, status
from prisma.errors import PrismaError
from prisma.models import entities as Entities
from ..database import db
from .. import auth
from ..config import settings
from ..schemas_zynk import CreateZynkEntityIn

router = APIRouter(prefix="/api/v1/zynk", tags=["zynk"])

def _auth_header():
    if not settings.zynk_api_key:
        raise HTTPException(status_code=500, detail="Zynk API key not configured")
    return {
        "x-api-token": settings.zynk_api_key,
    }

async def _call_zynk_create_entity(payload: dict) -> str:
    url = f"{settings.zynk_base_url}/api/v1/transformer/entity/create"
    headers = {**_auth_header(), "Content-Type": "application/json", "Accept": "application/json"}

    for attempt in range(2):  # 1 retry
        try:
            async with httpx.AsyncClient(timeout=settings.zynk_timeout_s) as client:
                resp = await client.post(url, json=payload, headers=headers)
        except httpx.RequestError:
            if attempt == 0:
                continue
            raise HTTPException(status_code=502, detail="Upstream unreachable")

        try:
            body = resp.json()
        except ValueError:
            raise HTTPException(status_code=502, detail=f"Invalid JSON response from upstream: {resp.text[:200]}")

        if not (200 <= resp.status_code < 300):
            # Include upstream error details
            error_detail = body.get("message", body.get("error", f"HTTP {resp.status_code}: Unknown upstream error"))
            raise HTTPException(status_code=502, detail=f"Upstream error: {error_detail}")

        if not isinstance(body, dict) or body.get("success") is not True:
            error_detail = body.get("message", body.get("error", "Upstream returned unsuccessful response"))
            raise HTTPException(status_code=502, detail=f"Upstream rejected request: {error_detail}")

        ext_id = body.get("data", {}).get("entityId")
        if not ext_id or not isinstance(ext_id, str):
            raise HTTPException(status_code=502, detail=f"Upstream returned invalid or missing entityId: {body.get('data', {})}")

        return ext_id

    raise HTTPException(status_code=502, detail="Failed to create entity upstream after retries")

async def _call_zynk_get_kyc_requirements(entity_id: str, routing_id: str) -> dict:
    """
    Call Zynk to fetch KYC requirements for a given entity and routing.
    Returns parsed JSON body on success, otherwise raises HTTPException.
    """
    url = f"{settings.zynk_base_url}/api/v1/transformer/entity/kyc/requirements/{entity_id}/{routing_id}"
    headers = {**_auth_header(), "Accept": "application/json"}

    for attempt in range(2):
        try:
            async with httpx.AsyncClient(timeout=settings.zynk_timeout_s) as client:
                resp = await client.get(url, headers=headers)
        except httpx.RequestError:
            if attempt == 0:
                continue
            raise HTTPException(status_code=502, detail="Upstream unreachable")

        try:
            body = resp.json()
        except ValueError:
            raise HTTPException(status_code=502, detail=f"Invalid JSON response from upstream: {resp.text[:200]}")

        if not (200 <= resp.status_code < 300):
            error_detail = body.get("message", body.get("error", f"HTTP {resp.status_code}: Unknown upstream error"))
            raise HTTPException(status_code=502, detail=f"Upstream error: {error_detail}")

        if not isinstance(body, dict) or body.get("success") is not True:
            error_detail = body.get("message", body.get("error", "Upstream returned unsuccessful response"))
            raise HTTPException(status_code=502, detail=f"Upstream rejected request: {error_detail}")

        return body.get("data", {})

    raise HTTPException(status_code=502, detail="Failed to fetch KYC requirements after retries")

async def get_current_entity(entity=Depends(auth.get_current_entity)):
    return entity

@router.post("/entity", status_code=status.HTTP_201_CREATED)
async def create_external_entity(
    payload: CreateZynkEntityIn,
    response: Response,
    current: Entities = Depends(get_current_entity),
):
    """
    Forward payload to Zynk; on success:
      - overwrite local `entityId` with upstream `entityId`
      - set `status = ACTIVE`
    """

    # 1) Email parity with signed-in user to prevent cross-account provisioning
    if (current.email or "").strip() != payload.email.strip():
        raise HTTPException(status_code=400, detail="Email mismatch with authenticated entity")

    # 3) Call Zynk
    upstream_entity_id = await _call_zynk_create_entity(payload.dict())

    # 4) Persist: overwrite `external_entity_id` and set status ACTIVE
    now = datetime.now(timezone.utc)
    try:
        updated = await db.entities.update(
            where={"entity_id": current.entity_id},  # use your immutable PK to locate the row
            data={
                "external_entity_id": upstream_entity_id,   # <- overwrite existing field
                "status": "ACTIVE",               # ensure enum has ACTIVE
                "updated_at": now,
            },
        )
    except PrismaError:
        raise HTTPException(status_code=500, detail="Failed to persist external entity link")

    # 5) Return unified API response
    response.headers["Location"] = f"/api/v1/zynk/entity/{updated.entity_id}"
    response.headers["X-External-Entity-Id"] = upstream_entity_id
    return {
        "success": True,
        "message": "Entity created successfully",
        "data": {"entityId": upstream_entity_id, "status": "ACTIVE"},
        "error": None,
        "meta": {},
    }


@router.get("/kyc/requirements/{routing_id}")
async def get_kyc_requirements(
    routing_id: str,
    current: Entities = Depends(get_current_entity),
):
    """
    Fetch KYC requirements for the logged-in user's external entity id and the provided routing id.
    Returns unified API response.
    """
    external_id = getattr(current, "external_entity_id", None)
    if not external_id:
        raise HTTPException(status_code=400, detail="External entity id is missing. Complete profile first.")

    data = await _call_zynk_get_kyc_requirements(external_id, routing_id)
    # Shape: { message, kycRequirements: [...] }
    return {
        "success": True,
        "message": data.get("message", "Fetched requirements"),
        "data": {"kycRequirements": data.get("kycRequirements", [])},
        "error": None,
        "meta": {},
    }
