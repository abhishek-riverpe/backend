from datetime import datetime, timezone
import httpx
from fastapi import APIRouter, Depends, HTTPException, Response, status, Request
from slowapi import Limiter
from ..utils.validate_id import validate_user_id
from slowapi.util import get_remote_address
from prisma.errors import PrismaError
from prisma.models import entities as Entities # type: ignore
from ..core.database import prisma
from ..core import auth
from ..core.config import settings
from urllib.parse import urljoin
from ..schemas.zynk import CreateZynkEntityIn
from ..utils.errors import upstream_error

router = APIRouter(prefix="/api/v1/transformer", tags=["transformer"])


limiter = Limiter(key_func=get_remote_address)

def _auth_header():
    if not settings.zynk_api_key:
        raise HTTPException(status_code=500, detail="Zynk API key not configured")
    return {
        "x-api-token": settings.zynk_api_key,
    }

async def _call_zynk_create_entity(payload: dict) -> str:
    url = f"{settings.zynk_base_url}/api/v1/transformer/entity/create"
    headers = {**_auth_header(), "Content-Type": "application/json", "Accept": "application/json"}

    for attempt in range(2):
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
            raise upstream_error(
                user_message="Verification service returned an invalid response. Please try again later.",
            )

        if not (200 <= resp.status_code < 300):
            raise upstream_error(
                user_message="Verification service is currently unavailable. Please try again later.",
            )

        if not isinstance(body, dict) or body.get("success") is not True:
            raise upstream_error(
                user_message="Verification service rejected the request. Please try again later.",
            )

        ext_id = body.get("data", {}).get("entityId")
        if not ext_id or not isinstance(ext_id, str):
            raise upstream_error(
                user_message="Verification service returned an invalid response. Please try again later.",
            )

        return ext_id

    raise HTTPException(status_code=502, detail="Failed to create entity upstream after retries")

async def get_current_entity(entity=Depends(auth.get_current_entity)):
    return entity

@router.post("/entity", status_code=status.HTTP_201_CREATED)
async def create_external_entity(
    payload: CreateZynkEntityIn,
    response: Response,
    current: Entities = Depends(get_current_entity),
):
    if (current.email or "").strip() != payload.email.strip():
        raise HTTPException(status_code=400, detail="Email mismatch with authenticated entity")
    
    upstream_entity_id = await _call_zynk_create_entity(payload.dict())

    now = datetime.now(timezone.utc)
    try:
        updated = await prisma.entities.update(
            where={"id": current.id},  
            data={
                "zynk_entity_id": upstream_entity_id,   
                "status": "ACTIVE",              
                "updated_at": now,
            },
        )
    except PrismaError:
        raise HTTPException(status_code=500, detail="Failed to persist external entity link")
    response.headers["Location"] = f"/api/v1/transformer/entity/{updated.id}"
    response.headers["X-External-Entity-Id"] = upstream_entity_id
    return {
        "success": True,
        "message": "Entity created successfully",
        "data": {"entityId": upstream_entity_id, "status": "ACTIVE"},
        "error": None,
        "meta": {},
    }


@router.get("/entity/kyc/requirements/{user_id}")
@limiter.limit("30/minute") 
async def get_kyc_requirements(
    user_id: str,
    request: Request,
    current: Entities = Depends(get_current_entity)
):
    if not validate_user_id(user_id):
        raise HTTPException(status_code=400, detail="Invalid user ID format")
    if current.id != user_id:
        raise HTTPException(status_code=403, detail="Not authorized to access this user's KYC requirements")

    user = await prisma.entities.find_unique(where={"id": user_id})
    if not user or not user.zynk_entity_id:
        raise HTTPException(status_code=404, detail="User not found or not registered with verification service")
    
    endpoint = f"/api/v1/transformer/entity/kyc/requirements/{user.zynk_entity_id}"
    url = urljoin(settings.zynk_base_url, endpoint)
    
    headers = _auth_header() 
    headers["Accept"] = "application/json"
    
    try:
        async with httpx.AsyncClient(timeout=settings.zynk_timeout_s) as client:
            resp = await client.get(url, headers=headers)
            resp.raise_for_status()
            data = resp.json()
    except httpx.HTTPStatusError as e:
        raise HTTPException(status_code=e.response.status_code, detail="Upstream service error")
    except httpx.RequestError:
        raise HTTPException(status_code=502, detail="Upstream service unavailable")
    except ValueError:
        raise upstream_error(
            user_message="Verification service returned an invalid response"
        )
    
    if not isinstance(data, dict):
        raise upstream_error(
            user_message="Verification service returned an unexpected response"
        )
    
    return {
        "success": True,
        "message": data.get("message", "Fetched requirements"),
        "data": {"kycRequirements": data.get("data", data)},
        "error": None,
        "meta": {},
    }