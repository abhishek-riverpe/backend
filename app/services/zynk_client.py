import logging
from typing import Any, Dict
import httpx
from fastapi import HTTPException, status
from ..core.config import settings
from ..utils.errors import upstream_error

logger = logging.getLogger(__name__)


# Generate Auth Header
def _auth_header() -> Dict[str, str]:
    if not settings.zynk_api_key:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="ZynkLabs API key not configured",
        )
    return {"x-api-token": settings.zynk_api_key}


async def get_kyc_link_from_zynk(zynk_entity_id: str, routing_id: str) -> Dict[str, Any]:
    url = f"{settings.zynk_base_url}/api/v1/transformer/entity/kyc/{zynk_entity_id}/{routing_id}"

    headers = {
        **_auth_header(),
        "Content-Type": "application/json",
        "Accept": "application/json",
    }

    # Simple retry for transient network errors
    for attempt in range(2):
        try:
            async with httpx.AsyncClient(timeout=settings.zynk_timeout_s) as client:
                response = await client.post(url, headers=headers, json={})

        except httpx.RequestError as exc:
            if attempt == 0:
                continue
            raise upstream_error(
                log_message=f"[ZYNK] Unable to reach verification service at {url}: {exc}",
                user_message="Unable to reach verification service. Please try again.",
            )

        try:
            body = response.json()
        except ValueError:
            raise upstream_error(
                log_message=f"[ZYNK] Invalid JSON from KYC link endpoint at {url}."
                f"Response preview: {response.text[:200]}",
                user_message="Verification service returned an invalid response. Please try again later.",
            )

        if not (200 <= response.status_code < 300):
            error_obj = body.get("error") or {}
            error_details = (error_obj.get("details") or body.get("message") or "").lower()
            if (
                response.status_code == 400
                and "kyc for this entity has already been done" in error_details
            ):
                
                return {
                    "kycCompleted": True,
                    "message": "KYC for this entity has already been completed.",
                }

            error_msg = body.get("message") or body.get("error") or "Unknown error"
            
            raise upstream_error(
                log_message=f"[ZYNK] Upstream error {response.status_code} while requesting "
                f"KYC link at {url}: {error_msg}",
                user_message="Verification service error. Please try again later.",
            )

        if not isinstance(body, dict) or not body.get("success"):
            error_msg = body.get("message", "Request was not successful")
            raise upstream_error(
                log_message=f"[ZYNK] Verification service rejected KYC link request at {url}: {error_msg}",
                user_message="Verification service rejected the request. Please contact support if this continues.",
            )

        data = body.get("data") or {}
        if not data.get("kycLink"):
            raise upstream_error(
                log_message=f"[ZYNK] Missing kycLink in upstream response from {url}: {data}",
                user_message="Verification service returned incomplete data. Please try again later.",
            )

        return data

    raise upstream_error(
        log_message=f"[ZYNK] Failed to obtain KYC link from {url} after multiple attempts",
        user_message="Verification service is currently unavailable. Please try again later.",
    )



async def create_funding_account_from_zynk(zynk_entity_id: str, jurisdiction_id: str) -> Dict[str, Any]:

    url = f"{settings.zynk_base_url}/api/v1/transformer/accounts/{zynk_entity_id}/create/funding_account/{jurisdiction_id}"

    headers = {**_auth_header()}

    for attempt in range(2):
        try:
            async with httpx.AsyncClient(timeout=settings.zynk_timeout_s) as client:
                response = await client.post(url, headers=headers, json={})
              
        except httpx.RequestError as exc:
            if attempt == 0:
                continue
            raise upstream_error(
                log_message=f"[ZYNK] Unable to reach verification service at {url}: {exc}",
                user_message="Unable to reach verification service. Please try again.",
            )

        try:
            body = response.json()
        except ValueError:
            raise upstream_error(
                log_message=f"[ZYNK] Invalid JSON from funding account creation endpoint at {url}. "
                f"Response preview: {response.text[:200]}",
                user_message="Verification service returned an invalid response. Please try again later.",
            )

        if not (200 <= response.status_code < 300):
            error_msg = body.get("message") or body.get("error") or "Unknown error"
            raise upstream_error(
                log_message=f"[ZYNK] Upstream error {response.status_code} while creating "
                f"funding account at {url}: {error_msg}",
                user_message="Verification service error. Please try again later.",
                error_details=body,
            )

        if not isinstance(body, dict) or not body.get("success"):
            error_msg = body.get("message", "Request was not successful")
            raise upstream_error(
                log_message=f"[ZYNK] Verification service rejected funding account creation request at {url}: {error_msg}",
                user_message="Verification service rejected the request. Please contact support if this continues.",
                error_details=body,
            )

        outer_data = body.get("data") or {}
        inner_data = outer_data.get("data") or {}

        if not inner_data.get("id"):
            raise upstream_error(
                log_message=f"[ZYNK] Missing funding account ID in upstream response from {url}: {inner_data}",
                user_message="Verification service returned incomplete data. Please try again later.",
            )

        return inner_data

    raise upstream_error(
        log_message=f"[ZYNK] Failed to create funding account from {url} after multiple attempts",
        user_message="Verification service is currently unavailable. Please try again later.",
    )


