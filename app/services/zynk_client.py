import logging
from typing import Any, Dict
import httpx
from fastapi import HTTPException, status
from ..core.config import settings
from ..utils.errors import upstream_error

logger = logging.getLogger(__name__)

# Constants
CONTENT_TYPE_JSON = "application/json"


# Generate Auth Header
def _auth_header() -> Dict[str, str]:
    if not settings.zynk_api_key:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="ZynkLabs API key not configured",
        )
    return {"x-api-token": settings.zynk_api_key}


def _parse_kyc_link_response(response: httpx.Response, url: str) -> dict:
    """Parse JSON response from KYC link endpoint."""
    try:
        return response.json()
    except ValueError:
        logger.error(
            "[ZYNK] Invalid JSON from KYC link endpoint. Preview: %s",
            response.text[:200],
        )
        raise upstream_error(
            log_message=f"[ZYNK] Invalid JSON from KYC link endpoint at {url}. "
            f"Response preview: {response.text[:200]}",
            user_message="Verification service returned an invalid response. Please try again later.",
        )


def _handle_kyc_already_completed(body: dict, zynk_entity_id: str) -> Dict[str, Any]:
    """Handle case where KYC is already completed."""
    error_obj = body.get("error") or {}
    error_details = (error_obj.get("details") or body.get("message") or "").lower()
    if "kyc for this entity has already been done" in error_details:
        logger.info(
            "[ZYNK] KYC already completed for entity=%s; treating as already verified.",
            zynk_entity_id,
        )
        return {
            "kycCompleted": True,
            "message": "KYC for this entity has already been completed.",
        }
    return None


def _validate_kyc_link_response(body: dict, url: str) -> None:
    """Validate KYC link response structure."""
    if not isinstance(body, dict) or not body.get("success"):
        error_msg = body.get("message", "Request was not successful")
        logger.error("[ZYNK] Unsuccessful KYC link response: %s", body)
        raise upstream_error(
            log_message=f"[ZYNK] Verification service rejected KYC link request at {url}: {error_msg}",
            user_message="Verification service rejected the request. Please contact support if this continues.",
        )


def _extract_kyc_link_data(body: dict, url: str) -> Dict[str, Any]:
    """Extract and validate KYC link data from response."""
    data = body.get("data") or {}
    if not data.get("kycLink"):
        logger.error("[ZYNK] Missing kycLink in KYC link response data: %s", data)
        raise upstream_error(
            log_message=f"[ZYNK] Missing kycLink in upstream response from {url}: {data}",
            user_message="Verification service returned incomplete data. Please try again later.",
        )
    return data


async def get_kyc_link_from_zynk(zynk_entity_id: str, routing_id: str) -> Dict[str, Any]:
    url = f"{settings.zynk_base_url}/api/v1/transformer/entity/kyc/{zynk_entity_id}/{routing_id}"

    headers = {
        **_auth_header(),
        "Content-Type": CONTENT_TYPE_JSON,
        "Accept": CONTENT_TYPE_JSON,
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

        body = _parse_kyc_link_response(response, url)

        if not (200 <= response.status_code < 300):
            kyc_completed = _handle_kyc_already_completed(body, zynk_entity_id)
            if kyc_completed:
                return kyc_completed

            error_msg = body.get("message") or body.get("error") or "Unknown error"
            
            raise upstream_error(
                log_message=f"[ZYNK] Upstream error {response.status_code} while requesting "
                f"KYC link at {url}: {error_msg}",
                user_message="Verification service error. Please try again later.",
            )

        _validate_kyc_link_response(body, url)
        data = _extract_kyc_link_data(body, url)

        return data

    raise upstream_error(
        log_message=f"[ZYNK] Failed to obtain KYC link from {url} after multiple attempts",
        user_message="Verification service is currently unavailable. Please try again later.",
    )


def _parse_funding_account_response(response: httpx.Response, url: str) -> dict:
    """Parse JSON response from funding account creation endpoint."""
    try:
        return response.json()
    except ValueError:
        logger.error(
            "[ZYNK] Invalid JSON from funding account creation endpoint. Preview: %s",
            response.text[:200],
        )
        raise upstream_error(
            log_message=f"[ZYNK] Invalid JSON from funding account creation endpoint at {url}. "
            f"Response preview: {response.text[:200]}",
            user_message="Verification service returned an invalid response. Please try again later.",
        )


def _validate_funding_account_response(body: dict, url: str) -> None:
    """Validate funding account creation response."""
    if not isinstance(body, dict) or not body.get("success"):
        error_msg = body.get("message", "Request was not successful")
        logger.error("[ZYNK] Unsuccessful funding account creation response: %s", body)
        raise upstream_error(
            log_message=f"[ZYNK] Verification service rejected funding account creation request at {url}: {error_msg}",
            user_message="Verification service rejected the request. Please contact support if this continues.",
            error_details=body,
        )


def _extract_funding_account_data(body: dict, url: str) -> Dict[str, Any]:
    """Extract and validate funding account data from nested response."""
    outer_data = body.get("data") or {}
    inner_data = outer_data.get("data") or {}

    if not inner_data.get("id"):
        logger.error(
            "[ZYNK] Missing funding account ID in creation response. Outer data: %s, Inner data: %s",
            outer_data,
            inner_data,
        )
        raise upstream_error(
            log_message=f"[ZYNK] Missing funding account ID in upstream response from {url}: {inner_data}",
            user_message="Verification service returned incomplete data. Please try again later.",
        )
    return inner_data


async def create_funding_account_from_zynk(zynk_entity_id: str, jurisdiction_id: str) -> Dict[str, Any]:

    url = f"{settings.zynk_base_url}/api/v1/transformer/accounts/{zynk_entity_id}/create/funding_account/{jurisdiction_id}"

    headers = {**_auth_header()}

    headers = {
        **_auth_header(),
        "Content-Type": CONTENT_TYPE_JSON,
        "Accept": CONTENT_TYPE_JSON,
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

        body = _parse_funding_account_response(response, url)

        if not (200 <= response.status_code < 300):
            error_msg = body.get("message") or body.get("error") or "Unknown error"
            raise upstream_error(
                log_message=f"[ZYNK] Upstream error {response.status_code} while creating "
                f"funding account at {url}: {error_msg}",
                user_message="Verification service error. Please try again later.",
                error_details=body,
            )

        _validate_funding_account_response(body, url)
        inner_data = _extract_funding_account_data(body, url)

        return inner_data

    raise upstream_error(
        log_message=f"[ZYNK] Failed to create funding account from {url} after multiple attempts",
        user_message="Verification service is currently unavailable. Please try again later.",
    )


