import logging
from typing import Any, Dict

import httpx
from fastapi import HTTPException, status

from ..core.config import settings
from ..utils.errors import upstream_error

logger = logging.getLogger(__name__)


def _auth_header() -> Dict[str, str]:
    """
    Generate authentication header for ZynkLabs API.
    """
    if not settings.zynk_api_key:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="ZynkLabs API key not configured",
        )
    return {"x-api-token": settings.zynk_api_key}


async def get_kyc_link_from_zynk(zynk_entity_id: str, routing_id: str) -> Dict[str, Any]:
    """
    Call ZynkLabs API to generate a KYC verification link.

    Returns the `data` payload from upstream, which should contain:
      - kycLink
      - tosLink
      - kycStatus
      - tosStatus
    """
    url = f"{settings.zynk_base_url}/api/v1/transformer/entity/kyc/{zynk_entity_id}/{routing_id}"

    logger.info("[ZYNK] Requesting KYC link: POST %s", url)

    headers = {
        **_auth_header(),
        "Content-Type": "application/json",
        "Accept": "application/json",
    }

    # Simple retry for transient network errors
    for attempt in range(2):
        logger.info("[ZYNK] KYC link call attempt %s/2", attempt + 1)

        try:
            async with httpx.AsyncClient(timeout=settings.zynk_timeout_s) as client:
                response = await client.post(url, headers=headers, json={})
                logger.info("[ZYNK] KYC link response status=%s", response.status_code)
        except httpx.RequestError as exc:
            logger.warning("[ZYNK] Network error on KYC link call: %s", exc, exc_info=exc)
            if attempt == 0:
                continue
            raise upstream_error(
                log_message=f"[ZYNK] Unable to reach verification service at {url}: {exc}",
                user_message="Unable to reach verification service. Please try again.",
            )

        try:
            body = response.json()
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

        if not (200 <= response.status_code < 300):
            # Handle special case where Zynk indicates KYC is already completed
            # Example body:
            #   {'success': False,
            #    'error': {'code': 400, 'message': 'Bad Request',
            #              'details': 'KYC for this entity has already been done'}}
            error_obj = body.get("error") or {}
            error_details = (error_obj.get("details") or body.get("message") or "").lower()
            if (
                response.status_code == 400
                and "kyc for this entity has already been done" in error_details
            ):
                logger.info(
                    "[ZYNK] KYC already completed for entity=%s; treating as already verified.",
                    zynk_entity_id,
                )
                # Surface a clean marker back to the router instead of raising.
                return {
                    "kycCompleted": True,
                    "message": "KYC for this entity has already been completed.",
                }

            error_msg = body.get("message") or body.get("error") or "Unknown error"
            logger.error(
                "[ZYNK] Upstream error on KYC link call: status=%s, error=%s, body=%s",
                response.status_code,
                error_msg,
                body,
            )
            raise upstream_error(
                log_message=f"[ZYNK] Upstream error {response.status_code} while requesting "
                f"KYC link at {url}: {error_msg}",
                user_message="Verification service error. Please try again later.",
            )

        if not isinstance(body, dict) or not body.get("success"):
            error_msg = body.get("message", "Request was not successful")
            logger.error("[ZYNK] Unsuccessful KYC link response: %s", body)
            raise upstream_error(
                log_message=f"[ZYNK] Verification service rejected KYC link request at {url}: {error_msg}",
                user_message="Verification service rejected the request. Please contact support if this continues.",
            )

        data = body.get("data") or {}
        if not data.get("kycLink"):
            logger.error("[ZYNK] Missing kycLink in KYC link response data: %s", data)
            raise upstream_error(
                log_message=f"[ZYNK] Missing kycLink in upstream response from {url}: {data}",
                user_message="Verification service returned incomplete data. Please try again later.",
            )

        logger.info(
            "[ZYNK] Successfully obtained KYC link for entity=%s. Keys: %s",
            zynk_entity_id,
            list(data.keys()),
        )
        return data

    # Should not reach here due to raises above
    raise upstream_error(
        log_message=f"[ZYNK] Failed to obtain KYC link from {url} after multiple attempts",
        user_message="Verification service is currently unavailable. Please try again later.",
    )


async def create_funding_account_from_zynk(zynk_entity_id: str, jurisdiction_id: str) -> Dict[str, Any]:
    """
    Call ZynkLabs API to create a funding account for an entity.

    Args:
        zynk_entity_id: The Zynk Labs entity ID
        jurisdiction_id: The jurisdiction ID (fixed: "jurisdiction_51607ba7_c0b2_428c_a8c5_75ad94c9ffb1")

    Returns:
        The nested `data.data` payload from upstream response, which should contain:
          - id (funding account ID from Zynk)
          - entityId
          - jurisdictionId
          - providerId
          - status
          - accountInfo (dict with bank details, currency, payment rails, etc.)
    """
    url = f"{settings.zynk_base_url}/api/v1/transformer/accounts/{zynk_entity_id}/create/funding_account/{jurisdiction_id}"

    logger.info(
        "[ZYNK] Creating funding account: POST %s for entity=%s, jurisdiction=%s",
        url,
        zynk_entity_id,
        jurisdiction_id,
    )

    headers = {
        **_auth_header(),
        "Content-Type": "application/json",
        "Accept": "application/json",
    }

    # Simple retry for transient network errors
    for attempt in range(2):
        logger.info("[ZYNK] Funding account creation call attempt %s/2", attempt + 1)

        try:
            async with httpx.AsyncClient(timeout=settings.zynk_timeout_s) as client:
                response = await client.post(url, headers=headers, json={})
                logger.info("[ZYNK] Funding account creation response status=%s", response.status_code)
        except httpx.RequestError as exc:
            logger.warning(
                "[ZYNK] Network error on funding account creation call: %s",
                exc,
                exc_info=exc,
            )
            if attempt == 0:
                continue
            raise upstream_error(
                log_message=f"[ZYNK] Unable to reach verification service at {url}: {exc}",
                user_message="Unable to reach verification service. Please try again.",
            )

        try:
            body = response.json()
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

        if not (200 <= response.status_code < 300):
            error_msg = body.get("message") or body.get("error") or "Unknown error"
            logger.error(
                "[ZYNK] Upstream error on funding account creation call: status=%s, error=%s, body=%s",
                response.status_code,
                error_msg,
                body,
            )
            raise upstream_error(
                log_message=f"[ZYNK] Upstream error {response.status_code} while creating "
                f"funding account at {url}: {error_msg}",
                user_message="Verification service error. Please try again later.",
                error_details=body,
            )

        if not isinstance(body, dict) or not body.get("success"):
            error_msg = body.get("message", "Request was not successful")
            logger.error("[ZYNK] Unsuccessful funding account creation response: %s", body)
            raise upstream_error(
                log_message=f"[ZYNK] Verification service rejected funding account creation request at {url}: {error_msg}",
                user_message="Verification service rejected the request. Please contact support if this continues.",
                error_details=body,
            )

        # Zynk Labs response structure: { success: true, data: { message: "...", data: {...} } }
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

        logger.info(
            "[ZYNK] Successfully created funding account for entity=%s. Funding account ID: %s",
            zynk_entity_id,
            inner_data.get("id"),
        )
        return inner_data

    # Should not reach here due to raises above
    raise upstream_error(
        log_message=f"[ZYNK] Failed to create funding account from {url} after multiple attempts",
        user_message="Verification service is currently unavailable. Please try again later.",
    )


