import httpx
import logging
from typing import Optional, Tuple

from fastapi import APIRouter, Depends, HTTPException, status
from prisma.models import entities as Entities
from ..core import auth
from ..core.config import settings
from ..core.database import prisma
from ..utils.errors import upstream_error
from ..schemas.teleport import (
    CreateTeleportRequest,
    CreateTeleportResponse,
    TeleportDetailsResponse,
    TeleportDetailsData,
    FundingAccountInfo,
    WalletAccountInfo,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/teleport", tags=["teleport"])

JSON_MIME_TYPE = "application/json"
ZYNK_TELEPORT_DETAILS_PATH = "/transformer/teleport/entity"
ZYNK_TELEPORT_CREATE_PATH = "/api/v1/transformer/teleport/create"


def _auth_header() -> dict:
    """
    Generate authentication header for ZyncLab API.
    """
    if not settings.zynk_api_key:
        raise HTTPException(status_code=500, detail="ZyncLab API key not configured")
    return {
        "x-api-token": settings.zynk_api_key,
    }


def _auth_json_headers() -> dict:
    """
    Authentication headers with JSON content negotiation.
    """
    base = _auth_header()
    base["Content-Type"] = JSON_MIME_TYPE
    base["Accept"] = JSON_MIME_TYPE
    return base


async def _get_funding_account(entity_id: str):
    return await prisma.funding_accounts.find_first(
        where={"entity_id": entity_id, "deleted_at": None}
    )


async def _get_first_active_wallet(entity_id: str) -> Tuple[Optional[object], Optional[object]]:
    """
    Return (wallet_account, wallet) for the first active wallet account for the entity.
    """
    wallets = await prisma.wallets.find_many(
        where={"entity_id": entity_id, "deleted_at": None},
        include={"wallet_accounts": True},
    )

    for wallet in wallets:
        for account in wallet.wallet_accounts:
            if account.deleted_at is None:
                return account, wallet

    return None, None


def _build_funding_account_info(funding_account) -> Optional[FundingAccountInfo]:
    if not funding_account:
        return None

    return FundingAccountInfo(
        id=str(funding_account.id),
        bank_name=funding_account.bank_name,
        bank_account_number=funding_account.bank_account_number,
        bank_routing_number=funding_account.bank_routing_number,
        currency=funding_account.currency,
        status=str(funding_account.status),
    )


def _build_wallet_account_info(wallet_account, wallet) -> Optional[WalletAccountInfo]:
    if not wallet_account or not wallet:
        return None

    return WalletAccountInfo(
        id=str(wallet_account.id),
        address=wallet_account.address,
        chain=wallet.chain,
        wallet_name=wallet.wallet_name or "Wallet",
    )


async def _fetch_teleport_id_from_zynk(zynk_entity_id: Optional[str]) -> Optional[str]:
    """
    Try to fetch teleportId from Zynk Labs for a given Zynk entity ID.
    """
    if not zynk_entity_id:
        return None

    url = f"{settings.zynk_base_url}{ZYNK_TELEPORT_DETAILS_PATH}/{zynk_entity_id}"
    headers = {**_auth_header(), "Accept": JSON_MIME_TYPE}

    try:
        async with httpx.AsyncClient(timeout=settings.zynk_timeout_s) as client:
            resp = await client.get(url, headers=headers)

        if resp.status_code != 200:
            logger.warning(
                "[TELEPORT] Non-200 from Zynk while fetching teleport for zynk_entity_id=%s: %s",
                zynk_entity_id,
                resp.status_code,
            )
            return None

        body = resp.json()
        if not (body.get("success") and body.get("data")):
            return None

        teleports = body.get("data", [])
        if not teleports:
            return None

        return teleports[0].get("teleportId")

    except Exception as exc:
        logger.warning("[TELEPORT] Failed to fetch teleport from Zynk: %s", exc)
        return None


async def _get_validated_funding_account(entity_id: str):
    funding_account = await _get_funding_account(entity_id)
    if not funding_account:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "success": False,
                "message": "Funding account not found. Please create a funding account first.",
                "error": {"code": "FUNDING_ACCOUNT_NOT_FOUND"},
            },
        )

    if not funding_account.zynk_funding_account_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "success": False,
                "message": "Funding account is not properly configured. Please contact support.",
                "error": {"code": "FUNDING_ACCOUNT_INVALID"},
            },
        )

    return funding_account


async def _get_wallet_account_for_entity(entity_id: str, wallet_account_id: Optional[str]):
    """
    Resolve wallet account for the entity either by explicit ID or first active wallet.
    Raises appropriate HTTPExceptions on invalid conditions.
    """
    if wallet_account_id:
        wallet_account = await prisma.wallet_accounts.find_first(
            where={
                "id": wallet_account_id,
                "deleted_at": None,
            },
            include={"wallet": True},
        )

        if not wallet_account:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail={
                    "success": False,
                    "message": "Wallet account not found.",
                    "error": {"code": "WALLET_ACCOUNT_NOT_FOUND"},
                },
            )

        if str(wallet_account.wallet.entity_id) != entity_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={
                    "success": False,
                    "message": "Access denied. Wallet account does not belong to you.",
                    "error": {"code": "ACCESS_DENIED"},
                },
            )

        return wallet_account

    wallet_account, _wallet = await _get_first_active_wallet(entity_id)

    if not wallet_account:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "success": False,
                "message": "No wallet account found. Please create a wallet first.",
                "error": {"code": "WALLET_ACCOUNT_NOT_FOUND"},
            },
        )

    return wallet_account


async def _create_teleport_upstream(
    url: str, headers: dict, request_body: dict, entity_id: str
) -> Tuple[str, str]:
    """
    Call ZynkLabs to create teleport with retry and validation logic.
    Returns (teleport_id, message).
    """
    for attempt in range(2):  # 1 retry
        try:
            async with httpx.AsyncClient(timeout=settings.zynk_timeout_s) as client:
                resp = await client.post(url, headers=headers, json=request_body)
        except httpx.RequestError as exc:
            if attempt == 0:
                continue
            raise upstream_error(
                log_message=(
                    f"[ZYNK] Request error while creating teleport for entity {entity_id} at {url}: {exc}"
                ),
                user_message="Verification service is currently unreachable. Please try again later.",
            )

        try:
            body = resp.json()
        except ValueError:
            raise upstream_error(
                log_message=(
                    f"[ZYNK] Invalid JSON while creating teleport for entity {entity_id} at {url}. "
                    f"Response preview: {resp.text[:200]}"
                ),
                user_message="Verification service returned an invalid response. Please try again later.",
            )

        if not (200 <= resp.status_code < 300):
            error_detail = body.get(
                "message",
                body.get("error", f"HTTP {resp.status_code}: Unknown upstream error"),
            )
            raise upstream_error(
                log_message=(
                    f"[ZYNK] Upstream error {resp.status_code} while creating teleport "
                    f"for entity {entity_id} at {url}: {error_detail}"
                ),
                user_message="Verification service is currently unavailable. Please try again later.",
            )

        if not isinstance(body, dict):
            raise upstream_error(
                log_message=(
                    f"[ZYNK] Unexpected response structure while creating teleport "
                    f"for entity {entity_id} at {url}: {body}"
                ),
                user_message="Verification service returned an unexpected response. Please try again later.",
            )

        if body.get("success") is not True:
            error_detail = body.get("message", body.get("error", "Request was not successful"))
            raise upstream_error(
                log_message=(
                    f"[ZYNK] Teleport creation rejected by upstream for entity {entity_id} at {url}: {error_detail}"
                ),
                user_message=(
                    "Verification service rejected the request. Please contact support if this continues."
                ),
            )

        zynk_data = body.get("data", {})
        zynk_inner_data = zynk_data.get("data", {})
        teleport_id = zynk_inner_data.get("teleportId")

        if not teleport_id:
            raise upstream_error(
                log_message=(
                    f"[ZYNK] Missing teleportId in ZynkLabs response for entity {entity_id} at {url}: {body}"
                ),
                user_message="Verification service returned an incomplete response. Please try again later.",
            )

        message = zynk_data.get("message", "Teleport created successfully")
        return teleport_id, message

    raise upstream_error(
        log_message=(
            f"[ZYNK] Failed to create teleport for entity {entity_id} at {url} after multiple attempts"
        ),
        user_message="Verification service is currently unavailable. Please try again later.",
    )


@router.get("", response_model=TeleportDetailsResponse, status_code=status.HTTP_200_OK)
async def get_teleport_details(
    current: Entities = Depends(auth.get_current_entity),
) -> TeleportDetailsResponse:
    """
    Get teleport details for the authenticated entity.
    Returns funding account and wallet account information.
    """
    entity_id = str(current.id)
    logger.info("[TELEPORT] Fetching teleport details for entity %s", entity_id)

    # Funding account
    funding_account = await _get_funding_account(entity_id)
    if not funding_account:
        return TeleportDetailsResponse(
            success=True,
            message="No funding account found",
            data=TeleportDetailsData(
                teleportId=None,
                fundingAccount=None,
                walletAccount=None,
            ),
            error=None,
            meta={},
        )

    # Wallet + account
    wallet_account, wallet = await _get_first_active_wallet(entity_id)

    funding_account_info = _build_funding_account_info(funding_account)
    wallet_account_info = _build_wallet_account_info(wallet_account, wallet)

    teleport_id = await _fetch_teleport_id_from_zynk(current.zynk_entity_id)

    return TeleportDetailsResponse(
        success=True,
        message="Teleport details fetched successfully",
        data=TeleportDetailsData(
            teleportId=teleport_id,
            fundingAccount=funding_account_info,
            walletAccount=wallet_account_info,
        ),
        error=None,
        meta={},
    )


@router.post("", response_model=CreateTeleportResponse, status_code=status.HTTP_201_CREATED)
async def create_teleport(
    payload: CreateTeleportRequest,
    current: Entities = Depends(auth.get_current_entity),
) -> CreateTeleportResponse:
    """
    Create a teleport route for the authenticated entity.
    Automatically gets funding account ID and wallet account address from database.
    """
    entity_id = str(current.id)
    logger.info("[TELEPORT] Creating teleport for entity %s", entity_id)

    funding_account = await _get_validated_funding_account(entity_id)
    wallet_account = await _get_wallet_account_for_entity(entity_id, payload.walletAccountId)

    url = f"{settings.zynk_base_url}{ZYNK_TELEPORT_CREATE_PATH}"
    headers = _auth_json_headers()

    request_body = {
        "fundingAccountId": funding_account.zynk_funding_account_id,
        "externalAccountId": wallet_account.address,
    }

    logger.info(
        "[TELEPORT] Creating teleport for entity %s - fundingAccountId: %s, externalAccountId: %s",
        entity_id,
        funding_account.zynk_funding_account_id,
        wallet_account.address,
    )

    teleport_id, message = await _create_teleport_upstream(
        url=url,
        headers=headers,
        request_body=request_body,
        entity_id=entity_id,
    )

    logger.info("[TELEPORT] Successfully created teleport %s for entity %s", teleport_id, entity_id)

    return CreateTeleportResponse(
        success=True,
        message=message,
        data={"teleportId": teleport_id},
        error=None,
        meta={},
    )
