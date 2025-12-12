import httpx
from fastapi import APIRouter, Depends, HTTPException, status
from prisma.models import entities as Entities # type: ignore
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

router = APIRouter(prefix="/api/v1/teleport", tags=["teleport"])

def _auth_header():
    if not settings.zynk_api_key:
        raise HTTPException(status_code=500, detail="ZyncLab API key not configured")
    return {
        "x-api-token": settings.zynk_api_key,
    }

@router.get("", response_model=TeleportDetailsResponse, status_code=status.HTTP_200_OK)
async def get_teleport_details(
    current: Entities = Depends(auth.get_current_entity)
):
    entity_id = str(current.id)
    
    funding_account = await prisma.funding_accounts.find_first(
        where={"entity_id": entity_id, "deleted_at": None}
    )
    
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
    
    wallets = await prisma.wallets.find_many(
        where={"entity_id": entity_id, "deleted_at": None},
        include={"wallet_accounts": True},
    )
    
    wallet_account = None
    wallet = None
    for w in wallets:
        for account in w.wallet_accounts:
            if account.deleted_at is None:
                wallet_account = account
                wallet = w
                break
        if wallet_account:
            break
    
    funding_account_info = None
    if funding_account:
        funding_account_info = FundingAccountInfo(
            id=str(funding_account.id),
            bank_name=funding_account.bank_name,
            bank_account_number=funding_account.bank_account_number,
            bank_routing_number=funding_account.bank_routing_number,
            currency=funding_account.currency,
            status=str(funding_account.status),
        )
    
    wallet_account_info = None
    if wallet_account and wallet:
        wallet_account_info = WalletAccountInfo(
            id=str(wallet_account.id),
            address=wallet_account.address,
            chain=wallet.chain,
            wallet_name=wallet.wallet_name or "Wallet",
        )
    
    teleport_id = None
    if current.zynk_entity_id:
        try:
            url = f"{settings.zynk_base_url}/transformer/teleport/entity/{current.zynk_entity_id}"
            headers = {**_auth_header(), "Accept": "application/json"}
            
            async with httpx.AsyncClient(timeout=settings.zynk_timeout_s) as client:
                resp = await client.get(url, headers=headers)
            
            if resp.status_code == 200:
                body = resp.json()
                if body.get("success") and body.get("data"):
                    teleports = body.get("data", [])
                    if teleports and len(teleports) > 0:
                        teleport_id = teleports[0].get("teleportId")
        except Exception:
            pass
    
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
    current: Entities = Depends(auth.get_current_entity)
):
    entity_id = str(current.id)
    
    funding_account = await prisma.funding_accounts.find_first(
        where={"entity_id": entity_id, "deleted_at": None}
    )
    
    if not funding_account:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "success": False,
                "message": "Funding account not found. Please create a funding account first.",
                "error": {"code": "FUNDING_ACCOUNT_NOT_FOUND"},
            }
        )
    
    if not funding_account.zynk_funding_account_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "success": False,
                "message": "Funding account is not properly configured. Please contact support.",
                "error": {"code": "FUNDING_ACCOUNT_INVALID"},
            }
        )
    
    wallet_account = None
    if payload.walletAccountId:
        wallet_account = await prisma.wallet_accounts.find_first(
            where={
                "id": payload.walletAccountId,
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
                }
            )
        
        if str(wallet_account.wallet.entity_id) != entity_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={
                    "success": False,
                    "message": "Access denied. Wallet account does not belong to you.",
                    "error": {"code": "ACCESS_DENIED"},
                }
            )
    else:
        wallets = await prisma.wallets.find_many(
            where={"entity_id": entity_id, "deleted_at": None},
            include={"wallet_accounts": True},
        )
        
        for wallet in wallets:
            for account in wallet.wallet_accounts:
                if account.deleted_at is None:
                    wallet_account = account
                    break
            if wallet_account:
                break
    
    if not wallet_account:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "success": False,
                "message": "No wallet account found. Please create a wallet first.",
                "error": {"code": "WALLET_ACCOUNT_NOT_FOUND"},
            }
        )
    
    url = f"{settings.zynk_base_url}/api/v1/transformer/teleport/create"
    headers = {**_auth_header(), "Content-Type": "application/json", "Accept": "application/json"}
    
    request_body = {
        "fundingAccountId": funding_account.zynk_funding_account_id,
        "externalAccountId": wallet_account.address,
    }
    
    for attempt in range(2):
        try:
            async with httpx.AsyncClient(timeout=settings.zynk_timeout_s) as client:
                resp = await client.post(url, headers=headers, json=request_body)
        except httpx.RequestError as exc:
            if attempt == 0:
                continue
            raise upstream_error(
                log_message=f"[ZYNK] Request error while creating teleport for entity {entity_id} at {url}: {exc}",
                user_message="Verification service is currently unreachable. Please try again later.",
            )
        
        try:
            body = resp.json()
        except ValueError:
            raise upstream_error(
                log_message=f"[ZYNK] Invalid JSON while creating teleport for entity {entity_id} at {url}. Response preview: {resp.text[:200]}",
                user_message="Verification service returned an invalid response. Please try again later.",
            )
        
        if not (200 <= resp.status_code < 300):
            error_detail = body.get("message", body.get("error", f"HTTP {resp.status_code}: Unknown upstream error"))
            raise upstream_error(
                log_message=f"[ZYNK] Upstream error {resp.status_code} while creating teleport for entity {entity_id} at {url}: {error_detail}",
                user_message="Verification service is currently unavailable. Please try again later.",
            )
        
        if not isinstance(body, dict):
            raise upstream_error(
                log_message=f"[ZYNK] Unexpected response structure while creating teleport for entity {entity_id} at {url}: {body}",
                user_message="Verification service returned an unexpected response. Please try again later.",
            )
        
        if body.get("success") is not True:
            error_detail = body.get("message", body.get("error", "Request was not successful"))
            raise upstream_error(
                log_message=f"[ZYNK] Teleport creation rejected by upstream for entity {entity_id} at {url}: {error_detail}",
                user_message="Verification service rejected the request. Please contact support if this continues.",
            )
        
        # Transform ZynkLabs response to unified format
        # ZynkLabs response: {"success": true, "data": {"message": "...", "data": {"teleportId": "..."}}}
        # Unified format: {"success": true, "message": "...", "data": {"teleportId": "..."}, "error": None, "meta": {}}
        
        zynk_data = body.get("data", {})
        zynk_inner_data = zynk_data.get("data", {})
        teleport_id = zynk_inner_data.get("teleportId")
        
        if not teleport_id:
            raise upstream_error(
                log_message=f"[ZYNK] Missing teleportId in ZynkLabs response for entity {entity_id} at {url}: {body}",
                user_message="Verification service returned an incomplete response. Please try again later.",
            )
        
        return CreateTeleportResponse(
            success=True,
            message=zynk_data.get("message", "Teleport created successfully"),
            data={"teleportId": teleport_id},
            error=None,
            meta={},
        )
    
    raise upstream_error(
        log_message=f"[ZYNK] Failed to create teleport for entity {entity_id} at {url} after multiple attempts",
        user_message="Verification service is currently unavailable. Please try again later.",
    )

