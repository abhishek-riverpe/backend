"""
Account Router

Handles user account-related endpoints including funding account management.
"""

import httpx
import logging
from fastapi import APIRouter, Depends, HTTPException, Request, status
from slowapi import Limiter
from slowapi.util import get_remote_address
from prisma.models import entities as Entities
from ..core import auth
from ..core.config import settings
from ..core.database import prisma
from ..utils.errors import upstream_error
from ..services.email_service import email_service

logger = logging.getLogger(__name__)
limiter = Limiter(key_func=get_remote_address)

router = APIRouter(prefix="/api/v1/account", tags=["account"])


def _auth_header():
    """
    Generate authentication header for ZyncLab API.
    """
    if not settings.zynk_api_key:
        raise HTTPException(status_code=500, detail="ZyncLab API key not configured")
    return {
        "x-api-token": settings.zynk_api_key,
    }


@router.get("/funding")
@limiter.limit("30/minute")
async def get_or_create_funding_account(
    request: Request,
    current: Entities = Depends(auth.get_current_entity)
):
    """
    Get funding account for the authenticated user with auto-creation.
    
    Flow:
    1. Check if user's KYC is completed (status = APPROVED)
    2. If funding account exists → Return details
    3. If no funding account exists:
       - Attempt to create one via Zynk API
       - If creation succeeds: Send email notification, return account details
       - If creation fails: Return 503 "System under maintenance"
    
    Returns:
        Funding account details
    """
    logger.info(f"[FUNDING] Get/Create funding account request for user: {current.email}")
    
    # Step 1: Check KYC status
    try:
        kyc_session = await prisma.kyc_sessions.find_first(
            where={
                "entity_id": current.id,
                "deleted_at": None
            },
            order={"created_at": "desc"}
        )
        
        if not kyc_session or kyc_session.status != "APPROVED":
            logger.warning(f"[FUNDING] KYC not approved for entity {current.id}. Status: {kyc_session.status if kyc_session else 'NO_SESSION'}")
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="KYC verification is required before creating a funding account. Please complete your KYC verification first."
            )
        
        logger.info(f"[FUNDING] KYC approved for entity {current.id}")
        
    except HTTPException:
        raise
    except Exception as exc:
        logger.error(f"[FUNDING] Error checking KYC status for entity {current.id}: {exc}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to verify KYC status. Please try again later."
        )
    
    # Step 2: Check if entity is linked to Zynk
    zynk_entity_id = getattr(current, "zynk_entity_id", None) or getattr(current, "external_entity_id", None)
    if not zynk_entity_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Entity not linked to external service. Please complete the entity creation process."
        )
    
    # Clean the entity ID
    zynk_entity_id = str(zynk_entity_id).strip().replace('\n', '').replace('\r', '')
    
    # Step 3: Try to fetch existing funding accounts
    fetch_url = f"{settings.zynk_base_url}/api/v1/transformer/accounts/{zynk_entity_id}/funding_accounts"
    headers = {**_auth_header(), "Accept": "application/json"}
    
    logger.info(f"[FUNDING] Attempting to fetch existing funding accounts from: {fetch_url}")
    
    funding_accounts_exist = False
    existing_accounts = None
    
    for attempt in range(2):
        try:
            async with httpx.AsyncClient(timeout=settings.zynk_timeout_s) as client:
                resp = await client.get(fetch_url, headers=headers)
        except httpx.RequestError as exc:
            if attempt == 0:
                continue
            logger.error(f"[FUNDING] Network error while fetching funding accounts: {exc}")
            # Continue to creation attempt
            break
        
        try:
            body = resp.json()
        except ValueError:
            logger.error(f"[FUNDING] Invalid JSON response: {resp.text[:200]}")
            break
        
        if 200 <= resp.status_code < 300:
            if body.get("success") and body.get("data"):
                data = body.get("data", {})
                accounts = data.get("fundingAccounts", [])
                if accounts and len(accounts) > 0:
                    funding_accounts_exist = True
                    existing_accounts = body
                    logger.info(f"[FUNDING] Found {len(accounts)} existing funding accounts")
                    break
                else:
                    logger.info("[FUNDING] No funding accounts found (empty list)")
                    break
            else:
                logger.info("[FUNDING] No funding accounts found in response")
                break
        elif resp.status_code == 404:
            logger.info("[FUNDING] No funding accounts found (404)")
            break
        else:
            logger.warning(f"[FUNDING] Unexpected status code: {resp.status_code}")
            break
    
    # Step 4: If funding account exists, return it
    if funding_accounts_exist and existing_accounts:
        logger.info(f"[FUNDING] Returning existing funding account for entity {current.id}")
        return existing_accounts
    
    # Step 5: No funding account exists - attempt to create one
    logger.info(f"[FUNDING] No funding account found. Attempting to create one for entity {current.id}")
    
    # Use the specific jurisdiction ID
    jurisdiction_id = "jurisdiction_51607ba7_c0b2_428c_a8c5_75ad94c9ffb1"
    logger.info(f"[FUNDING] Using jurisdiction: {jurisdiction_id}")
    
    create_url = f"{settings.zynk_base_url}/api/v1/transformer/accounts/{zynk_entity_id}/create/funding_account/{jurisdiction_id}"
    create_headers = {**_auth_header(), "Content-Type": "application/json", "Accept": "application/json"}
    
    logger.info(f"[FUNDING] Creating funding account - URL: {create_url}")
    
    for attempt in range(2):
        try:
            async with httpx.AsyncClient(timeout=settings.zynk_timeout_s) as client:
                # POST request without body - jurisdiction is in the URL path
                create_resp = await client.post(create_url, json={}, headers=create_headers)
        except httpx.RequestError as exc:
            if attempt == 0:
                continue
            logger.error(f"[FUNDING] Network error while creating funding account: {exc}")
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="System is currently under maintenance. We'll notify you via email once your funding account is created."
            )
        
        try:
            create_body = create_resp.json()
        except ValueError:
            logger.error(f"[FUNDING] Invalid JSON during creation: {create_resp.text[:200]}")
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="System is currently under maintenance. We'll notify you via email once your funding account is created."
            )
        
        # Step 6: Handle creation response
        if 200 <= create_resp.status_code < 300:
            if create_body.get("success"):
                logger.info(f"[FUNDING] Funding account created successfully for entity {current.id}")
                
                # Step 7: Send email notification
                try:
                    account_data = create_body.get("data", {})
                    funding_account = account_data.get("fundingAccount", {})
                    
                    user_name = f"{current.first_name} {current.last_name}"
                    await email_service.send_funding_account_created_notification(
                        email=current.email,
                        user_name=user_name,
                        account_details=funding_account
                    )
                    logger.info(f"[FUNDING] Email notification sent to {current.email}")
                except Exception as email_error:
                    # Don't fail the request if email fails
                    logger.error(f"[FUNDING] Failed to send email notification: {email_error}", exc_info=True)
                
                # Return the created account
                return create_body
            else:
                error_msg = create_body.get("message", "Creation failed")
                logger.error(f"[FUNDING] Funding account creation failed: {error_msg}")
                raise HTTPException(
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    detail="System is currently under maintenance. We'll notify you via email once your funding account is created."
                )
        else:
            error_detail = create_body.get("message", f"HTTP {create_resp.status_code}")
            logger.error(f"[FUNDING] Zynk API error during creation: {error_detail}")
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="System is currently under maintenance. We'll notify you via email once your funding account is created."
            )
    
    # If all retries failed
    raise HTTPException(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        detail="System is currently under maintenance. We'll notify you via email once your funding account is created."
    )

