"""
Wallet Router

Handles wallet creation endpoints for Zynk Labs Continuum API integration.
Complete wallet creation flow:
1. Register Auth (always proceed)
2. Initiate OTP
3. Generate P-256 key pair
4. Start session with OTP verification
5. Decrypt credential bundle (HPKE)
6. Prepare wallet creation
7. Sign payload with session key
8. Submit wallet creation
"""

import json
import logging
import httpx
from typing import Optional, Any
from fastapi import APIRouter, HTTPException, status, Depends, Request
from slowapi import Limiter
from slowapi.util import get_remote_address
from app.core.config import settings
from app.core.auth import get_current_entity
from app.core.database import prisma
from prisma.models import entities as Entities
from app.utils.wallet_crypto import (
    generate_keypair as generate_keypair_crypto,
    decrypt_credential_bundle,
    sign_payload_with_api_key
)
from app.services.otp_service import OTPService

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1/wallets", tags=["Wallets"])

# Rate limiter instance (will be set from app.state.limiter)
limiter = Limiter(key_func=get_remote_address)

# Zynk API base URL
ZYNK_BASE_URL = "https://qaapi.zynklabs.xyz"

# Error message constants
ERR_ZYNK_API_ERROR = "Zynk API returned error"
ERR_WALLET_NOT_FOUND = "Wallet not found or unauthorized"

logger.info(f"[WALLET] Router initialized with Zynk API: {ZYNK_BASE_URL}")


def _clean_entity_id(entity_id) -> str:
    """Clean entity ID by removing whitespace and validating format."""
    if not entity_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User is not linked to a Zynk entity"
        )

    entity_id = str(entity_id).strip()
    if not entity_id or '\n' in entity_id or '\r' in entity_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid entity ID format"
        )

    return entity_id


def _zynk_auth_header():
    """Get Zynk API authentication header"""
    if not settings.zynk_api_key:
        raise HTTPException(status_code=500, detail="Zynk API key not configured")
    return {
        "x-api-token": settings.zynk_api_key,
        "Content-Type": "application/json",
        "Accept": "application/json"
    }


async def _initiate_otp_internal(entity_id: str, user_email: str) -> dict:
    """
    Internal helper function to initiate OTP.
    Can be called from register-auth or the initiate-otp endpoint.
    
    Args:
        entity_id: Cleaned entity ID
        user_email: User email for logging
        
    Returns:
        dict: OTP response with otpId, otpType, otpContact
    """
    logger.info("[WALLET] ========== INITIATE OTP (INTERNAL) START ==========")
    logger.info(f"[WALLET] Initiating OTP for entity: {entity_id}, user: {user_email}")
    
    # Call Zynk initiate-otp endpoint (entityId in path, no payload needed)
    url = f"{ZYNK_BASE_URL}/api/v1/wallets/{entity_id}/initiate-otp"
    logger.info(f"[WALLET] Zynk API URL: {url}")
    
    headers = _zynk_auth_header()
    
    async with httpx.AsyncClient(timeout=settings.zynk_timeout_s) as client:
        logger.info("[WALLET] Sending POST request to Zynk API for initiate-otp")
        response = await client.post(url, headers=headers)
        logger.info(f"[WALLET] Response status code: {response.status_code}")
        
        if response.status_code != 200:
            try:
                error_body = response.json()
                error_detail = error_body.get("message", f"HTTP {response.status_code}")
            except (ValueError, json.JSONDecodeError):
                error_detail = f"HTTP {response.status_code}: {response.text[:200]}"
            
            logger.error(f"[WALLET] Initiate OTP failed: {error_detail}")
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail=f"Zynk API error: {error_detail}"
            )
        
        body = response.json()
        logger.info(f"[WALLET] Initiate OTP response: {body}")
        
        if not body.get("success"):
            error_msg = body.get("message", ERR_ZYNK_API_ERROR)
            logger.error(f"[WALLET] Initiate OTP failed: {error_msg}")
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail=error_msg
            )
        
        data = body.get("data", {})
        otp_id = data.get("otpId")
        
        if not otp_id:
            logger.error("[WALLET] Initiate OTP failed: Missing otpId in response")
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail="Zynk API did not return otpId"
            )
        
        logger.info("[WALLET] ========== INITIATE OTP (INTERNAL) SUCCESS ==========")
        logger.info(f"[WALLET] OTP ID: {otp_id}")
        return body


async def _handle_successful_registration(
    entity_id: str,
    current_user: Entities,
) -> dict:
    """Handle successful registration (200 with success=true)."""
    logger.info("[WALLET] Step 5 Complete: New user registered successfully")
    logger.info("[WALLET] ========== REGISTER AUTH SUCCESS (New Registration) ==========")
    logger.info("[WALLET] ✅ Automatically calling initiate-otp...")
    
    try:
        otp_response = await _initiate_otp_internal(entity_id, current_user.email)
        logger.info("[WALLET] ✅ Initiate OTP completed successfully")
        return otp_response
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"[WALLET] Unexpected error during initiate-otp: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to initiate OTP: {str(e)}"
        )


async def _handle_already_registered(
    entity_id: str,
    current_user: Entities,
) -> dict:
    """Handle already registered case (400 with specific error message)."""
    logger.info("[WALLET] Step 5 Complete: User already registered with Turnkey")
    logger.info("[WALLET] ========== REGISTER AUTH SUCCESS (Already Registered) ==========")
    logger.info("[WALLET] ✅ Automatically calling initiate-otp...")
    
    try:
        otp_response = await _initiate_otp_internal(entity_id, current_user.email)
        logger.info("[WALLET] ✅ Initiate OTP completed successfully")
        return otp_response
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"[WALLET] Unexpected error during initiate-otp: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to initiate OTP: {str(e)}"
        )


def _parse_error_response(response: httpx.Response) -> str:
    """Parse error response from Zynk API."""
    try:
        return response.json().get("message", f"HTTP {response.status_code}")
    except (ValueError, json.JSONDecodeError):
        return f"HTTP {response.status_code}: {response.text[:200]}"


@router.post("/register-auth")
@limiter.limit("10/minute")
async def register_auth(
    request: Request,
    current_user: Entities = Depends(get_current_entity)
):
    """
    Register auth for wallet creation.
    Always proceeds to next step regardless of response.

    Returns:
        Success response (always proceeds)
    """
    logger.info("[WALLET] ========== REGISTER AUTH START ==========")
    logger.info(f"[WALLET] Step 1: Received register-auth request from user: {current_user.email}")

    # Get and clean entity ID from authenticated user
    logger.info("[WALLET] Step 2: Getting and cleaning entity ID")
    entity_id = _clean_entity_id(current_user.zynk_entity_id)
    logger.info(f"[WALLET] Step 2 Complete: Entity ID = {entity_id}")

    # Call Zynk register-auth endpoint
    url = f"{ZYNK_BASE_URL}/api/v1/wallets/{entity_id}/register-auth"
    payload = {
        "authType": "Email_Auth",
        "authPayload": {
            "email": current_user.email
        }
    }

    logger.info("[WALLET] Step 3: Preparing Zynk API call")
    logger.info(f"[WALLET] Register auth payload: {payload}")
    logger.info(f"[WALLET] Register auth URL: {url}")

    async with httpx.AsyncClient(timeout=settings.zynk_timeout_s) as client:
        logger.info("[WALLET] Step 4: Sending request to Zynk API")
        response = await client.post(url, json=payload, headers=_zynk_auth_header())
        logger.info(f"[WALLET] Step 4 Complete: Received response with status {response.status_code}")

        # Handle both 200 (success) and 400 (already registered) responses
        if response.status_code == 200:
            body = response.json()
            logger.info(f"[WALLET] Register auth response: {body}")

            if body.get("success"):
                return await _handle_successful_registration(entity_id, current_user)
            else:
                error_msg = body.get("error", {}).get("message", "Unknown error")
                logger.error(f"[WALLET] Register auth unexpected failure: {error_msg}")
                raise HTTPException(
                    status_code=status.HTTP_502_BAD_GATEWAY,
                    detail=f"Zynk API error: {error_msg}"
                )

        elif response.status_code == 400:
            try:
                body = response.json()
                error_details = body.get("error", {}).get("details", "")
                if "Entity already has a registered Turnkey organization" in error_details:
                    return await _handle_already_registered(entity_id, current_user)
                else:
                    error_msg = body.get("error", {}).get("message", "Bad Request")
                    logger.error(f"[WALLET] Register auth 400 error: {error_msg}")
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail=error_msg
                    )
            except HTTPException:
                raise
            except Exception as e:
                logger.error(f"[WALLET] Failed to parse 400 response: {e}")
                raise HTTPException(
                    status_code=status.HTTP_502_BAD_GATEWAY,
                    detail="Invalid response from Zynk API"
                )

        else:
            error_detail = _parse_error_response(response)
            logger.error(f"[WALLET] Register auth HTTP error: {error_detail}")
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail=f"Zynk API error: {error_detail}"
            )


@router.post("/generate-keypair")
@limiter.limit("30/minute")
async def generate_keypair(request: Request):
    """
    Generate P-256 key pair for wallet creation.

    Returns:
        - privateKey: 64-character hex string
        - publicKey: 130-character hex string (uncompressed)
    """
    logger.info("[WALLET] Generating P-256 key pair")

    private_hex, public_hex = generate_keypair_crypto()

    logger.info(f"[WALLET] Key pair generated - private: {len(private_hex)} chars, public: {len(public_hex)} chars")

    return {
        "success": True,
        "data": {
            "privateKey": private_hex,
            "publicKey": public_hex
        }
    }


@router.post("/initiate-otp")
@limiter.limit("10/minute")
async def initiate_otp(
    request: Request,
    current_user: Entities = Depends(get_current_entity)
):
    """
    Initiate OTP for wallet creation.
    This endpoint can still be called directly if needed.

    Returns:
        - otpId: OTP session ID
        - otpType: OTP type
        - otpContact: Contact method
    """
    try:
        logger.info("[WALLET] ========== INITIATE OTP (ENDPOINT) START ==========")
        logger.info(f"[WALLET] Received initiate-otp request from user: {current_user.email}")

        # Get and clean entity ID from authenticated user
        entity_id = _clean_entity_id(current_user.zynk_entity_id)
        logger.info(f"[WALLET] Entity ID: {entity_id}")

        # Call the internal helper function
        result = await _initiate_otp_internal(entity_id, current_user.email)
        
        logger.info("[WALLET] ========== INITIATE OTP (ENDPOINT) SUCCESS ==========")
        return result

    except HTTPException as he:
        logger.error("[WALLET] ========== INITIATE OTP (ENDPOINT) FAILED (HTTPException) ==========")
        logger.error(f"[WALLET] HTTPException status: {he.status_code}")
        logger.error(f"[WALLET] HTTPException detail: {he.detail}")
        raise
    except Exception as e:
        logger.error("[WALLET] ========== INITIATE OTP (ENDPOINT) FAILED (Unexpected Error) ==========")
        logger.error(f"[WALLET] Error type: {type(e).__name__}")
        logger.error(f"[WALLET] Error message: {str(e)}")
        logger.error("[WALLET] Full traceback:", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to initiate OTP: {str(e)}"
        )


@router.post("/start-session")
@limiter.limit("10/minute")
async def start_session(
    data: dict,
    request: Request,
    current_user: Entities = Depends(get_current_entity)
):
    """
    Start session with OTP code. Generates keypair (or uses provided publicKey) and calls Zynk API.

    Body:
        - otpId: OTP session ID from initiate-otp response (required)
        - otpCode: OTP code entered by user (required)
        - publicKey: Optional public key (if not provided, will generate a new keypair)

    Returns:
        - success: true
        - data:
            - credentialBundle: Encrypted credential bundle from Zynk API
            - privateKey: Private key (if generated, for decryption later)
    """
    logger.info("[WALLET] ========== START SESSION START ==========")
    logger.info(f"[WALLET] Request payload keys: {list(data.keys())}")
    logger.info(f"[WALLET] Full request payload: {data}")

    otp_id = data.get("otpId")
    otp_code = data.get("otpCode")
    public_key = data.get("publicKey")

    if not otp_id or not otp_code:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="otpId and otpCode are required"
        )

    logger.info(f"[WALLET] Step 1: Received otpId: {otp_id}, otpCode: {otp_code}")
    if public_key:
        logger.info(f"[WALLET] Step 1a: Using provided publicKey: {public_key}")

    # Get and clean entity_id from current user
    logger.info("[WALLET] Step 2: Getting entity ID")
    entity_id = _clean_entity_id(current_user.zynk_entity_id)
    logger.info(f"[WALLET] Step 2 Complete: Entity ID = {entity_id}")

    # Generate keypair if publicKey not provided
    private_hex = None
    if not public_key:
        logger.info("[WALLET] Step 3: Generating P-256 keypair (publicKey not provided)")
        private_hex, public_key = generate_keypair_crypto()
        logger.info("[WALLET] Step 3 Complete: Generated keypair")
        logger.info(f"[WALLET] Private key length: {len(private_hex)} chars")
        logger.info(f"[WALLET] Public key length: {len(public_key)} chars")
    else:
        logger.info("[WALLET] Step 3: Using provided publicKey (no keypair generation needed)")

    logger.info(f"[WALLET] Public key to use: {public_key}")

    # Call Zynk wallets start-session endpoint
    logger.info("[WALLET] Step 4: Preparing Zynk API call")
    url = f"{ZYNK_BASE_URL}/api/v1/wallets/{entity_id}/start-session"
    payload = {
        "publicKey": public_key,
        "otpId": otp_id,
        "otpCode": otp_code
    }

    logger.info(f"[WALLET] Step 4 Complete: Zynk API URL = {url}")
    logger.info(f"[WALLET] Step 4 Complete: Request payload to Zynk = {payload}")

    async with httpx.AsyncClient(timeout=settings.zynk_timeout_s) as client:
        logger.info("[WALLET] Step 5: Sending POST request to Zynk API")
        logger.info(f"[WALLET] Request URL: {url}")
        logger.info(f"[WALLET] Request headers: {_zynk_auth_header()}")
        logger.info(f"[WALLET] Request payload: {payload}")
        
        response = await client.post(
            url,
            json=payload,
            headers=_zynk_auth_header()
        )

        logger.info(f"[WALLET] Step 5 Complete: Response status = {response.status_code}")
        logger.info(f"[WALLET] Response headers: {dict(response.headers)}")

        if response.status_code != 200:
            try:
                error_body = response.json()
                error_detail = error_body.get("message", f"HTTP {response.status_code}")
                logger.error(f"[WALLET] Zynk API error response: {error_body}")
            except (ValueError, json.JSONDecodeError):
                error_detail = f"HTTP {response.status_code}: {response.text[:200]}"
                logger.error(f"[WALLET] Zynk API error (non-JSON): {error_detail}")
            
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail=f"Zynk API error: {error_detail}"
            )

        logger.info("[WALLET] Step 6: Parsing response")
        body = response.json()
        logger.info(f"[WALLET] Step 6 Complete: Full response body = {body}")
        logger.info("[WALLET] Response JSON (formatted):")
        logger.info(f"[WALLET] {json.dumps(body, indent=2)}")

        if not body.get("success"):
            error_msg = body.get("message", ERR_ZYNK_API_ERROR)
            logger.error(f"[WALLET] Zynk API returned error: {error_msg}")
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail=error_msg
            )

        logger.info("[WALLET] Step 7: Extracting credential bundle")
        credential_bundle = body.get("data", {}).get("credentialBundle")
        if not credential_bundle:
            logger.error("[WALLET] Missing credentialBundle in response")
            logger.error(f"[WALLET] Response data keys: {list(body.get('data', {}).keys())}")
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail="Zynk API did not return credential bundle"
            )

        logger.info(f"[WALLET] Step 7 Complete: Credential bundle length = {len(credential_bundle)} chars")
        logger.info(f"[WALLET] Step 7 Complete: Credential bundle (first 50 chars): {credential_bundle[:50]}...")
        logger.info("[WALLET] ========== START SESSION SUCCESS ==========")
        logger.info("[WALLET] ✅ Full Zynk API Response:")
        logger.info(f"[WALLET] {json.dumps(body, indent=2)}")
        logger.info(f"[WALLET] ✅ Credential Bundle: {credential_bundle}")

        # Prepare response
        result = {
            "success": True,
            "data": {
                "credentialBundle": credential_bundle
            }
        }
        
        # Include private key if we generated it (for decryption later)
        if private_hex:
            result["data"]["privateKey"] = private_hex
            logger.info(f"[WALLET] ✅ Private Key (for decryption): {private_hex}")

        return result


@router.post("/decrypt-bundle")
@limiter.limit("30/minute")
async def decrypt_bundle(
    data: dict,
    request: Request,
    current_user: Entities = Depends(get_current_entity)
):
    """
    Decrypt credential bundle using HPKE to get session keys.

    Body:
        - credentialBundle: Encrypted credential bundle from start-session
        - ephemeralPrivateKey: 64-character hex string from generate-keypair

    Returns:
        - sessionPrivateKey: 64-character hex string
        - sessionPublicKey: 66-character compressed hex string
    """
    logger.info(f"[WALLET] Decrypt bundle request - keys: {list(data.keys())}")

    credential_bundle = data.get("credentialBundle")
    ephemeral_private_key = data.get("ephemeralPrivateKey")

    if not credential_bundle or not ephemeral_private_key:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="credentialBundle and ephemeralPrivateKey are required"
        )

    logger.info(f"[WALLET] Input - bundle: {len(credential_bundle)} chars, private key: {len(ephemeral_private_key)} chars")

    # Decrypt using HPKE
    logger.info("[WALLET] Starting HPKE decryption")
    result = decrypt_credential_bundle(credential_bundle, ephemeral_private_key)

    session_private_key = result['tempPrivateKey']
    session_public_key = result['tempPublicKey']

    logger.info(f"[WALLET] Decryption successful - private key: {len(session_private_key)} chars, public key: {len(session_public_key)} chars")

    return {
        "success": True,
        "data": {
            "sessionPrivateKey": session_private_key,
            "sessionPublicKey": session_public_key
        }
    }


@router.post("/prepare")
@limiter.limit("30/minute")
async def prepare_wallet(
    data: dict,
    request: Request,
    current_user: Entities = Depends(get_current_entity)
):
    """
    Prepare wallet creation challenge.

    Body:
        - walletName: Name for the wallet
        - chain: Blockchain (SOLANA, ETHEREUM, etc.)

    Returns:
        - payloadId: Unique identifier for this challenge
        - payloadToSign: JSON string to sign
        - rpId: Relying Party ID
    """
    logger.info(f"[WALLET] Prepare wallet request - keys: {list(data.keys())}")

    wallet_name = data.get("walletName")
    chain = data.get("chain", "SOLANA")

    if not wallet_name:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="walletName is required"
        )

    # Get and clean entity_id from current user
    entity_id = _clean_entity_id(current_user.zynk_entity_id)

    logger.info(f"[WALLET] Preparing wallet - Name: {wallet_name}, Chain: {chain}, Entity ID: {entity_id}")

    # Call Zynk prepare wallet creation endpoint
    url = f"{ZYNK_BASE_URL}/api/v1/wallets/{entity_id}/create/prepare"
    payload = {
        "walletName": wallet_name,
        "chain": chain
    }

    logger.info(f"[WALLET] Prepare wallet payload: {payload}")

    async with httpx.AsyncClient(timeout=settings.zynk_timeout_s) as client:
        response = await client.post(
            url,
            json=payload,
            headers=_zynk_auth_header()
        )

        logger.info(f"[WALLET] Prepare wallet response status: {response.status_code}")

        if response.status_code != 200:
            error_detail = response.json().get("message", f"HTTP {response.status_code}")
            logger.error(f"[WALLET] Zynk API error: {error_detail}")
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail=f"Zynk API error: {error_detail}"
            )

        body = response.json()
        if not body.get("success"):
            error_msg = body.get("message", ERR_ZYNK_API_ERROR)
            logger.error(f"[WALLET] Zynk API returned error: {error_msg}")
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail=error_msg
            )

        logger.info(f"[WALLET] Prepare wallet response: {body}")

        data_response = body.get("data", {})
        payload_id = data_response.get("payloadId")
        payload_to_sign = data_response.get("payloadToSign")
        rp_id = data_response.get("rpId")

        if not all([payload_id, payload_to_sign]):
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail="Zynk API did not return complete challenge data"
            )

        return {
            "success": True,
            "data": {
                "payloadId": payload_id,
                "payloadToSign": payload_to_sign,
                "rpId": rp_id
            }
        }


@router.get("/user")
@limiter.limit("60/minute")
async def get_user_wallet(
    request: Request,
    current_user: Entities = Depends(get_current_entity)
):
    """
    Get user's wallet from database.
    Returns the first active wallet for the authenticated user.
    
    Returns:
        - walletId: Zynk wallet ID
        - walletName: User-defined wallet name
        - chain: Blockchain (SOLANA, etc.)
        - addresses: List of addresses from wallet_accounts
        - created_at: Wallet creation timestamp
    """
    logger.info(f"[WALLET] Fetching wallet for user: {current_user.email} (ID: {current_user.id})")
    
    try:
        # Get user's wallet with its accounts
        wallet = await prisma.wallets.find_first(
            where={
                "entity_id": str(current_user.id),
                "deleted_at": None,
                "status": "ACTIVE"
            },
            include={
                "wallet_accounts": {
                    "where": {
                        "deleted_at": None
                    }
                }
            },
            order={
                "created_at": "desc"
            }
        )
        
        if not wallet:
            logger.info(f"[WALLET] No wallet found for user: {current_user.id}")
            return {
                "success": True,
                "message": "No wallet found",
                "data": None
            }
        
        # Extract addresses and account details
        addresses = [account.address for account in wallet.wallet_accounts] if wallet.wallet_accounts else []
        wallet_accounts = [
            {
                "id": str(account.id),
                "address": account.address,
                "chain": wallet.chain,
                "wallet_name": wallet.wallet_name,
                "wallet_id": wallet.zynk_wallet_id,
            }
            for account in wallet.wallet_accounts
        ] if wallet.wallet_accounts else []
        
        logger.info(f"[WALLET] Found wallet: {wallet.zynk_wallet_id} with {len(addresses)} addresses")
        
        return {
            "success": True,
            "message": "Wallet retrieved successfully",
            "data": {
                "walletId": wallet.zynk_wallet_id,
                "walletName": wallet.wallet_name,
                "chain": wallet.chain,
                "addresses": addresses,
                "wallet_accounts": wallet_accounts,
                "status": wallet.status,
                "createdAt": wallet.created_at.isoformat() if wallet.created_at else None
            }
        }
    except Exception as e:
        logger.error(f"[WALLET] Error fetching user wallet: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to fetch wallet"
        )


@router.get("/{wallet_id}")
@limiter.limit("60/minute")
async def get_wallet_details(
    wallet_id: str,
    request: Request,
    current_user: Entities = Depends(get_current_entity)
):
    """
    Get wallet details from Zynk API.
    
    Path:
        - wallet_id: Zynk wallet ID
    
    Returns:
        Wallet details from Zynk API
    """
    logger.info(f"[WALLET] Fetching wallet details from Zynk - wallet_id: {wallet_id}, user: {current_user.email}")
    
    # Verify wallet belongs to user
    wallet = await prisma.wallets.find_first(
        where={
            "zynk_wallet_id": wallet_id,
            "entity_id": str(current_user.id),
            "deleted_at": None
        }
    )
    
    if not wallet:
        logger.error(f"[WALLET] Wallet not found or unauthorized - wallet_id: {wallet_id}, user: {current_user.id}")
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=ERR_WALLET_NOT_FOUND
        )
    
    # Call Zynk API
    url = f"{ZYNK_BASE_URL}/api/v1/wallets/{wallet_id}"
    logger.info(f"[WALLET] Calling Zynk API: {url}")
    
    async with httpx.AsyncClient(timeout=settings.zynk_timeout_s) as client:
        response = await client.get(url, headers=_zynk_auth_header())
        
        if response.status_code != 200:
            logger.error(f"[WALLET] Zynk API error: {response.status_code}")
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail="Failed to fetch wallet details from Zynk API"
            )
        
        body = response.json()
        logger.info("[WALLET] Wallet details retrieved successfully")
        return body


@router.get("/{wallet_id}/balances")
@limiter.limit("60/minute")
async def get_wallet_balances(
    wallet_id: str,
    request: Request,
    current_user: Entities = Depends(get_current_entity)
):
    """
    Get wallet balances from Zynk API.
    
    Path:
        - wallet_id: Zynk wallet ID
    
    Returns:
        Wallet balances for all tokens
    """
    logger.info(f"[WALLET] Fetching wallet balances from Zynk - wallet_id: {wallet_id}, user: {current_user.email}")
    
    # Verify wallet belongs to user
    wallet = await prisma.wallets.find_first(
        where={
            "zynk_wallet_id": wallet_id,
            "entity_id": str(current_user.id),
            "deleted_at": None
        }
    )
    
    if not wallet:
        logger.error(f"[WALLET] Wallet not found or unauthorized - wallet_id: {wallet_id}, user: {current_user.id}")
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=ERR_WALLET_NOT_FOUND
        )
    
    # Call Zynk API
    url = f"{ZYNK_BASE_URL}/api/v1/wallets/{wallet_id}/balances"
    logger.info(f"[WALLET] Calling Zynk API: {url}")
    
    async with httpx.AsyncClient(timeout=settings.zynk_timeout_s) as client:
        response = await client.get(url, headers=_zynk_auth_header())
        
        if response.status_code != 200:
            logger.error(f"[WALLET] Zynk API error: {response.status_code}")
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail="Failed to fetch wallet balances from Zynk API"
            )
        
        body = response.json()
        logger.info("[WALLET] Wallet balances retrieved successfully")
        return body


@router.get("/{wallet_id}/{address}/transactions")
@limiter.limit("60/minute")
async def get_wallet_transactions(
    wallet_id: str,
    address: str,
    request: Request,
    current_user: Entities = Depends(get_current_entity),
    limit: int = 10,
    offset: int = 0
):
    """
    Get wallet transactions from Zynk API.
    
    Path:
        - wallet_id: Zynk wallet ID
        - address: Wallet address
    
    Query:
        - limit: Number of transactions (default: 10)
        - offset: Pagination offset (default: 0)
    
    Returns:
        Transaction history
    """
    logger.info(f"[WALLET] Fetching wallet transactions from Zynk - wallet_id: {wallet_id}, address: {address}, user: {current_user.email}")
    
    # Verify wallet belongs to user
    wallet = await prisma.wallets.find_first(
        where={
            "zynk_wallet_id": wallet_id,
            "entity_id": str(current_user.id),
            "deleted_at": None
        }
    )
    
    if not wallet:
        logger.error(f"[WALLET] Wallet not found or unauthorized - wallet_id: {wallet_id}, user: {current_user.id}")
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=ERR_WALLET_NOT_FOUND
        )
    
    # Call Zynk API
    url = f"{ZYNK_BASE_URL}/api/v1/wallets/{wallet_id}/{address}/transactions"
    params = {"limit": limit, "offset": offset}
    logger.info(f"[WALLET] Calling Zynk API: {url} with params: {params}")
    
    async with httpx.AsyncClient(timeout=settings.zynk_timeout_s) as client:
        response = await client.get(url, headers=_zynk_auth_header(), params=params)
        
        if response.status_code != 200:
            logger.error(f"[WALLET] Zynk API error: {response.status_code}")
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail="Failed to fetch wallet transactions from Zynk API"
            )
        
        body = response.json()
        logger.info("[WALLET] Wallet transactions retrieved successfully")
        return body


@router.post("/sign-payload")
@limiter.limit("30/minute")
async def sign_payload(
    data: dict,
    request: Request,
    current_user: Entities = Depends(get_current_entity)
):
    """
    Sign payload using session private key.

    Body:
        - payload: JSON string to sign from prepare step
        - sessionPrivateKey: 64-character hex string from decrypt step
        - sessionPublicKey: 66-character compressed hex string

    Returns:
        - signature: Base64URL-encoded signature
    """
    logger.info(f"[WALLET] Sign payload request - keys: {data}")

    payload_to_sign = data.get("payload")
    session_private_key = data.get("sessionPrivateKey")
    session_public_key = data.get("sessionPublicKey")

    if not all([payload_to_sign, session_private_key, session_public_key]):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="payload, sessionPrivateKey, and sessionPublicKey are required"
        )

    logger.info(f"[WALLET] Input - payload: {len(payload_to_sign)} chars, private key: {len(session_private_key)} chars, public key: {len(session_public_key)} chars")

    # Sign the payload
    logger.info("[WALLET] Signing payload with session key")
    signature = sign_payload_with_api_key(payload_to_sign, session_private_key, session_public_key)

    logger.info(f"[WALLET] Payload signed successfully - signature: {len(signature)} chars")
    logger.info(f"[WALLET] 🔐 Signature (first 80 chars): {signature[:80]}...")
    logger.info(f"[WALLET] 🔐 Signature (last 80 chars): ...{signature[-80:]}")

    return {
        "success": True,
        "data": {
            "signature": signature
        }
    }


async def _save_wallet_to_db(
    wallet_id: str,
    current_user: Entities,
    wallet_name: str,
    chain: str,
    addresses: list,
) -> Optional[Any]:
    """Save wallet to database. Returns wallet object or None if save fails."""
    logger.info(f"[WALLET] Saving wallet to database - ID: {wallet_id}, Entity: {current_user.id}")
    try:
        wallet = await prisma.wallets.create(
            data={
                "entity_id": str(current_user.id),
                "zynk_wallet_id": wallet_id,
                "wallet_name": wallet_name,
                "chain": chain,
                "status": "ACTIVE"
            }
        )
        logger.info(f"[WALLET] Wallet saved to database successfully - DB ID: {wallet.id}")
        if addresses and len(addresses) > 0:
            logger.info(f"[WALLET] Initial address from wallet creation: {addresses[0]}")
        return wallet
    except Exception as db_error:
        logger.error(f"[WALLET] Failed to save wallet to database: {db_error}")
        return None


async def _prepare_account_creation(
    wallet_id: str,
    chain: str,
) -> Optional[dict]:
    """Prepare account creation and return prepare data if successful."""
    prepare_url = f"{ZYNK_BASE_URL}/api/v1/wallets/{wallet_id}/accounts/prepare"
    prepare_payload = {"chain": chain}
    
    logger.info(f"[WALLET] Calling account prepare: {prepare_url}")
    
    async with httpx.AsyncClient(timeout=settings.zynk_timeout_s) as client:
        prepare_response = await client.post(
            prepare_url,
            json=prepare_payload,
            headers=_zynk_auth_header()
        )
        
        if prepare_response.status_code == 200:
            prepare_body = prepare_response.json()
            if prepare_body.get("success"):
                account_prepare_data = prepare_body.get("data", {})
                logger.info(f"[WALLET] ✅ Account preparation successful - payloadId: {account_prepare_data.get('payloadId')}")
                logger.info("[WALLET] 📦 Account Prepare Response:")
                logger.info(f"[WALLET]    - payloadId: {account_prepare_data.get('payloadId')}")
                logger.info(f"[WALLET]    - payloadToSign (first 100 chars): {account_prepare_data.get('payloadToSign', '')[:100]}")
                logger.info("❤️❤️❤️❤️❤️❤️❤️❤️")
                return account_prepare_data
            else:
                logger.warning(f"[WALLET] Account preparation returned unsuccessful: {prepare_body}")
        else:
            logger.warning(f"[WALLET] Account preparation failed with status {prepare_response.status_code}")
    
    return None


async def _sign_and_submit_account(
    account_prepare_data: dict,
    session_private_key: str,
    session_public_key: str,
    wallet: Any,
) -> Optional[dict]:
    """Sign and submit account creation. Returns account data if successful."""
    logger.info("[WALLET] 🔐 Session keys provided - automatically signing and submitting account...")
    
    try:
        account_payload_to_sign = account_prepare_data.get('payloadToSign')
        account_payload_id = account_prepare_data.get('payloadId')
        
        logger.info("[WALLET] Signing account payload...")
        account_signature = sign_payload_with_api_key(
            account_payload_to_sign,
            session_private_key,
            session_public_key
        )
        logger.info(f"[WALLET] ✅ Account payload signed - signature length: {len(account_signature)}")
        
        submit_url = f"{ZYNK_BASE_URL}/api/v1/wallets/accounts/submit"
        submit_payload = {
            "payloadId": account_payload_id,
            "signatureType": "ApiKey",
            "signature": account_signature
        }
        
        logger.info("[WALLET] Submitting account to Zynk...")
        async with httpx.AsyncClient(timeout=settings.zynk_timeout_s) as client:
            submit_response = await client.post(
                submit_url,
                json=submit_payload,
                headers=_zynk_auth_header()
            )
            
            if submit_response.status_code == 200:
                submit_body = submit_response.json()
                if submit_body.get("success"):
                    return await _save_account_to_db(submit_body, wallet)
                else:
                    logger.error(f"[WALLET] Account submit returned unsuccessful: {submit_body}")
            else:
                logger.error(f"[WALLET] Account submit failed with status {submit_response.status_code}")
    except Exception as account_error:
        logger.error(f"[WALLET] Failed to sign/submit account: {account_error}")
        logger.error("[WALLET] Error details:", exc_info=True)
    
    return None


async def _save_account_to_db(submit_body: dict, wallet: Any) -> Optional[dict]:
    """Save account to database and return account data."""
    account_data = submit_body.get("data", {})
    account_wallet_id = account_data.get("walletId")
    account_details = account_data.get("account", {})
    account_address = account_data.get("address") or account_details.get("address")
    
    logger.info("[WALLET] ✅ Account created successfully!")
    logger.info("[WALLET] 📦 Account Details:")
    logger.info(f"[WALLET]    - walletId: {account_wallet_id}")
    logger.info(f"[WALLET]    - address: {account_address}")
    logger.info(f"[WALLET]    - curve: {account_details.get('curve')}")
    logger.info(f"[WALLET]    - path: {account_details.get('path')}")
    
    logger.info("[WALLET] 💾 Saving account to database...")
    try:
        await prisma.wallet_accounts.create(
            data={
                "wallet_id": wallet.id,
                "curve": account_details.get("curve", ""),
                "path_format": account_details.get("pathFormat", ""),
                "path": account_details.get("path", ""),
                "address_format": account_details.get("addressFormat", ""),
                "address": account_address
            }
        )
        logger.info(f"[WALLET] ✅ Account saved to database")
        return {
            "address": account_address,
            "curve": account_details.get("curve"),
            "path": account_details.get("path"),
            "pathFormat": account_details.get("pathFormat"),
            "addressFormat": account_details.get("addressFormat")
        }
    except Exception as db_error:
        logger.error(f"[WALLET] Failed to save account to database: {db_error}")
        return None


def _build_wallet_response(
    wallet_id: str,
    addresses: list,
    account_created: Optional[dict],
    account_prepare_data: Optional[dict],
) -> dict:
    """Build response for wallet submission."""
    response_data = {
        "walletId": wallet_id,
        "addresses": addresses
    }
    
    if account_created:
        response_data["account"] = account_created
        logger.info("[WALLET] ✅ Returning wallet + account data")
        logger.info(f"[WALLET] 📦 Response includes: walletId={wallet_id}, account.address={account_created.get('address')}")
        message = "Wallet and account created successfully"
    elif account_prepare_data:
        response_data["accountPrepare"] = account_prepare_data
        logger.info("[WALLET] ✅ Returning wallet creation + account preparation data")
        logger.info(f"[WALLET] 📦 Response includes: walletId={wallet_id}, accountPrepare.payloadId={account_prepare_data.get('payloadId')}")
        message = "Wallet created successfully and account preparation ready"
    else:
        message = "Wallet created successfully"
    
    return {
        "success": True,
        "message": message,
        "data": response_data
    }


@router.post("/submit")
@limiter.limit("30/minute")
async def submit_wallet(
    data: dict,
    request: Request,
    current_user: Entities = Depends(get_current_entity)
):
    """
    Submit signed wallet creation and automatically create account.

    Body:
        - payloadId: Payload ID from prepare step
        - signatureType: "ApiKey"
        - signature: Base64URL-encoded signature from sign step
        - sessionPrivateKey: Session private key (for automatic account creation)
        - sessionPublicKey: Session public key (for automatic account creation)
        - walletName: Wallet name (optional, for saving)
        - chain: Blockchain chain (optional, defaults to SOLANA)

    Returns:
        - walletId: Created wallet ID
        - addresses: Wallet addresses for the chain
        - account: Account details (if auto-created)
    """
    logger.info(f"[WALLET] Submit wallet request - keys: {list(data.keys())}")

    payload_id = data.get("payloadId")
    signature_type = data.get("signatureType", "ApiKey")
    signature = data.get("signature")
    session_private_key = data.get("sessionPrivateKey")
    session_public_key = data.get("sessionPublicKey")

    if not all([payload_id, signature]):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="payloadId and signature are required"
        )

    logger.info(f"[WALLET] Input - payloadId: {payload_id}, signature: {len(signature)} chars")
    logger.info(f"[WALLET] Session keys provided: {bool(session_private_key)}/{bool(session_public_key)}")

    # Call Zynk submit wallet creation endpoint
    url = f"{ZYNK_BASE_URL}/api/v1/wallets/create/submit"
    payload = {
        "payloadId": payload_id,
        "signatureType": signature_type,
        "signature": signature
    }

    logger.info(f"[WALLET] Submit wallet payload: {payload}")

    async with httpx.AsyncClient(timeout=settings.zynk_timeout_s) as client:
        response = await client.post(
            url,
            json=payload,
            headers=_zynk_auth_header()
        )

        logger.info(f"[WALLET] Submit wallet response status: {response.status_code}")

        if response.status_code != 200:
            error_detail = response.json().get("message", f"HTTP {response.status_code}")
            logger.error(f"[WALLET] Zynk API error: {error_detail}")
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail=f"Zynk API error: {error_detail}"
            )

        body = response.json()
        if not body.get("success"):
            error_msg = body.get("message", ERR_ZYNK_API_ERROR)
            logger.error(f"[WALLET] Zynk API returned error: {error_msg}")
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail=error_msg
            )

        logger.info(f"[WALLET] Submit wallet response: {body}")

        wallet_data = body.get("data", {})
        wallet_id = wallet_data.get("walletId")
        addresses = wallet_data.get("addresses", [])

        wallet_name = data.get("walletName", "Solana Wallet")
        chain = data.get("chain", "SOLANA")
        wallet = await _save_wallet_to_db(wallet_id, current_user, wallet_name, chain, addresses)

        account_prepare_data = None
        account_created = None
        
        if session_private_key and session_public_key:
            logger.info("[WALLET] ✅ Wallet created successfully. Now preparing account creation...")
            try:
                account_prepare_data = await _prepare_account_creation(wallet_id, chain)
                if account_prepare_data and wallet:
                    account_created = await _sign_and_submit_account(
                        account_prepare_data,
                        session_private_key,
                        session_public_key,
                        wallet
                    )
            except Exception as prepare_error:
                logger.error(f"[WALLET] Failed to prepare account: {prepare_error}")

        return _build_wallet_response(wallet_id, addresses, account_created, account_prepare_data)


@router.post("/{wallet_id}/accounts/prepare")
@limiter.limit("30/minute")
async def prepare_account(
    wallet_id: str,
    data: dict,
    request: Request,
    current_user: Entities = Depends(get_current_entity)
):
    """
    Prepare wallet account creation challenge.
    
    Path:
        - wallet_id: Zynk wallet ID (e.g., znc_wallet_...)
    
    Body:
        - chain: Blockchain (SOLANA, ETHEREUM, etc.)
    
    Returns:
        - payloadId: Unique identifier for this challenge
        - payloadToSign: JSON string to sign
        - rpId: Relying Party ID
    """
    logger.info(f"[WALLET] Prepare account request - wallet_id: {wallet_id}, keys: {list(data.keys())}")
    
    chain = data.get("chain", "SOLANA")
    
    # Verify wallet belongs to current user
    wallet = await prisma.wallets.find_first(
        where={
            "zynk_wallet_id": wallet_id,
            "entity_id": str(current_user.id),
            "deleted_at": None
        }
    )
    
    if not wallet:
        logger.error(f"[WALLET] Wallet not found or unauthorized - wallet_id: {wallet_id}, user: {current_user.id}")
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=ERR_WALLET_NOT_FOUND
        )
    
    logger.info(f"[WALLET] Preparing account - Chain: {chain}, Wallet ID: {wallet_id}")
    
    # Call Zynk prepare account creation endpoint
    url = f"{ZYNK_BASE_URL}/api/v1/wallets/{wallet_id}/accounts/prepare"
    payload = {
        "chain": chain
    }
    
    logger.info(f"[WALLET] Prepare account URL: {url}")
    logger.info(f"[WALLET] Prepare account payload: {payload}")
    
    async with httpx.AsyncClient(timeout=settings.zynk_timeout_s) as client:
        response = await client.post(
            url,
            json=payload,
            headers=_zynk_auth_header()
        )
        
        logger.info(f"[WALLET] Prepare account response status: {response.status_code}")
        
        if response.status_code != 200:
            try:
                error_detail = response.json().get("message", f"HTTP {response.status_code}")
            except (ValueError, json.JSONDecodeError):
                error_detail = f"HTTP {response.status_code}: {response.text[:200]}"
            logger.error(f"[WALLET] Zynk API error: {error_detail}")
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail=f"Zynk API error: {error_detail}"
            )
        
        body = response.json()
        if not body.get("success"):
            error_msg = body.get("message", ERR_ZYNK_API_ERROR)
            logger.error(f"[WALLET] Zynk API returned error: {error_msg}")
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail=error_msg
            )
        
        logger.info(f"[WALLET] Prepare account response: {body}")
        
        data_response = body.get("data", {})
        payload_id = data_response.get("payloadId")
        payload_to_sign = data_response.get("payloadToSign")
        rp_id = data_response.get("rpId")
        
        if not all([payload_id, payload_to_sign]):
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail="Zynk API did not return complete challenge data"
            )
        
        return {
            "success": True,
            "data": {
                "payloadId": payload_id,
                "payloadToSign": payload_to_sign,
                "rpId": rp_id
            }
        }


@router.post("/accounts/submit")
@limiter.limit("30/minute")
async def submit_account(
    data: dict,
    request: Request,
    current_user: Entities = Depends(get_current_entity)
):
    """
    Submit signed wallet account creation.
    
    Body:
        - payloadId: Payload ID from prepare step
        - signatureType: "ApiKey"
        - signature: Base64URL-encoded signature from sign step
    
    Returns:
        - walletId: Wallet ID
        - account: Account details (curve, path, addressFormat, address)
        - address: Blockchain address
    """
    logger.info("[WALLET] ========================================")
    logger.info("[WALLET] 🔵 ACCOUNT SUBMIT REQUEST RECEIVED")
    logger.info(f"[WALLET] Request keys: {list(data.keys())}")
    logger.info(f"[WALLET] User: {current_user.email} (ID: {current_user.id})")
    logger.info("[WALLET] ========================================")
    
    payload_id = data.get("payloadId")
    signature_type = data.get("signatureType", "ApiKey")
    signature = data.get("signature")
    
    if not all([payload_id, signature]):
        logger.error(f"[WALLET] ❌ Missing required fields - payloadId: {bool(payload_id)}, signature: {bool(signature)}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="payloadId and signature are required"
        )
    
    logger.info(f"[WALLET] Validated input - payloadId: {payload_id}, signatureType: {signature_type}, signature: {len(signature)} chars")
    
    # Call Zynk submit account creation endpoint
    url = f"{ZYNK_BASE_URL}/api/v1/wallets/accounts/submit"
    payload = {
        "payloadId": payload_id,
        "signatureType": signature_type,
        "signature": signature
    }
    
    logger.info(f"[WALLET] Submit account payload: {payload}")
    
    async with httpx.AsyncClient(timeout=settings.zynk_timeout_s) as client:
        response = await client.post(
            url,
            json=payload,
            headers=_zynk_auth_header()
        )
        
        logger.info(f"[WALLET] Submit account response status: {response.status_code}")
        
        if response.status_code != 200:
            try:
                error_detail = response.json().get("message", f"HTTP {response.status_code}")
            except (ValueError, json.JSONDecodeError):
                error_detail = f"HTTP {response.status_code}: {response.text[:200]}"
            logger.error(f"[WALLET] Zynk API error: {error_detail}")
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail=f"Zynk API error: {error_detail}"
            )
        
        body = response.json()
        if not body.get("success"):
            error_msg = body.get("message", ERR_ZYNK_API_ERROR)
            logger.error(f"[WALLET] Zynk API returned error: {error_msg}")
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail=error_msg
            )
        
        logger.info("[WALLET] ✅ Submit account response received from Zynk API")
        logger.info("[WALLET] 📦 Submit Account Response:")
        logger.info(f"[WALLET]    - success: {body.get('success')}")
        logger.info(f"[WALLET]    - Full response: {body}")
        
        account_data = body.get("data", {})
        wallet_id = account_data.get("walletId")
        account = account_data.get("account", {})
        address = account_data.get("address") or account.get("address")
        
        logger.info("[WALLET] 📦 Parsed Account Data:")
        logger.info(f"[WALLET]    - walletId: {wallet_id}")
        logger.info(f"[WALLET]    - address: {address}")
        logger.info(f"[WALLET]    - curve: {account.get('curve')}")
        logger.info(f"[WALLET]    - path: {account.get('path')}")
        logger.info(f"[WALLET]    - addressFormat: {account.get('addressFormat')}")
        
        # Save account to database
        logger.info(f"[WALLET] 💾 Saving account to database - Wallet ID: {wallet_id}, Address: {address}")
        try:
            # Find the wallet in our database
            wallet = await prisma.wallets.find_first(
                where={
                    "zynk_wallet_id": wallet_id,
                    "entity_id": str(current_user.id),
                    "deleted_at": None
                }
            )
            
            if not wallet:
                logger.error(f"[WALLET] Wallet not found in database for saving account - wallet_id: {wallet_id}")
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Wallet not found in database"
                )
            
            # Create wallet account record
            wallet_account = await prisma.wallet_accounts.create(
                data={
                    "wallet_id": wallet.id,
                    "curve": account.get("curve", ""),
                    "path_format": account.get("pathFormat", ""),
                    "path": account.get("path", ""),
                    "address_format": account.get("addressFormat", ""),
                    "address": address
                }
            )
            logger.info(f"[WALLET] Account saved to database successfully - DB ID: {wallet_account.id}")
            
        except Exception as db_error:
            logger.error(f"[WALLET] Failed to save account to database: {db_error}")
            # Don't fail the request if DB save fails - account is already created in Zynk
            # Return success but log the error
        
        return {
            "success": True,
            "message": "Wallet account created successfully",
            "data": {
                "walletId": wallet_id,
                "account": account,
                "address": address
            }
        }

