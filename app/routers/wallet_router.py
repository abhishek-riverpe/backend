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
from app.utils.log_sanitizer import sanitize_for_log, sanitize_dict_for_log

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1/wallets", tags=["Wallets"])

# Rate limiter instance (will be set from app.state.limiter)
limiter = Limiter(key_func=get_remote_address)

# Zynk API base URL
ZYNK_BASE_URL = "https://qaapi.zynklabs.xyz"

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
    logger.info("[WALLET] Initiating OTP for entity: %s, user: %s",
                sanitize_for_log(entity_id), sanitize_for_log(user_email))

    # Call Zynk initiate-otp endpoint (entityId in path, no payload needed)
    url = f"{ZYNK_BASE_URL}/api/v1/wallets/{sanitize_for_log(entity_id)}/initiate-otp"
    logger.info("[WALLET] Zynk API URL: %s", url)
    
    headers = _zynk_auth_header()
    
    async with httpx.AsyncClient(timeout=settings.zynk_timeout_s) as client:
        logger.info("[WALLET] Sending POST request to Zynk API for initiate-otp")
        response = await client.post(url, headers=headers)
        logger.info("[WALLET] Response status code: %d", response.status_code)

        if response.status_code != 200:
            try:
                error_body = response.json()
                error_detail = error_body.get("message", f"HTTP {response.status_code}")
            except:
                error_detail = f"HTTP {response.status_code}: {sanitize_for_log(response.text[:200])}"

            logger.error("[WALLET] Initiate OTP failed: %s", sanitize_for_log(error_detail))
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail=f"Zynk API error: {error_detail}"
            )

        body = response.json()
        logger.info("[WALLET] Initiate OTP response: %s", sanitize_dict_for_log(body))

        if not body.get("success"):
            error_msg = body.get("message", "Zynk API returned error")
            logger.error("[WALLET] Initiate OTP failed: %s", sanitize_for_log(error_msg))
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
        logger.info("[WALLET] OTP ID: %s", sanitize_for_log(otp_id))
        return body


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
    logger.info("[WALLET] Step 1: Received register-auth request from user: %s",
                sanitize_for_log(current_user.email))

    # Get and clean entity ID from authenticated user
    logger.info("[WALLET] Step 2: Getting and cleaning entity ID")
    entity_id = _clean_entity_id(current_user.zynk_entity_id)
    logger.info("[WALLET] Step 2 Complete: Entity ID = %s", sanitize_for_log(entity_id))

    # Call Zynk register-auth endpoint
    url = f"{ZYNK_BASE_URL}/api/v1/wallets/{sanitize_for_log(entity_id)}/register-auth"
    payload = {
        "authType": "Email_Auth",
        "authPayload": {
            "email": current_user.email
        }
    }

    logger.info("[WALLET] Step 3: Preparing Zynk API call")
    logger.info("[WALLET] Register auth payload: %s", sanitize_dict_for_log(payload))
    logger.info("[WALLET] Register auth URL: %s", url)

    async with httpx.AsyncClient(timeout=settings.zynk_timeout_s) as client:
        logger.info("[WALLET] Step 4: Sending request to Zynk API")
        response = await client.post(url, json=payload, headers=_zynk_auth_header())
        logger.info("[WALLET] Step 4 Complete: Received response with status %d", response.status_code)

        # Handle both 200 (success) and 400 (already registered) responses
        if response.status_code == 200:
            body = response.json()
            logger.info("[WALLET] Register auth response: %s", sanitize_dict_for_log(body))

            if body.get("success"):
                logger.info("[WALLET] Step 5 Complete: New user registered successfully")
                logger.info("[WALLET] ========== REGISTER AUTH SUCCESS (New Registration) ==========")
                logger.info("[WALLET] Automatically calling initiate-otp...")

                # Automatically call initiate-otp
                try:
                    otp_response = await _initiate_otp_internal(entity_id, current_user.email)
                    logger.info("[WALLET] Initiate OTP completed successfully")
                    return otp_response
                except HTTPException as e:
                    logger.error("[WALLET] Failed to initiate OTP after register-auth: %s",
                               sanitize_for_log(e.detail))
                    raise
                except Exception as e:
                    logger.error("[WALLET] Unexpected error during initiate-otp: %s",
                               sanitize_for_log(str(e)))
                    raise HTTPException(
                        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                        detail=f"Failed to initiate OTP: {str(e)}"
                    )
            else:
                # Unexpected 200 response with success: false
                error_msg = body.get("error", {}).get("message", "Unknown error")
                logger.error("[WALLET] Register auth unexpected failure: %s",
                           sanitize_for_log(error_msg))
                raise HTTPException(
                    status_code=status.HTTP_502_BAD_GATEWAY,
                    detail=f"Zynk API error: {error_msg}"
                )

        elif response.status_code == 400:
            # Check if it's the "already registered" case
            try:
                body = response.json()
                error_details = body.get("error", {}).get("details", "")
                if "Entity already has a registered Turnkey organization" in error_details:
                    logger.info("[WALLET] Step 5 Complete: User already registered with Turnkey")
                    logger.info("[WALLET] ========== REGISTER AUTH SUCCESS (Already Registered) ==========")
                    logger.info("[WALLET] Automatically calling initiate-otp...")

                    # Automatically call initiate-otp
                    try:
                        otp_response = await _initiate_otp_internal(entity_id, current_user.email)
                        logger.info("[WALLET] Initiate OTP completed successfully")
                        return otp_response
                    except HTTPException as e:
                        logger.error("[WALLET] Failed to initiate OTP after register-auth: %s",
                                   sanitize_for_log(e.detail))
                        raise
                    except Exception as e:
                        logger.error("[WALLET] Unexpected error during initiate-otp: %s",
                                   sanitize_for_log(str(e)))
                        raise HTTPException(
                            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                            detail=f"Failed to initiate OTP: {str(e)}"
                        )
                else:
                    # Different 400 error
                    error_msg = body.get("error", {}).get("message", "Bad Request")
                    logger.error("[WALLET] Register auth 400 error: %s", sanitize_for_log(error_msg))
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail=error_msg
                    )
            except Exception as e:
                logger.error("[WALLET] Failed to parse 400 response: %s", sanitize_for_log(str(e)))
                raise HTTPException(
                    status_code=status.HTTP_502_BAD_GATEWAY,
                    detail="Invalid response from Zynk API"
                )

        else:
            # Other HTTP status codes
            try:
                error_detail = response.json().get("message", f"HTTP {response.status_code}")
            except:
                error_detail = f"HTTP {response.status_code}: {sanitize_for_log(response.text[:200])}"

            logger.error("[WALLET] Register auth HTTP error: %s", sanitize_for_log(error_detail))
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
        logger.info("[WALLET] Received initiate-otp request from user: %s",
                   sanitize_for_log(current_user.email))

        # Get and clean entity ID from authenticated user
        entity_id = _clean_entity_id(current_user.zynk_entity_id)
        logger.info("[WALLET] Entity ID: %s", sanitize_for_log(entity_id))

        # Call the internal helper function
        result = await _initiate_otp_internal(entity_id, current_user.email)

        logger.info("[WALLET] ========== INITIATE OTP (ENDPOINT) SUCCESS ==========")
        return result

    except HTTPException as he:
        logger.error("[WALLET] ========== INITIATE OTP (ENDPOINT) FAILED (HTTPException) ==========")
        logger.error("[WALLET] HTTPException status: %d", he.status_code)
        logger.error("[WALLET] HTTPException detail: %s", sanitize_for_log(he.detail))
        raise
    except Exception as e:
        logger.error("[WALLET] ========== INITIATE OTP (ENDPOINT) FAILED (Unexpected Error) ==========")
        logger.error("[WALLET] Error type: %s", type(e).__name__)
        logger.error("[WALLET] Error message: %s", sanitize_for_log(str(e)))
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
    logger.info("[WALLET] Request payload keys: %s", list(data.keys()))
    logger.info("[WALLET] Full request payload: %s", sanitize_dict_for_log(data))

    otp_id = data.get("otpId")
    otp_code = data.get("otpCode")
    public_key = data.get("publicKey")

    if not otp_id or not otp_code:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="otpId and otpCode are required"
        )

    logger.info("[WALLET] Step 1: Received otpId: %s, otpCode: %s",
                sanitize_for_log(otp_id), sanitize_for_log(otp_code))
    if public_key:
        logger.info("[WALLET] Step 1a: Using provided publicKey: %s",
                   sanitize_for_log(public_key))

    # Get and clean entity_id from current user
    logger.info("[WALLET] Step 2: Getting entity ID")
    entity_id = _clean_entity_id(current_user.zynk_entity_id)
    logger.info("[WALLET] Step 2 Complete: Entity ID = %s", sanitize_for_log(entity_id))

    # Generate keypair if publicKey not provided
    private_hex = None
    if not public_key:
        logger.info("[WALLET] Step 3: Generating P-256 keypair (publicKey not provided)")
        private_hex, public_key = generate_keypair_crypto()
        logger.info("[WALLET] Step 3 Complete: Generated keypair")
        logger.info("[WALLET] Private key length: %d chars", len(private_hex))
        logger.info("[WALLET] Public key length: %d chars", len(public_key))
    else:
        logger.info("[WALLET] Step 3: Using provided publicKey (no keypair generation needed)")

    logger.info("[WALLET] Public key to use: %s", sanitize_for_log(public_key))

    # Call Zynk wallets start-session endpoint
    logger.info("[WALLET] Step 4: Preparing Zynk API call")
    url = f"{ZYNK_BASE_URL}/api/v1/wallets/{sanitize_for_log(entity_id)}/start-session"
    payload = {
        "publicKey": public_key,
        "otpId": otp_id,
        "otpCode": otp_code
    }

    logger.info("[WALLET] Step 4 Complete: Zynk API URL = %s", url)
    logger.info("[WALLET] Step 4 Complete: Request payload to Zynk = %s",
                sanitize_dict_for_log(payload))

    async with httpx.AsyncClient(timeout=settings.zynk_timeout_s) as client:
        logger.info("[WALLET] Step 5: Sending POST request to Zynk API")
        logger.info("[WALLET] Request URL: %s", url)
        sanitized_headers = sanitize_dict_for_log(_zynk_auth_header())
        logger.info("[WALLET] Request headers: %s", sanitized_headers)
        logger.info("[WALLET] Request payload: %s", sanitize_dict_for_log(payload))

        response = await client.post(
            url,
            json=payload,
            headers=_zynk_auth_header()
        )

        logger.info("[WALLET] Step 5 Complete: Response status = %d", response.status_code)
        logger.info("[WALLET] Response headers: %s",
                   sanitize_dict_for_log(dict(response.headers)))

        if response.status_code != 200:
            try:
                error_body = response.json()
                error_detail = error_body.get("message", f"HTTP {response.status_code}")
                logger.error("[WALLET] Zynk API error response: %s",
                           sanitize_dict_for_log(error_body))
            except:
                error_detail = f"HTTP {response.status_code}: {sanitize_for_log(response.text[:200])}"
                logger.error("[WALLET] Zynk API error (non-JSON): %s",
                           sanitize_for_log(error_detail))

            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail=f"Zynk API error: {error_detail}"
            )

        logger.info("[WALLET] Step 6: Parsing response")
        body = response.json()
        logger.info("[WALLET] Step 6 Complete: Full response body = %s",
                   sanitize_dict_for_log(body))
        logger.info("[WALLET] Response JSON (formatted):")
        logger.info("[WALLET] %s", sanitize_for_log(json.dumps(body, indent=2)))

        if not body.get("success"):
            error_msg = body.get("message", "Zynk API returned error")
            logger.error("[WALLET] Zynk API returned error: %s", sanitize_for_log(error_msg))
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail=error_msg
            )

        logger.info("[WALLET] Step 7: Extracting credential bundle")
        credential_bundle = body.get("data", {}).get("credentialBundle")
        if not credential_bundle:
            logger.error("[WALLET] Missing credentialBundle in response")
            logger.error("[WALLET] Response data keys: %s",
                        list(body.get('data', {}).keys()))
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail="Zynk API did not return credential bundle"
            )

        logger.info("[WALLET] Step 7 Complete: Credential bundle length = %d chars",
                   len(credential_bundle))
        logger.info("[WALLET] Step 7 Complete: Credential bundle (first 50 chars): %s",
                   sanitize_for_log(credential_bundle[:50]))
        logger.info("[WALLET] ========== START SESSION SUCCESS ==========")
        logger.info("[WALLET] Full Zynk API Response:")
        logger.info("[WALLET] %s", sanitize_for_log(json.dumps(body, indent=2)))
        logger.info("[WALLET] Credential Bundle: %s", sanitize_for_log(credential_bundle))

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
            logger.info("[WALLET] Private Key (for decryption): %s",
                       sanitize_for_log(private_hex))

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
    logger.info("[WALLET] Decrypt bundle request - keys: %s", list(data.keys()))

    credential_bundle = data.get("credentialBundle")
    ephemeral_private_key = data.get("ephemeralPrivateKey")

    if not credential_bundle or not ephemeral_private_key:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="credentialBundle and ephemeralPrivateKey are required"
        )

    logger.info("[WALLET] Input - bundle: %d chars, private key: %d chars",
                len(credential_bundle), len(ephemeral_private_key))

    # Decrypt using HPKE
    logger.info("[WALLET] Starting HPKE decryption")
    result = decrypt_credential_bundle(credential_bundle, ephemeral_private_key)

    session_private_key = result['tempPrivateKey']
    session_public_key = result['tempPublicKey']

    logger.info("[WALLET] Decryption successful - private key: %d chars, public key: %d chars",
                len(session_private_key), len(session_public_key))

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
    logger.info("[WALLET] Prepare wallet request - keys: %s", list(data.keys()))

    wallet_name = data.get("walletName")
    chain = data.get("chain", "SOLANA")

    if not wallet_name:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="walletName is required"
        )

    # Get and clean entity_id from current user
    entity_id = _clean_entity_id(current_user.zynk_entity_id)

    logger.info("[WALLET] Preparing wallet - Name: %s, Chain: %s, Entity ID: %s",
                sanitize_for_log(wallet_name), sanitize_for_log(chain),
                sanitize_for_log(entity_id))

    # Call Zynk prepare wallet creation endpoint
    url = f"{ZYNK_BASE_URL}/api/v1/wallets/{sanitize_for_log(entity_id)}/create/prepare"
    payload = {
        "walletName": wallet_name,
        "chain": chain
    }

    logger.info("[WALLET] Prepare wallet payload: %s", sanitize_dict_for_log(payload))

    async with httpx.AsyncClient(timeout=settings.zynk_timeout_s) as client:
        response = await client.post(
            url,
            json=payload,
            headers=_zynk_auth_header()
        )

        logger.info("[WALLET] Prepare wallet response status: %d", response.status_code)

        if response.status_code != 200:
            error_detail = response.json().get("message", f"HTTP {response.status_code}")
            logger.error("[WALLET] Zynk API error: %s", sanitize_for_log(error_detail))
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail=f"Zynk API error: {error_detail}"
            )

        body = response.json()
        if not body.get("success"):
            error_msg = body.get("message", "Zynk API returned error")
            logger.error("[WALLET] Zynk API returned error: %s", sanitize_for_log(error_msg))
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail=error_msg
            )

        logger.info("[WALLET] Prepare wallet response: %s", sanitize_dict_for_log(body))

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
    logger.info("[WALLET] Fetching wallet for user: %s (ID: %s)",
                sanitize_for_log(current_user.email), sanitize_for_log(str(current_user.id)))

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
            logger.info("[WALLET] No wallet found for user: %s",
                       sanitize_for_log(str(current_user.id)))
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

        logger.info("[WALLET] Found wallet: %s with %d addresses",
                   sanitize_for_log(wallet.zynk_wallet_id), len(addresses))
        
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
        logger.error("[WALLET] Error fetching user wallet: %s", sanitize_for_log(str(e)))
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
    logger.info("[WALLET] Fetching wallet details from Zynk - wallet_id: %s, user: %s",
                sanitize_for_log(wallet_id), sanitize_for_log(current_user.email))

    # Verify wallet belongs to user
    wallet = await prisma.wallets.find_first(
        where={
            "zynk_wallet_id": wallet_id,
            "entity_id": str(current_user.id),
            "deleted_at": None
        }
    )

    if not wallet:
        logger.error("[WALLET] Wallet not found or unauthorized - wallet_id: %s, user: %s",
                    sanitize_for_log(wallet_id), sanitize_for_log(str(current_user.id)))
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Wallet not found or unauthorized"
        )

    # Call Zynk API
    url = f"{ZYNK_BASE_URL}/api/v1/wallets/{sanitize_for_log(wallet_id)}"
    logger.info("[WALLET] Calling Zynk API: %s", url)

    async with httpx.AsyncClient(timeout=settings.zynk_timeout_s) as client:
        response = await client.get(url, headers=_zynk_auth_header())

        if response.status_code != 200:
            logger.error("[WALLET] Zynk API error: %d", response.status_code)
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail=f"Failed to fetch wallet details from Zynk API"
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
    logger.info("[WALLET] Fetching wallet balances from Zynk - wallet_id: %s, user: %s",
                sanitize_for_log(wallet_id), sanitize_for_log(current_user.email))

    # Verify wallet belongs to user
    wallet = await prisma.wallets.find_first(
        where={
            "zynk_wallet_id": wallet_id,
            "entity_id": str(current_user.id),
            "deleted_at": None
        }
    )

    if not wallet:
        logger.error("[WALLET] Wallet not found or unauthorized - wallet_id: %s, user: %s",
                    sanitize_for_log(wallet_id), sanitize_for_log(str(current_user.id)))
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Wallet not found or unauthorized"
        )

    # Call Zynk API
    url = f"{ZYNK_BASE_URL}/api/v1/wallets/{sanitize_for_log(wallet_id)}/balances"
    logger.info("[WALLET] Calling Zynk API: %s", url)

    async with httpx.AsyncClient(timeout=settings.zynk_timeout_s) as client:
        response = await client.get(url, headers=_zynk_auth_header())

        if response.status_code != 200:
            logger.error("[WALLET] Zynk API error: %d", response.status_code)
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail=f"Failed to fetch wallet balances from Zynk API"
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
    logger.info("[WALLET] Fetching wallet transactions from Zynk - wallet_id: %s, address: %s, user: %s",
                sanitize_for_log(wallet_id), sanitize_for_log(address),
                sanitize_for_log(current_user.email))

    # Verify wallet belongs to user
    wallet = await prisma.wallets.find_first(
        where={
            "zynk_wallet_id": wallet_id,
            "entity_id": str(current_user.id),
            "deleted_at": None
        }
    )

    if not wallet:
        logger.error("[WALLET] Wallet not found or unauthorized - wallet_id: %s, user: %s",
                    sanitize_for_log(wallet_id), sanitize_for_log(str(current_user.id)))
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Wallet not found or unauthorized"
        )

    # Call Zynk API
    url = f"{ZYNK_BASE_URL}/api/v1/wallets/{sanitize_for_log(wallet_id)}/{sanitize_for_log(address)}/transactions"
    params = {"limit": limit, "offset": offset}
    logger.info("[WALLET] Calling Zynk API: %s with params: %s", url, params)

    async with httpx.AsyncClient(timeout=settings.zynk_timeout_s) as client:
        response = await client.get(url, headers=_zynk_auth_header(), params=params)

        if response.status_code != 200:
            logger.error("[WALLET] Zynk API error: %d", response.status_code)
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail=f"Failed to fetch wallet transactions from Zynk API"
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
    logger.info("[WALLET] Sign payload request - keys: %s", sanitize_dict_for_log(data))

    payload_to_sign = data.get("payload")
    session_private_key = data.get("sessionPrivateKey")
    session_public_key = data.get("sessionPublicKey")

    if not all([payload_to_sign, session_private_key, session_public_key]):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="payload, sessionPrivateKey, and sessionPublicKey are required"
        )

    logger.info("[WALLET] Input - payload: %d chars, private key: %d chars, public key: %d chars",
                len(payload_to_sign), len(session_private_key), len(session_public_key))

    # Sign the payload
    logger.info("[WALLET] Signing payload with session key")
    signature = sign_payload_with_api_key(payload_to_sign, session_private_key, session_public_key)

    logger.info("[WALLET] Payload signed successfully - signature: %d chars", len(signature))
    logger.info("[WALLET] Signature (first 80 chars): %s",
                sanitize_for_log(signature[:80]))
    logger.info("[WALLET] Signature (last 80 chars): %s",
                sanitize_for_log(signature[-80:]))

    return {
        "success": True,
        "data": {
            "signature": signature
        }
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
    logger.info("[WALLET] Submit wallet request - keys: %s", list(data.keys()))

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

    logger.info("[WALLET] Input - payloadId: %s, signature: %d chars",
                sanitize_for_log(payload_id), len(signature))
    logger.info("[WALLET] Session keys provided: %s/%s",
                bool(session_private_key), bool(session_public_key))

    # Call Zynk submit wallet creation endpoint
    url = f"{ZYNK_BASE_URL}/api/v1/wallets/create/submit"
    payload = {
        "payloadId": payload_id,
        "signatureType": signature_type,
        "signature": signature
    }

    logger.info("[WALLET] Submit wallet payload: %s", sanitize_dict_for_log(payload))

    async with httpx.AsyncClient(timeout=settings.zynk_timeout_s) as client:
        response = await client.post(
            url,
            json=payload,
            headers=_zynk_auth_header()
        )

        logger.info("[WALLET] Submit wallet response status: %d", response.status_code)

        if response.status_code != 200:
            error_detail = response.json().get("message", f"HTTP {response.status_code}")
            logger.error("[WALLET] Zynk API error: %s", sanitize_for_log(error_detail))
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail=f"Zynk API error: {error_detail}"
            )

        body = response.json()
        if not body.get("success"):
            error_msg = body.get("message", "Zynk API returned error")
            logger.error("[WALLET] Zynk API returned error: %s", sanitize_for_log(error_msg))
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail=error_msg
            )

        logger.info("[WALLET] Submit wallet response: %s", sanitize_dict_for_log(body))

        wallet_data = body.get("data", {})
        wallet_id = wallet_data.get("walletId")
        addresses = wallet_data.get("addresses", [])

        # Save wallet to database
        logger.info("[WALLET] Saving wallet to database - ID: %s, Entity: %s",
                   sanitize_for_log(wallet_id), sanitize_for_log(str(current_user.id)))
        try:
            # Get wallet name from original request (or use default)
            wallet_name = data.get("walletName", "Solana Wallet")
            chain = data.get("chain", "SOLANA")
            
            # Create wallet record
            wallet = await prisma.wallets.create(
                data={
                    "entity_id": str(current_user.id),
                    "zynk_wallet_id": wallet_id,
                    "wallet_name": wallet_name,
                    "chain": chain,
                    "status": "ACTIVE"
                }
            )
            logger.info("[WALLET] Wallet saved to database successfully - DB ID: %s",
                       sanitize_for_log(str(wallet.id)))

            # Save the first address if available
            if addresses and len(addresses) > 0:
                # For initial wallet creation, we might not have full account details
                # These will be saved when accounts are created via /accounts/submit
                logger.info("[WALLET] Initial address from wallet creation: %s",
                           sanitize_for_log(addresses[0]))
        except Exception as db_error:
            logger.error("[WALLET] Failed to save wallet to database: %s",
                        sanitize_for_log(str(db_error)))
            # Don't fail the request if DB save fails - wallet is already created in Zynk
            # Return success but log the error

        # Automatically prepare and create account if session keys provided
        logger.info("[WALLET] Wallet created successfully. Now preparing account creation...")
        account_prepare_data = None
        account_created = None

        try:
            # Call Zynk prepare account creation endpoint
            prepare_url = f"{ZYNK_BASE_URL}/api/v1/wallets/{sanitize_for_log(wallet_id)}/accounts/prepare"
            prepare_payload = {"chain": chain}

            logger.info("[WALLET] Calling account prepare: %s", prepare_url)
            
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
                        logger.info("[WALLET] Account preparation successful - payloadId: %s",
                                   sanitize_for_log(account_prepare_data.get('payloadId')))
                        logger.info("[WALLET] Account Prepare Response:")
                        logger.info("[WALLET]    - payloadId: %s",
                                   sanitize_for_log(account_prepare_data.get('payloadId')))
                        logger.info("[WALLET]    - payloadToSign (first 100 chars): %s",
                                   sanitize_for_log(account_prepare_data.get('payloadToSign', '')[:100]))

                        # If session keys provided, automatically sign and submit account
                        if session_private_key and session_public_key and account_prepare_data:
                            logger.info("[WALLET] Session keys provided - automatically signing and submitting account...")

                            try:
                                # Sign the account payload
                                account_payload_to_sign = account_prepare_data.get('payloadToSign')
                                account_payload_id = account_prepare_data.get('payloadId')

                                logger.info("[WALLET] Signing account payload...")
                                account_signature = sign_payload_with_api_key(
                                    account_payload_to_sign,
                                    session_private_key,
                                    session_public_key
                                )
                                logger.info("[WALLET] Account payload signed - signature length: %d",
                                           len(account_signature))

                                # Submit the account
                                logger.info("[WALLET] Submitting account to Zynk...")
                                submit_url = f"{ZYNK_BASE_URL}/api/v1/wallets/accounts/submit"
                                submit_payload = {
                                    "payloadId": account_payload_id,
                                    "signatureType": "ApiKey",
                                    "signature": account_signature
                                }
                                
                                submit_response = await client.post(
                                    submit_url,
                                    json=submit_payload,
                                    headers=_zynk_auth_header()
                                )
                                
                                if submit_response.status_code == 200:
                                    submit_body = submit_response.json()
                                    if submit_body.get("success"):
                                        account_data = submit_body.get("data", {})
                                        account_wallet_id = account_data.get("walletId")
                                        account_details = account_data.get("account", {})
                                        account_address = account_data.get("address") or account_details.get("address")

                                        logger.info("[WALLET] Account created successfully!")
                                        logger.info("[WALLET] Account Details:")
                                        logger.info("[WALLET]    - walletId: %s",
                                                   sanitize_for_log(account_wallet_id))
                                        logger.info("[WALLET]    - address: %s",
                                                   sanitize_for_log(account_address))
                                        logger.info("[WALLET]    - curve: %s",
                                                   sanitize_for_log(account_details.get('curve')))
                                        logger.info("[WALLET]    - path: %s",
                                                   sanitize_for_log(account_details.get('path')))

                                        # Save account to database
                                        logger.info("[WALLET] Saving account to database...")
                                        try:
                                            wallet_account = await prisma.wallet_accounts.create(
                                                data={
                                                    "wallet_id": wallet.id,
                                                    "curve": account_details.get("curve", ""),
                                                    "path_format": account_details.get("pathFormat", ""),
                                                    "path": account_details.get("path", ""),
                                                    "address_format": account_details.get("addressFormat", ""),
                                                    "address": account_address
                                                }
                                            )
                                            logger.info("[WALLET] Account saved to database - DB ID: %s",
                                                       sanitize_for_log(str(wallet_account.id)))
                                            account_created = {
                                                "address": account_address,
                                                "curve": account_details.get("curve"),
                                                "path": account_details.get("path"),
                                                "pathFormat": account_details.get("pathFormat"),
                                                "addressFormat": account_details.get("addressFormat")
                                            }
                                        except Exception as db_error:
                                            logger.error("[WALLET] Failed to save account to database: %s",
                                                        sanitize_for_log(str(db_error)))
                                    else:
                                        logger.error("[WALLET] Account submit returned unsuccessful: %s",
                                                    sanitize_dict_for_log(submit_body))
                                else:
                                    logger.error("[WALLET] Account submit failed with status %d",
                                               submit_response.status_code)
                            except Exception as account_error:
                                logger.error("[WALLET] Failed to sign/submit account: %s",
                                           sanitize_for_log(str(account_error)))
                                logger.error("[WALLET] Error details:", exc_info=True)
                    else:
                        logger.warning("[WALLET] Account preparation returned unsuccessful: %s",
                                      sanitize_dict_for_log(prepare_body))
                else:
                    logger.warning("[WALLET] Account preparation failed with status %d",
                                  prepare_response.status_code)
        except Exception as prepare_error:
            logger.error("[WALLET] Failed to prepare account: %s",
                        sanitize_for_log(str(prepare_error)))
            # Don't fail the wallet creation if account prepare fails
            # User can manually call the prepare endpoint later

        # Build response
        response_data = {
            "walletId": wallet_id,
            "addresses": addresses
        }

        # Include account data if created
        if account_created:
            response_data["account"] = account_created
            logger.info("[WALLET] Returning wallet + account data")
            logger.info("[WALLET] Response includes: walletId=%s, account.address=%s",
                       sanitize_for_log(wallet_id),
                       sanitize_for_log(account_created.get('address')))
            message = "Wallet and account created successfully"
        # Otherwise include account preparation data if available
        elif account_prepare_data:
            response_data["accountPrepare"] = account_prepare_data
            logger.info("[WALLET] Returning wallet creation + account preparation data")
            logger.info("[WALLET] Response includes: walletId=%s, accountPrepare.payloadId=%s",
                       sanitize_for_log(wallet_id),
                       sanitize_for_log(account_prepare_data.get('payloadId')))
            message = "Wallet created successfully and account preparation ready"
        else:
            message = "Wallet created successfully"
        
        return {
            "success": True,
            "message": message,
            "data": response_data
        }


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
    logger.info("[WALLET] Prepare account request - wallet_id: %s, keys: %s",
                sanitize_for_log(wallet_id), list(data.keys()))

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
        logger.error("[WALLET] Wallet not found or unauthorized - wallet_id: %s, user: %s",
                    sanitize_for_log(wallet_id), sanitize_for_log(str(current_user.id)))
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Wallet not found or unauthorized"
        )

    logger.info("[WALLET] Preparing account - Chain: %s, Wallet ID: %s",
                sanitize_for_log(chain), sanitize_for_log(wallet_id))

    # Call Zynk prepare account creation endpoint
    url = f"{ZYNK_BASE_URL}/api/v1/wallets/{sanitize_for_log(wallet_id)}/accounts/prepare"
    payload = {
        "chain": chain
    }

    logger.info("[WALLET] Prepare account URL: %s", url)
    logger.info("[WALLET] Prepare account payload: %s", sanitize_dict_for_log(payload))
    
    async with httpx.AsyncClient(timeout=settings.zynk_timeout_s) as client:
        response = await client.post(
            url,
            json=payload,
            headers=_zynk_auth_header()
        )

        logger.info("[WALLET] Prepare account response status: %d", response.status_code)

        if response.status_code != 200:
            try:
                error_detail = response.json().get("message", f"HTTP {response.status_code}")
            except:
                error_detail = f"HTTP {response.status_code}: {sanitize_for_log(response.text[:200])}"
            logger.error("[WALLET] Zynk API error: %s", sanitize_for_log(error_detail))
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail=f"Zynk API error: {error_detail}"
            )

        body = response.json()
        if not body.get("success"):
            error_msg = body.get("message", "Zynk API returned error")
            logger.error("[WALLET] Zynk API returned error: %s", sanitize_for_log(error_msg))
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail=error_msg
            )

        logger.info("[WALLET] Prepare account response: %s", sanitize_dict_for_log(body))
        
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
    logger.info("[WALLET] ACCOUNT SUBMIT REQUEST RECEIVED")
    logger.info("[WALLET] Request keys: %s", list(data.keys()))
    logger.info("[WALLET] User: %s (ID: %s)",
                sanitize_for_log(current_user.email), sanitize_for_log(str(current_user.id)))
    logger.info("[WALLET] ========================================")

    payload_id = data.get("payloadId")
    signature_type = data.get("signatureType", "ApiKey")
    signature = data.get("signature")

    if not all([payload_id, signature]):
        logger.error("[WALLET] Missing required fields - payloadId: %s, signature: %s",
                    bool(payload_id), bool(signature))
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="payloadId and signature are required"
        )

    logger.info("[WALLET] Validated input - payloadId: %s, signatureType: %s, signature: %d chars",
                sanitize_for_log(payload_id), signature_type, len(signature))
    
    # Call Zynk submit account creation endpoint
    url = f"{ZYNK_BASE_URL}/api/v1/wallets/accounts/submit"
    payload = {
        "payloadId": payload_id,
        "signatureType": signature_type,
        "signature": signature
    }

    logger.info("[WALLET] Submit account payload: %s", sanitize_dict_for_log(payload))

    async with httpx.AsyncClient(timeout=settings.zynk_timeout_s) as client:
        response = await client.post(
            url,
            json=payload,
            headers=_zynk_auth_header()
        )

        logger.info("[WALLET] Submit account response status: %d", response.status_code)

        if response.status_code != 200:
            try:
                error_detail = response.json().get("message", f"HTTP {response.status_code}")
            except:
                error_detail = f"HTTP {response.status_code}: {sanitize_for_log(response.text[:200])}"
            logger.error("[WALLET] Zynk API error: %s", sanitize_for_log(error_detail))
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail=f"Zynk API error: {error_detail}"
            )

        body = response.json()
        if not body.get("success"):
            error_msg = body.get("message", "Zynk API returned error")
            logger.error("[WALLET] Zynk API returned error: %s", sanitize_for_log(error_msg))
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail=error_msg
            )

        logger.info("[WALLET] Submit account response received from Zynk API")
        logger.info("[WALLET] Submit Account Response:")
        logger.info("[WALLET]    - success: %s", body.get('success'))
        logger.info("[WALLET]    - Full response: %s", sanitize_dict_for_log(body))

        account_data = body.get("data", {})
        wallet_id = account_data.get("walletId")
        account = account_data.get("account", {})
        address = account_data.get("address") or account.get("address")

        logger.info("[WALLET] Parsed Account Data:")
        logger.info("[WALLET]    - walletId: %s", sanitize_for_log(wallet_id))
        logger.info("[WALLET]    - address: %s", sanitize_for_log(address))
        logger.info("[WALLET]    - curve: %s", sanitize_for_log(account.get('curve')))
        logger.info("[WALLET]    - path: %s", sanitize_for_log(account.get('path')))
        logger.info("[WALLET]    - addressFormat: %s", sanitize_for_log(account.get('addressFormat')))

        # Save account to database
        logger.info("[WALLET] Saving account to database - Wallet ID: %s, Address: %s",
                   sanitize_for_log(wallet_id), sanitize_for_log(address))
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
                logger.error("[WALLET] Wallet not found in database for saving account - wallet_id: %s",
                           sanitize_for_log(wallet_id))
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
            logger.info("[WALLET] Account saved to database successfully - DB ID: %s",
                       sanitize_for_log(str(wallet_account.id)))

        except Exception as db_error:
            logger.error("[WALLET] Failed to save account to database: %s",
                        sanitize_for_log(str(db_error)))
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

