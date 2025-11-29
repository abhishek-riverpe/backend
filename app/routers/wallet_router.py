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
            except:
                error_detail = f"HTTP {response.status_code}: {response.text[:200]}"
            
            logger.error(f"[WALLET] Initiate OTP failed: {error_detail}")
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail=f"Zynk API error: {error_detail}"
            )
        
        body = response.json()
        logger.info(f"[WALLET] Initiate OTP response: {body}")
        
        if not body.get("success"):
            error_msg = body.get("message", "Zynk API returned error")
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
        
        logger.info(f"[WALLET] ========== INITIATE OTP (INTERNAL) SUCCESS ==========")
        logger.info(f"[WALLET] OTP ID: {otp_id}")
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

    logger.info(f"[WALLET] Step 3: Preparing Zynk API call")
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
                logger.info("[WALLET] Step 5 Complete: New user registered successfully")
                logger.info("[WALLET] ========== REGISTER AUTH SUCCESS (New Registration) ==========")
                logger.info("[WALLET] ✅ Automatically calling initiate-otp...")
                
                # Automatically call initiate-otp
                try:
                    otp_response = await _initiate_otp_internal(entity_id, current_user.email)
                    logger.info("[WALLET] ✅ Initiate OTP completed successfully")
                    return otp_response
                except HTTPException as e:
                    logger.error(f"[WALLET] Failed to initiate OTP after register-auth: {e.detail}")
                    raise
                except Exception as e:
                    logger.error(f"[WALLET] Unexpected error during initiate-otp: {str(e)}")
                    raise HTTPException(
                        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                        detail=f"Failed to initiate OTP: {str(e)}"
                    )
            else:
                # Unexpected 200 response with success: false
                error_msg = body.get("error", {}).get("message", "Unknown error")
                logger.error(f"[WALLET] Register auth unexpected failure: {error_msg}")
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
                    logger.info("[WALLET] ✅ Automatically calling initiate-otp...")
                    
                    # Automatically call initiate-otp
                    try:
                        otp_response = await _initiate_otp_internal(entity_id, current_user.email)
                        logger.info("[WALLET] ✅ Initiate OTP completed successfully")
                        return otp_response
                    except HTTPException as e:
                        logger.error(f"[WALLET] Failed to initiate OTP after register-auth: {e.detail}")
                        raise
                    except Exception as e:
                        logger.error(f"[WALLET] Unexpected error during initiate-otp: {str(e)}")
                        raise HTTPException(
                            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                            detail=f"Failed to initiate OTP: {str(e)}"
                        )
                else:
                    # Different 400 error
                    error_msg = body.get("error", {}).get("message", "Bad Request")
                    logger.error(f"[WALLET] Register auth 400 error: {error_msg}")
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail=error_msg
                    )
            except Exception as e:
                logger.error(f"[WALLET] Failed to parse 400 response: {e}")
                raise HTTPException(
                    status_code=status.HTTP_502_BAD_GATEWAY,
                    detail="Invalid response from Zynk API"
                )

        else:
            # Other HTTP status codes
            try:
                error_detail = response.json().get("message", f"HTTP {response.status_code}")
            except:
                error_detail = f"HTTP {response.status_code}: {response.text[:200]}"

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
        logger.error(f"[WALLET] ========== INITIATE OTP (ENDPOINT) FAILED (Unexpected Error) ==========")
        logger.error(f"[WALLET] Error type: {type(e).__name__}")
        logger.error(f"[WALLET] Error message: {str(e)}")
        logger.error(f"[WALLET] Full traceback:", exc_info=True)
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
        logger.info(f"[WALLET] Step 3 Complete: Generated keypair")
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
            except:
                error_detail = f"HTTP {response.status_code}: {response.text[:200]}"
                logger.error(f"[WALLET] Zynk API error (non-JSON): {error_detail}")
            
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail=f"Zynk API error: {error_detail}"
            )

        logger.info("[WALLET] Step 6: Parsing response")
        body = response.json()
        logger.info(f"[WALLET] Step 6 Complete: Full response body = {body}")
        logger.info(f"[WALLET] Response JSON (formatted):")
        logger.info(f"[WALLET] {json.dumps(body, indent=2)}")

        if not body.get("success"):
            error_msg = body.get("message", "Zynk API returned error")
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
        logger.info(f"[WALLET] ✅ Full Zynk API Response:")
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
            error_msg = body.get("message", "Zynk API returned error")
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
    logger.info(f"[WALLET] Sign payload request - keys: {list(data.keys())}")

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
    Submit signed wallet creation.

    Body:
        - payloadId: Payload ID from prepare step
        - signatureType: "ApiKey"
        - signature: Base64URL-encoded signature from sign step

    Returns:
        - walletId: Created wallet ID
        - addresses: Wallet addresses for the chain
    """
    logger.info(f"[WALLET] Submit wallet request - keys: {list(data.keys())}")

    payload_id = data.get("payloadId")
    signature_type = data.get("signatureType", "ApiKey")
    signature = data.get("signature")

    if not all([payload_id, signature]):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="payloadId and signature are required"
        )

    logger.info(f"[WALLET] Input - payloadId: {payload_id}, signature: {len(signature)} chars")

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
            error_msg = body.get("message", "Zynk API returned error")
            logger.error(f"[WALLET] Zynk API returned error: {error_msg}")
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail=error_msg
            )

        logger.info(f"[WALLET] Submit wallet response: {body}")

        wallet_data = body.get("data", {})
        wallet_id = wallet_data.get("walletId")
        addresses = wallet_data.get("addresses", [])

        return {
            "success": True,
            "message": "Wallet created successfully",
            "data": {
                "walletId": wallet_id,
                "addresses": addresses
            }
        }

