"""
Wallet Router

Handles wallet creation endpoints for Zynk Labs Continuum API integration.
Follows the official Zynk Labs authentication and wallet creation flow:
1. Generate ephemeral P-256 key pair
2. Initiate OTP for authentication
3. Start session with OTP and ephemeral public key
4. Decrypt credential bundle to get session key
5. Prepare wallet creation challenge
6. Sign challenge with session key
7. Submit signed wallet creation
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
    generate_p256_key_pair,
    decrypt_credential_bundle,
    sign_payload_with_session_key
)
from app.services.otp_service import OTPService

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1/wallets", tags=["Wallets"])

# Rate limiter instance (will be set from app.state.limiter)
limiter = Limiter(key_func=get_remote_address)


def _auth_header():
    """Get Zynk API authentication header"""
    if not settings.zynk_api_key:
        raise HTTPException(status_code=500, detail="Zynk API key not configured")
    return {
        "x-api-token": settings.zynk_api_key,
        "Content-Type": "application/json",
        "Accept": "application/json"
    }


def _continuum_auth_header():
    """Get Zynk Continuum API authentication header"""
    if not settings.zynk_api_key:
        raise HTTPException(status_code=500, detail="Zynk API key not configured")
    return {
        "x-api-token": settings.zynk_api_key,
        "Content-Type": "application/json",
        "Accept": "application/json"
    }


@router.post("/generate-keypair")
@limiter.limit("30/minute")
async def generate_keypair(request: Request):
    """
    Generate a P-256 key pair for wallet creation.

    Returns:
        - publicKey: Base64-encoded uncompressed public key
        - privateKeyPem: PEM-encoded private key
    """
    try:
        private_key_pem, public_key_base64 = generate_p256_key_pair()

        return {
            "success": True,
            "message": "Key pair generated successfully",
            "data": {
                "publicKey": public_key_base64,
                "privateKeyPem": private_key_pem
            }
        }
    except Exception as e:
        logger.error(f"Error generating key pair: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to generate key pair: {str(e)}"
        )


@router.post("/{entity_id}/initiate-otp")
@limiter.limit("10/minute")
async def initiate_otp(
    entity_id: str,
    request: Request,
    current_user: Entities = Depends(get_current_entity)
):
    """
    Initiate email OTP for wallet session creation.

    Path: entity_id - Zynk entity ID
    Body: None (uses current user's email)

    Returns:
        - otpId: OTP session ID for verification
    """
    try:
        # Verify entity belongs to current user
        if current_user.zynk_entity_id != entity_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Entity ID does not match authenticated user"
            )

        # Send email OTP to current user's email
        otp_service = OTPService(prisma)
        success, message, otp_data = await otp_service.send_email_otp(current_user.email)

        if not success:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=message
            )

        return {
            "success": True,
            "message": "OTP sent successfully",
            "otpId": otp_data.get("otp_id") if otp_data else None
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error initiating OTP: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to initiate OTP: {str(e)}"
        )


@router.post("/{entity_id}/start-session")
@limiter.limit("10/minute")
async def start_session(
    entity_id: str,
    data: dict,
    request: Request,
    current_user: Entities = Depends(get_current_entity)
):
    """
    Start Zynk session using OTP and ephemeral public key.

    Path: entity_id - Zynk entity ID
    Body:
        - publicKey: Base64-encoded ephemeral public key
        - otpId: OTP session ID
        - otpCode: OTP code

    Returns:
        - credentialBundle: Encrypted credential bundle from Zynk
    """
    try:
        public_key = data.get("publicKey")
        otp_id = data.get("otpId")
        otp_code = data.get("otpCode")

        if not all([public_key, otp_id, otp_code]):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="publicKey, otpId, and otpCode are required"
            )

        # Verify entity belongs to current user
        if current_user.zynk_entity_id != entity_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Entity ID does not match authenticated user"
            )

        # Verify OTP
        otp_service = OTPService(prisma)
        success, message, _ = await otp_service.verify_email_otp(
            email=current_user.email,
            otp_code=otp_code
        )

        if not success:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=message or "Invalid OTP code"
            )

        # Call Zynk Labs continuum session creation endpoint
        url = f"{settings.zynk_base_url}/api/v1/continuum/session/create"
        payload = {
            "entityId": entity_id,
            "ephemeralPublicKey": public_key
        }

        async with httpx.AsyncClient(timeout=settings.zynk_timeout_s) as client:
            response = await client.post(
                url,
                json=payload,
                headers=_continuum_auth_header()
            )

            if response.status_code != 200:
                error_detail = response.json().get("message", f"HTTP {response.status_code}")
                raise HTTPException(
                    status_code=status.HTTP_502_BAD_GATEWAY,
                    detail=f"Zynk API error: {error_detail}"
                )

            body = response.json()
            if not body.get("success"):
                raise HTTPException(
                    status_code=status.HTTP_502_BAD_GATEWAY,
                    detail=body.get("message", "Zynk API returned error")
                )

            credential_bundle = body.get("data", {}).get("credentialBundle")
            if not credential_bundle:
                raise HTTPException(
                    status_code=status.HTTP_502_BAD_GATEWAY,
                    detail="Zynk API did not return credential bundle"
                )

            return {
                "success": True,
                "message": "Session created successfully",
                "credentialBundle": credential_bundle
            }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error starting session: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to start session: {str(e)}"
        )


@router.post("/decrypt-credential")
@limiter.limit("30/minute")
async def decrypt_credential(
    data: dict,
    request: Request,
    current_user: Entities = Depends(get_current_entity)
):
    """
    Decrypt credential bundle to extract session key.

    Body:
        - credentialBundle: Encrypted credential bundle from Zynk
        - privateKeyPem: PEM-encoded ephemeral private key

    Returns:
        - sessionKeyJwk: Session key in JWK format
    """
    try:
        credential_bundle = data.get("credentialBundle")
        private_key_pem = data.get("privateKeyPem")

        if not credential_bundle or not private_key_pem:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="credentialBundle and privateKeyPem are required"
            )

        # Decrypt credential bundle
        credential_data = decrypt_credential_bundle(credential_bundle, private_key_pem)

        # Extract session key JWK
        session_key_jwk = credential_data.get("sessionKey")
        if not session_key_jwk:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Session key not found in decrypted credential"
            )

        return {
            "success": True,
            "message": "Credential decrypted successfully",
            "sessionKeyJwk": json.dumps(session_key_jwk) if isinstance(session_key_jwk, dict) else session_key_jwk
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error decrypting credential: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to decrypt credential: {str(e)}"
        )


@router.post("/create/prepare")
@limiter.limit("30/minute")
async def prepare_wallet_creation(
    data: dict,
    request: Request,
    current_user: Entities = Depends(get_current_entity)
):
    """
    Prepare wallet creation challenge.

    Body:
        - entityId: Zynk entity ID
        - walletName: Name for the wallet
        - chain: Blockchain (SOLANA, ETHEREUM, ARBITRUM, POLYGON)

    Returns:
        - payloadId: Unique identifier for this challenge
        - payloadToSign: JSON stringified unsigned activity payload
        - rpId: Relying Party ID for Turnkey authentication
    """
    try:
        entity_id = data.get("entityId")
        wallet_name = data.get("walletName")
        chain = data.get("chain", "SOLANA")

        if not all([entity_id, wallet_name]):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="entityId and walletName are required"
            )

        # Verify entity belongs to current user
        if current_user.zynk_entity_id != entity_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Entity ID does not match authenticated user"
            )

        # Call Zynk Labs prepare wallet creation endpoint
        url = f"{settings.zynk_base_url}/api/v1/wallets/create/prepare"
        payload = {
            "entityId": entity_id,
            "walletName": wallet_name,
            "chain": chain
        }

        async with httpx.AsyncClient(timeout=settings.zynk_timeout_s) as client:
            response = await client.post(
                url,
                json=payload,
                headers=_continuum_auth_header()
            )

            if response.status_code != 200:
                error_detail = response.json().get("message", f"HTTP {response.status_code}")
                raise HTTPException(
                    status_code=status.HTTP_502_BAD_GATEWAY,
                    detail=f"Zynk API error: {error_detail}"
                )

            body = response.json()
            if not body.get("success"):
                raise HTTPException(
                    status_code=status.HTTP_502_BAD_GATEWAY,
                    detail=body.get("message", "Zynk API returned error")
                )

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
                "message": "Wallet creation challenge prepared successfully",
                "payloadId": payload_id,
                "payloadToSign": payload_to_sign,
                "rpId": rp_id
            }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error preparing wallet creation: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to prepare wallet creation: {str(e)}"
        )


@router.post("/sign-payload")
@limiter.limit("30/minute")
async def sign_payload(
    data: dict,
    request: Request,
    current_user: Entities = Depends(get_current_entity)
):
    """
    Sign a payload using the session key.

    Body:
        - payloadToSign: String payload to sign
        - sessionKeyJwk: Session key in JWK format

    Returns:
        - signature: Base64-encoded signature
    """
    try:
        payload_to_sign = data.get("payloadToSign")
        session_key_jwk = data.get("sessionKeyJwk")

        if not payload_to_sign or not session_key_jwk:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="payloadToSign and sessionKeyJwk are required"
            )

        # Sign payload
        signature = sign_payload_with_session_key(payload_to_sign, session_key_jwk)

        return {
            "success": True,
            "message": "Payload signed successfully",
            "signature": signature
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error signing payload: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to sign payload: {str(e)}"
        )


@router.post("/create/submit")
@limiter.limit("30/minute")
async def submit_wallet_creation(
    data: dict,
    request: Request,
    current_user: Entities = Depends(get_current_entity)
):
    """
    Submit signed wallet creation activity.

    Body:
        - payloadId: Payload ID from prepare step
        - signatureType: "ApiKey" for session-based signing
        - signature: Signed challenge (X-Stamp header value)

    Returns:
        - walletId: Created wallet ID
        - addresses: Wallet addresses for the chain
    """
    try:
        payload_id = data.get("payloadId")
        signature_type = data.get("signatureType", "ApiKey")
        signature = data.get("signature")

        if not all([payload_id, signature]):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="payloadId and signature are required"
            )

        # Call Zynk Labs submit wallet creation endpoint
        url = f"{settings.zynk_base_url}/api/v1/wallets/create/submit"
        payload = {
            "payloadId": payload_id,
            "signatureType": signature_type,
            "signature": signature
        }

        async with httpx.AsyncClient(timeout=settings.zynk_timeout_s) as client:
            response = await client.post(
                url,
                json=payload,
                headers=_continuum_auth_header()
            )

            if response.status_code != 200:
                error_detail = response.json().get("message", f"HTTP {response.status_code}")
                raise HTTPException(
                    status_code=status.HTTP_502_BAD_GATEWAY,
                    detail=f"Zynk API error: {error_detail}"
                )

            body = response.json()
            if not body.get("success"):
                raise HTTPException(
                    status_code=status.HTTP_502_BAD_GATEWAY,
                    detail=body.get("message", "Zynk API returned error")
                )

            wallet_data = body.get("data", {})
            wallet_id = wallet_data.get("walletId")
            addresses = wallet_data.get("addresses", [])

            return {
                "success": True,
                "message": "Wallet created successfully",
                "walletId": wallet_id,
                "addresses": addresses
            }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error submitting wallet creation: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to submit wallet creation: {str(e)}"
        )

