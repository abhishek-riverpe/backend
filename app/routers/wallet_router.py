"""
Wallet Router

Handles wallet creation flow using Zynk Labs Continuum API.
Implements email-based authentication and two-step wallet creation process.
"""

import logging
import httpx
import json
from fastapi import APIRouter, HTTPException, status, Depends, Request
from slowapi import Limiter
from slowapi.util import get_remote_address
from pydantic import BaseModel, EmailStr
from typing import Optional, Dict, Any
from ..core.config import settings
from ..core.database import prisma
from ..utils.wallet_crypto import (
    generate_p256_key_pair,
    public_key_to_base64,
    sha256_hash,
    decrypt_credential_bundle,
    sign_payload_with_session_key,
    jwk_to_private_key
)
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
import base64

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/wallet", tags=["wallet"])

# Rate limiter
limiter = Limiter(key_func=get_remote_address)


def _auth_header() -> Dict[str, str]:
    """Generate authentication header for Zynk Labs API"""
    if not settings.zynk_api_key:
        raise HTTPException(status_code=500, detail="Zynk API key not configured")
    return {
        "x-api-token": settings.zynk_api_key,
    }


# Request/Response Models
class InitiateOtpRequest(BaseModel):
    entityId: str
    email: EmailStr


class InitiateOtpResponse(BaseModel):
    success: bool
    message: str
    data: Optional[Dict[str, Any]] = None
    otpId: Optional[str] = None


class StartSessionRequest(BaseModel):
    entityId: str
    publicKey: str  # Base64 encoded uncompressed public key
    otpId: str
    otpCode: str


class StartSessionResponse(BaseModel):
    success: bool
    message: str
    credentialBundle: Optional[str] = None
    sessionId: Optional[str] = None


class PrepareWalletRequest(BaseModel):
    entityId: str
    walletName: str
    chain: str = "SOLANA"  # SOLANA, ETHEREUM, ARBITRUM, POLYGON


class PrepareWalletResponse(BaseModel):
    success: bool
    payloadId: Optional[str] = None
    payloadToSign: Optional[str] = None
    rpId: Optional[str] = None
    message: Optional[str] = None


class SubmitWalletRequest(BaseModel):
    payloadId: str
    signatureType: str  # "ApiKey" or "WebAuthn"
    signature: str  # Base64 encoded signature


class SubmitWalletResponse(BaseModel):
    success: bool
    walletId: Optional[str] = None
    addresses: Optional[list[str]] = None
    message: Optional[str] = None


# Endpoints

@router.post("/initiate-otp", response_model=InitiateOtpResponse)
@limiter.limit("10/minute")
async def initiate_otp(request_data: InitiateOtpRequest, request: Request):
    """
    Initiate OTP for email authentication.
    This calls Zynk Labs API to send OTP to the user's email.
    """
    try:
        url = f"{settings.zynk_base_url}/api/v1/wallets/{request_data.entityId}/initiate-otp"
        headers = {
            **_auth_header(),
            "Content-Type": "application/json",
            "Accept": "application/json"
        }
        
        payload = {
            "email": request_data.email
        }
        
        logger.info(f"[WALLET] Initiating OTP for entity {request_data.entityId}, email: {request_data.email}")
        
        async with httpx.AsyncClient(timeout=settings.zynk_timeout_s) as client:
            response = await client.post(url, json=payload, headers=headers)
            
            if response.status_code == 200:
                body = response.json()
                return InitiateOtpResponse(
                    success=True,
                    message="OTP sent successfully",
                    data=body.get("data"),
                    otpId=body.get("data", {}).get("otpId")
                )
            else:
                error_body = response.json() if response.headers.get("content-type", "").startswith("application/json") else {}
                error_msg = error_body.get("message", f"Failed to initiate OTP: {response.status_code}")
                logger.error(f"[WALLET] OTP initiation failed: {error_msg}")
                raise HTTPException(
                    status_code=response.status_code,
                    detail=error_msg
                )
                
    except httpx.RequestError as e:
        logger.error(f"[WALLET] Network error initiating OTP: {e}")
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Failed to connect to authentication service"
        )
    except Exception as e:
        logger.error(f"[WALLET] Error initiating OTP: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to initiate OTP"
        )


@router.post("/start-session", response_model=StartSessionResponse)
@limiter.limit("10/minute")
async def start_session(request_data: StartSessionRequest, request: Request):
    """
    Start a session using email OTP authentication.
    Returns encrypted credential bundle that must be decrypted with ephemeral private key.
    """
    try:
        url = f"{settings.zynk_base_url}/api/v1/wallets/{request_data.entityId}/start-session"
        headers = {
            **_auth_header(),
            "Content-Type": "application/json",
            "Accept": "application/json"
        }
        
        payload = {
            "publicKey": request_data.publicKey,
            "otpId": request_data.otpId,
            "otpCode": request_data.otpCode
        }
        
        logger.info(f"[WALLET] Starting session for entity {request_data.entityId}")
        
        async with httpx.AsyncClient(timeout=settings.zynk_timeout_s) as client:
            response = await client.post(url, json=payload, headers=headers)
            
            if response.status_code == 200:
                body = response.json()
                credential_bundle = body.get("data", {}).get("credentialBundle")
                session_id = body.get("data", {}).get("sessionId")
                
                return StartSessionResponse(
                    success=True,
                    message="Session created successfully",
                    credentialBundle=credential_bundle,
                    sessionId=session_id
                )
            else:
                error_body = response.json() if response.headers.get("content-type", "").startswith("application/json") else {}
                error_msg = error_body.get("message", f"Failed to start session: {response.status_code}")
                logger.error(f"[WALLET] Session start failed: {error_msg}")
                raise HTTPException(
                    status_code=response.status_code,
                    detail=error_msg
                )
                
    except httpx.RequestError as e:
        logger.error(f"[WALLET] Network error starting session: {e}")
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Failed to connect to authentication service"
        )
    except Exception as e:
        logger.error(f"[WALLET] Error starting session: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to start session"
        )


@router.post("/prepare", response_model=PrepareWalletResponse)
@limiter.limit("20/minute")
async def prepare_wallet_creation(request_data: PrepareWalletRequest, request: Request):
    """
    Step 1: Prepare wallet creation challenge.
    Returns a payload that needs to be signed.
    """
    try:
        url = f"{settings.zynk_base_url}/api/v1/wallets/create/prepare"
        headers = {
            **_auth_header(),
            "Content-Type": "application/json",
            "Accept": "application/json"
        }
        
        payload = {
            "entityId": request_data.entityId,
            "walletName": request_data.walletName,
            "chain": request_data.chain
        }
        
        logger.info(f"[WALLET] Preparing wallet creation for entity {request_data.entityId}, chain: {request_data.chain}")
        
        async with httpx.AsyncClient(timeout=settings.zynk_timeout_s) as client:
            response = await client.post(url, json=payload, headers=headers)
            
            if response.status_code == 200:
                body = response.json()
                return PrepareWalletResponse(
                    success=True,
                    payloadId=body.get("payloadId"),
                    payloadToSign=body.get("payloadToSign"),
                    rpId=body.get("rpId"),
                    message="Wallet creation challenge prepared"
                )
            else:
                error_body = response.json() if response.headers.get("content-type", "").startswith("application/json") else {}
                error_msg = error_body.get("message", f"Failed to prepare wallet: {response.status_code}")
                logger.error(f"[WALLET] Wallet preparation failed: {error_msg}")
                raise HTTPException(
                    status_code=response.status_code,
                    detail=error_msg
                )
                
    except httpx.RequestError as e:
        logger.error(f"[WALLET] Network error preparing wallet: {e}")
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Failed to connect to wallet service"
        )
    except Exception as e:
        logger.error(f"[WALLET] Error preparing wallet: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to prepare wallet creation"
        )


@router.post("/submit", response_model=SubmitWalletResponse)
@limiter.limit("20/minute")
async def submit_wallet_creation(request_data: SubmitWalletRequest, request: Request):
    """
    Step 2: Submit signed wallet creation activity.
    Completes the wallet creation process.
    """
    try:
        url = f"{settings.zynk_base_url}/api/v1/wallets/create/submit"
        headers = {
            **_auth_header(),
            "Content-Type": "application/json",
            "Accept": "application/json"
        }
        
        payload = {
            "payloadId": request_data.payloadId,
            "signatureType": request_data.signatureType,
            "signature": request_data.signature
        }
        
        logger.info(f"[WALLET] Submitting wallet creation with payloadId: {request_data.payloadId}")
        
        async with httpx.AsyncClient(timeout=settings.zynk_timeout_s) as client:
            response = await client.post(url, json=payload, headers=headers)
            
            if response.status_code == 200:
                body = response.json()
                return SubmitWalletResponse(
                    success=True,
                    walletId=body.get("walletId"),
                    addresses=body.get("addresses", []),
                    message="Wallet created successfully"
                )
            else:
                error_body = response.json() if response.headers.get("content-type", "").startswith("application/json") else {}
                error_msg = error_body.get("message", f"Failed to submit wallet: {response.status_code}")
                logger.error(f"[WALLET] Wallet submission failed: {error_msg}")
                raise HTTPException(
                    status_code=response.status_code,
                    detail=error_msg
                )
                
    except httpx.RequestError as e:
        logger.error(f"[WALLET] Network error submitting wallet: {e}")
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Failed to connect to wallet service"
        )
    except Exception as e:
        logger.error(f"[WALLET] Error submitting wallet: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to submit wallet creation"
        )


@router.post("/generate-keypair")
@limiter.limit("30/minute")
async def generate_keypair(request: Request):
    """
    Generate a P-256 ephemeral key pair for session creation.
    Returns the public key in base64 format (to be sent to Zynk) and
    stores the private key temporarily (client should handle this securely).
    
    Note: In production, key generation should happen on the client side.
    This endpoint is provided for convenience but should be used carefully.
    """
    try:
        private_key, public_key_bytes = generate_p256_key_pair()
        public_key_b64 = public_key_to_base64(public_key_bytes)
        
        # Serialize private key for client (in production, this should be done client-side)
        private_key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        return {
            "success": True,
            "publicKey": public_key_b64,
            "privateKeyPem": private_key_pem.decode('utf-8'),
            "message": "Key pair generated. Store private key securely."
        }
        
    except Exception as e:
        logger.error(f"[WALLET] Error generating key pair: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to generate key pair"
        )


@router.post("/decrypt-credential")
@limiter.limit("20/minute")
async def decrypt_credential(request_data: Dict[str, str], request: Request):
    """
    Decrypt credential bundle using ephemeral private key.
    
    Request body:
    {
        "credentialBundle": "base64_encoded_encrypted_bundle",
        "privateKeyPem": "PEM_format_private_key"
    }
    
    Returns decrypted session key in JWK format.
    """
    try:
        credential_bundle = request_data.get("credentialBundle")
        private_key_pem = request_data.get("privateKeyPem")
        
        if not credential_bundle or not private_key_pem:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Missing credentialBundle or privateKeyPem"
            )
        
        # Load private key from PEM
        from cryptography.hazmat.primitives import serialization
        private_key = serialization.load_pem_private_key(
            private_key_pem.encode(),
            password=None,
            backend=default_backend()
        )
        
        # Decrypt credential bundle
        session_key_jwk = decrypt_credential_bundle(credential_bundle, private_key)
        
        return {
            "success": True,
            "sessionKeyJwk": session_key_jwk,
            "message": "Credential bundle decrypted successfully"
        }
        
    except Exception as e:
        logger.error(f"[WALLET] Error decrypting credential: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to decrypt credential bundle: {str(e)}"
        )


@router.post("/sign-payload")
@limiter.limit("30/minute")
async def sign_payload(request_data: Dict[str, str], request: Request):
    """
    Sign a payload using session private key.
    
    Request body:
    {
        "payloadToSign": "JSON_stringified_payload",
        "sessionKeyJwk": "JWK_format_session_key"
    }
    
    Returns base64 encoded signature.
    """
    try:
        payload_to_sign = request_data.get("payloadToSign")
        session_key_jwk = request_data.get("sessionKeyJwk")
        
        if not payload_to_sign or not session_key_jwk:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Missing payloadToSign or sessionKeyJwk"
            )
        
        # Sign the payload
        signature = sign_payload_with_session_key(payload_to_sign, session_key_jwk)
        
        return {
            "success": True,
            "signature": signature,
            "message": "Payload signed successfully"
        }
        
    except Exception as e:
        logger.error(f"[WALLET] Error signing payload: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to sign payload: {str(e)}"
        )

