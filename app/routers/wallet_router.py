import json
import httpx
from fastapi import APIRouter, HTTPException, status, Depends, Request
from slowapi import Limiter # type: ignore
from slowapi.util import get_remote_address # type: ignore
from app.core.config import settings
from app.core.auth import get_current_entity
from app.core.database import prisma
from prisma.models import entities as Entities # type: ignore
from app.utils.wallet_crypto import (
    generate_keypair as generate_keypair_crypto,
    decrypt_credential_bundle,
    sign_payload_with_api_key
)

router = APIRouter(prefix="/api/v1/wallets", tags=["Wallets"])
limiter = Limiter(key_func=get_remote_address)

def _clean_entity_id(entity_id) -> str:
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
    if not settings.zynk_api_key:
        raise HTTPException(status_code=500, detail="Zynk API key not configured")
    return {
        "x-api-token": settings.zynk_api_key,
        "Content-Type": "application/json",
        "Accept": "application/json"
    }


async def _initiate_otp_internal(entity_id: str, user_email: str) -> dict:
    url = f"{settings.zynk_base_url}/api/v1/wallets/{entity_id}/initiate-otp"
    
    headers = _zynk_auth_header()
    
    async with httpx.AsyncClient(timeout=settings.zynk_timeout_s) as client:
        response = await client.post(url, headers=headers)
        
        if response.status_code != 200:
            try:
                error_body = response.json()
                error_detail = error_body.get("message", f"HTTP {response.status_code}")
            except:
                error_detail = f"HTTP {response.status_code}: {response.text[:200]}"
            
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail=f"Zynk API error: {error_detail}"
            )
        
        body = response.json()
        
        if not body.get("success"):
            error_msg = body.get("message", "Zynk API returned error")
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail=error_msg
            )
        
        data = body.get("data", {})
        otp_id = data.get("otpId")
        
        if not otp_id:
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail="Zynk API did not return otpId"
            )
        
        return body


@router.post("/register-auth")
@limiter.limit("10/minute")
async def register_auth(
    request: Request,
    current_user: Entities = Depends(get_current_entity)
):

    entity_id = _clean_entity_id(current_user.zynk_entity_id)
    url = f"{settings.zynk_base_url}/api/v1/wallets/{entity_id}/register-auth"
    payload = {
        "authType": "Email_Auth",
        "authPayload": {
            "email": current_user.email
        }
    }

    async with httpx.AsyncClient(timeout=settings.zynk_timeout_s) as client:
        response = await client.post(url, json=payload, headers=_zynk_auth_header())
     
        if response.status_code == 200:
            body = response.json()

            if body.get("success"):
                try:
                    otp_response = await _initiate_otp_internal(entity_id, current_user.email)
                    return otp_response
                except HTTPException:
                    raise
                except Exception as e:
                    raise HTTPException(
                        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                        detail=f"Failed to initiate OTP: {str(e)}"
                    )
            else:
                error_msg = body.get("error", {}).get("message", "Unknown error")
                raise HTTPException(
                    status_code=status.HTTP_502_BAD_GATEWAY,
                    detail=f"Zynk API error: {error_msg}"
                )

        elif response.status_code == 400:
            try:
                body = response.json()
                error_details = body.get("error", {}).get("details", "")
                if "Entity already has a registered Turnkey organization" in error_details:
                    try:
                        otp_response = await _initiate_otp_internal(entity_id, current_user.email)
                        return otp_response
                    except HTTPException:
                        raise
                    except Exception as e:
                        raise HTTPException(
                            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                            detail=f"Failed to initiate OTP: {str(e)}"
                        )
                else:
                    error_msg = body.get("error", {}).get("message", "Bad Request")
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail=error_msg
                    )
            except Exception:
                raise HTTPException(
                    status_code=status.HTTP_502_BAD_GATEWAY,
                    detail="Invalid response from Zynk API"
                )

        else:
            try:
                error_detail = response.json().get("message", f"HTTP {response.status_code}")
            except:
                error_detail = f"HTTP {response.status_code}: {response.text[:200]}"

            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail=f"Zynk API error: {error_detail}"
            )


@router.post("/generate-keypair")
@limiter.limit("30/minute")
async def generate_keypair(request: Request):
    private_hex, public_hex = generate_keypair_crypto()

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
    try:
        entity_id = _clean_entity_id(current_user.zynk_entity_id)

        result = await _initiate_otp_internal(entity_id, current_user.email)
        
        return result

    except HTTPException:
        raise
    except Exception as e:
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
    otp_id = data.get("otpId")
    otp_code = data.get("otpCode")
    public_key = data.get("publicKey")

    if not otp_id or not otp_code:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="otpId and otpCode are required"
        )

    entity_id = _clean_entity_id(current_user.zynk_entity_id)

    private_hex = None
    if not public_key:
        private_hex, public_key = generate_keypair_crypto()

    url = f"{settings.zynk_api_key}/api/v1/wallets/{entity_id}/start-session"
    payload = {
        "publicKey": public_key,
        "otpId": otp_id,
        "otpCode": otp_code
    }

    async with httpx.AsyncClient(timeout=settings.zynk_timeout_s) as client:
        response = await client.post(
            url,
            json=payload,
            headers=_zynk_auth_header()
        )

        if response.status_code != 200:
            try:
                error_body = response.json()
                error_detail = error_body.get("message", f"HTTP {response.status_code}")
            except:
                error_detail = f"HTTP {response.status_code}: {response.text[:200]}"
            
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail=f"Zynk API error: {error_detail}"
            )

        body = response.json()

        if not body.get("success"):
            error_msg = body.get("message", "Zynk API returned error")
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail=error_msg
            )

        credential_bundle = body.get("data", {}).get("credentialBundle")
        if not credential_bundle:
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail="Zynk API did not return credential bundle"
            )

        result = {
            "success": True,
            "data": {
                "credentialBundle": credential_bundle
            }
        }
        
        if private_hex:
            result["data"]["privateKey"] = private_hex

        return result


@router.post("/decrypt-bundle")
@limiter.limit("30/minute")
async def decrypt_bundle(
    data: dict,
    request: Request,
    current_user: Entities = Depends(get_current_entity)
):
    credential_bundle = data.get("credentialBundle")
    ephemeral_private_key = data.get("ephemeralPrivateKey")

    if not credential_bundle or not ephemeral_private_key:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="credentialBundle and ephemeralPrivateKey are required"
        )

    result = decrypt_credential_bundle(credential_bundle, ephemeral_private_key)

    session_private_key = result['tempPrivateKey']
    session_public_key = result['tempPublicKey']

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
    wallet_name = data.get("walletName")
    chain = data.get("chain", "SOLANA")

    if not wallet_name:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="walletName is required"
        )

    entity_id = _clean_entity_id(current_user.zynk_entity_id)

    url = f"{settings.zynk_base_url}/api/v1/wallets/{entity_id}/create/prepare"
    payload = {
        "walletName": wallet_name,
        "chain": chain
    }

    async with httpx.AsyncClient(timeout=settings.zynk_timeout_s) as client:
        response = await client.post(
            url,
            json=payload,
            headers=_zynk_auth_header()
        )

        if response.status_code != 200:
            error_detail = response.json().get("message", f"HTTP {response.status_code}")
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail=f"Zynk API error: {error_detail}"
            )

        body = response.json()
        if not body.get("success"):
            error_msg = body.get("message", "Zynk API returned error")
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail=error_msg
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
    try:
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
            return {
                "success": True,
                "message": "No wallet found",
                "data": None
            }
        
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
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to fetch wallet"
        )


async def _get_validated_user_wallet(current_user):
    user = await prisma.entities.find_unique(where={"id": current_user.id})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if not user.wallet_id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, 
            detail="User does not have a wallet"
        )

    wallet = await prisma.wallets.find_first(
        where={
            "zynk_wallet_id": user.wallet_id,
            "entity_id": str(user.zynk_entity_id),
            "deleted_at": None
        }
    )
    
    if not wallet:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Wallet not found or unauthorized"
        )

    return user, wallet


@router.get("/")
@limiter.limit("60/minute")
async def get_wallet_details(
    request: Request,
    current_user: Entities = Depends(get_current_entity)
):

    user, _ = await _get_validated_user_wallet(current_user)

    url = f"{settings.zynk_base_url}/api/v1/wallets/{user.wallet_id}"
    
    async with httpx.AsyncClient(timeout=settings.zynk_timeout_s) as client:
        response = await client.get(url, headers=_zynk_auth_header())

    if response.status_code != 200:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Failed to fetch wallet details from Zynk API"
        )
    
    return response.json()


@router.get("/balances")
@limiter.limit("60/minute")
async def get_wallet_balances(
    request: Request,
    current_user: Entities = Depends(get_current_entity)
):

    user, _ = await _get_validated_user_wallet(current_user)

    url = f"{settings.zynk_base_url}/api/v1/wallets/{user.wallet_id}/balances"
    
    async with httpx.AsyncClient(timeout=settings.zynk_timeout_s) as client:
        response = await client.get(url, headers=_zynk_auth_header())

    if response.status_code != 200:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Failed to fetch wallet balances from Zynk API"
        )
    
    return response.json()



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

    wallet = await prisma.wallets.find_first(
        where={
            "zynk_wallet_id": wallet_id,
            "entity_id": str(current_user.id),
            "deleted_at": None
        }
    )
    
    if not wallet:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Wallet not found or unauthorized"
        )
    
    url = f"{settings.zynk_base_url}/api/v1/wallets/{wallet_id}/{address}/transactions"
    params = {"limit": limit, "offset": offset}
    
    async with httpx.AsyncClient(timeout=settings.zynk_timeout_s) as client:
        response = await client.get(url, headers=_zynk_auth_header(), params=params)
        
        if response.status_code != 200:
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail=f"Failed to fetch wallet transactions from Zynk API"
            )
        
        body = response.json()
        return body


@router.post("/sign-payload")
@limiter.limit("30/minute")
async def sign_payload(
    data: dict,
):
    payload_to_sign = data.get("payload")
    session_private_key = data.get("sessionPrivateKey")
    session_public_key = data.get("sessionPublicKey")

    if not all([payload_to_sign, session_private_key, session_public_key]):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="payload, sessionPrivateKey, and sessionPublicKey are required"
        )

    signature = sign_payload_with_api_key(payload_to_sign, session_private_key, session_public_key)

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
            headers=_zynk_auth_header()
        )

        if response.status_code != 200:
            error_detail = response.json().get("message", f"HTTP {response.status_code}")
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail=f"Zynk API error: {error_detail}"
            )

        body = response.json()
        if not body.get("success"):
            error_msg = body.get("message", "Zynk API returned error")
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail=error_msg
            )

        wallet_data = body.get("data", {})
        wallet_id = wallet_data.get("walletId")
        addresses = wallet_data.get("addresses", [])

        try:
            wallet_name = data.get("walletName", "Solana Wallet")
            chain = data.get("chain", "SOLANA")
            
            wallet = await prisma.wallets.create(
                data={
                    "entity_id": str(current_user.id),
                    "zynk_wallet_id": wallet_id,
                    "wallet_name": wallet_name,
                    "chain": chain,
                    "status": "ACTIVE"
                }
            )
        except Exception as db_error:
            pass
    
        account_prepare_data = None
        account_created = None
        
        try:
            prepare_url = f"{settings.zynk_base_url}/api/v1/wallets/{wallet_id}/accounts/prepare"
            prepare_payload = {"chain": chain}
            
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
                        if session_private_key and session_public_key and account_prepare_data: 
                            try:
                                account_payload_to_sign = account_prepare_data.get('payloadToSign')
                                account_payload_id = account_prepare_data.get('payloadId')
                                
                                account_signature = sign_payload_with_api_key(
                                    account_payload_to_sign,
                                    session_private_key,
                                    session_public_key
                                )
                                
                                submit_url = f"{settings.zynk_base_url}/api/v1/wallets/accounts/submit"
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
                                            account_created = {
                                                "address": account_address,
                                                "curve": account_details.get("curve"),
                                                "path": account_details.get("path"),
                                                "pathFormat": account_details.get("pathFormat"),
                                                "addressFormat": account_details.get("addressFormat")
                                            }
                                        except Exception as db_error:
                                            pass
                                    else:
                                        pass
                                else:
                                    pass
                            except Exception as account_error:
                                pass
                    else:
                        pass
                else:
                    pass
        except Exception as prepare_error:
            pass

        response_data = {
            "walletId": wallet_id,
            "addresses": addresses
        }
        
        if account_created:
            response_data["account"] = account_created
            message = "Wallet and account created successfully"
        elif account_prepare_data:
            response_data["accountPrepare"] = account_prepare_data
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

    chain = data.get("chain", "SOLANA")
    
    wallet = await prisma.wallets.find_first(
        where={
            "zynk_wallet_id": wallet_id,
            "entity_id": str(current_user.id),
            "deleted_at": None
        }
    )
    
    if not wallet:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Wallet not found or unauthorized"
        )
    
    url = f"{settings.zynk_base_url}/api/v1/wallets/{wallet_id}/accounts/prepare"
    payload = {
        "chain": chain
    }
    
    async with httpx.AsyncClient(timeout=settings.zynk_timeout_s) as client:
        response = await client.post(
            url,
            json=payload,
            headers=_zynk_auth_header()
        )
        
        if response.status_code != 200:
            try:
                error_detail = response.json().get("message", f"HTTP {response.status_code}")
            except:
                error_detail = f"HTTP {response.status_code}: {response.text[:200]}"
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail=f"Zynk API error: {error_detail}"
            )
        
        body = response.json()
        if not body.get("success"):
            error_msg = body.get("message", "Zynk API returned error")
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail=error_msg
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

    payload_id = data.get("payloadId")
    signature_type = data.get("signatureType", "ApiKey")
    signature = data.get("signature")
    
    if not all([payload_id, signature]):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="payloadId and signature are required"
        )
    
    url = f"{settings.zynk_base_url}/api/v1/wallets/accounts/submit"
    payload = {
        "payloadId": payload_id,
        "signatureType": signature_type,
        "signature": signature
    }
    
    async with httpx.AsyncClient(timeout=settings.zynk_timeout_s) as client:
        response = await client.post(
            url,
            json=payload,
            headers=_zynk_auth_header()
        )
        
        if response.status_code != 200:
            try:
                error_detail = response.json().get("message", f"HTTP {response.status_code}")
            except:
                error_detail = f"HTTP {response.status_code}: {response.text[:200]}"
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail=f"Zynk API error: {error_detail}"
            )
        
        body = response.json()
        if not body.get("success"):
            error_msg = body.get("message", "Zynk API returned error")
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail=error_msg
            ) 
        
        account_data = body.get("data", {})
        wallet_id = account_data.get("walletId")
        account = account_data.get("account", {})
        address = account_data.get("address") or account.get("address")
        try:
            wallet = await prisma.wallets.find_first(
                where={
                    "zynk_wallet_id": wallet_id,
                    "entity_id": str(current_user.id),
                    "deleted_at": None
                }
            )
            
            if not wallet:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Wallet not found in database"
                )
            
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
            
        except Exception as db_error:
            pass

        return {
            "success": True,
            "message": "Wallet account created successfully",
            "data": {
                "walletId": wallet_id,
                "account": account,
                "address": address
            }
        }

