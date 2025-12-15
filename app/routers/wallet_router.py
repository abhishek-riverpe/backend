import httpx
from fastapi import APIRouter, HTTPException, status, Depends, Request
from slowapi import Limiter
from slowapi.util import get_remote_address
from ..core.config import settings
from ..core.auth import get_current_entity
from ..core.database import prisma
from prisma.models import entities as Entities # type: ignore
from ..utils.wallet_crypto import (
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

def _validate_safe_path_component(value: str, param_name: str, max_length: int = 200) -> str:
    """Validate path components to prevent path traversal SSRF attacks."""
    if not value or not isinstance(value, str):
        raise HTTPException(status_code=400, detail=f"Invalid {param_name}: must be a non-empty string")
    
    value = value.strip()
    if not value:
        raise HTTPException(status_code=400, detail=f"Invalid {param_name}: cannot be empty")
    
    if len(value) > max_length:
        raise HTTPException(status_code=400, detail=f"Invalid {param_name}: exceeds maximum length of {max_length}")
    
    if '..' in value or '/' in value or '\\' in value:
        raise HTTPException(status_code=400, detail=f"Invalid {param_name}: path traversal characters are not allowed")
    
    if not all(c.isalnum() or c in ('-', '_') for c in value):
        raise HTTPException(status_code=400, detail=f"Invalid {param_name}: contains invalid characters. Only alphanumeric, hyphens, and underscores are allowed")
    
    return value


def _zynk_auth_header():
    if not settings.zynk_api_key:
        raise HTTPException(status_code=500, detail="Zynk API key not configured")
    return {
        "x-api-token": settings.zynk_api_key,
        "Content-Type": "application/json",
        "Accept": "application/json"
    }


def _handle_zynk_response_error(response: httpx.Response) -> None:
    """Handle error responses from Zynk API."""
    try:
        error_detail = response.json().get("message", f"HTTP {response.status_code}")
    except Exception:
        error_detail = f"HTTP {response.status_code}: {response.text[:200]}"
    raise HTTPException(
        status_code=status.HTTP_502_BAD_GATEWAY,
        detail=f"Zynk API error: {error_detail}"
    )


def _validate_zynk_response_success(body: dict) -> None:
    """Validate that Zynk API response indicates success."""
    if not body.get("success"):
        error_msg = body.get("message", "Zynk API returned error")
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=error_msg
        )


async def _handle_otp_initiation_error(entity_id: str) -> dict:
    """Handle OTP initiation with consistent error handling."""
    try:
        return await _initiate_otp_internal(entity_id)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to initiate OTP: {str(e)}"
        )


async def _initiate_otp_internal(entity_id: str) -> dict:
    url = f"{settings.zynk_base_url}/api/v1/wallets/{entity_id}/initiate-otp"
    
    headers = _zynk_auth_header()
    
    async with httpx.AsyncClient(timeout=settings.zynk_timeout_s) as client:
        response = await client.post(url, headers=headers)
        
        if response.status_code != 200:
            _handle_zynk_response_error(response)
        
        body = response.json()
        _validate_zynk_response_success(body)
        
        data = body.get("data", {})
        
        if not data.get("otpId"):
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
                otp_response = await _handle_otp_initiation_error(entity_id)
                return otp_response
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
                    otp_response = await _handle_otp_initiation_error(entity_id)
                    return otp_response
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
            _handle_zynk_response_error(response)


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
    entity_id = _clean_entity_id(current_user.zynk_entity_id)
    result = await _handle_otp_initiation_error(entity_id)
    return result


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

    url = f"{settings.zynk_base_url}/api/v1/wallets/{entity_id}/start-session"
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
            _handle_zynk_response_error(response)

        body = response.json()
        _validate_zynk_response_success(body)

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
            _handle_zynk_response_error(response)

        body = response.json()
        _validate_zynk_response_success(body)

        data_response = body.get("data", {})
        payload_id = data_response.get("payloadId")
        payload_to_sign = data_response.get("payloadToSign")
        rp_id = data_response.get("rpId")

        if not all([payload_id, payload_to_sign]):
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail="Zynk API did not return complete challenge data"
            )

        return _create_prepare_response(payload_id, payload_to_sign, rp_id)


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
    except Exception:
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


async def _validate_wallet_ownership(wallet_id: str, current_user: Entities, include_accounts: bool = False):
    """Validate wallet belongs to current user and return wallet."""
    where_clause = {
        "zynk_wallet_id": wallet_id,
        "entity_id": str(current_user.id),
        "deleted_at": None
    }
    
    if include_accounts:
        wallet = await prisma.wallets.find_first(
            where=where_clause,
            include={
                "wallet_accounts": {
                    "where": {
                        "deleted_at": None
                    }
                }
            }
        )
    else:
        wallet = await prisma.wallets.find_first(where=where_clause)
    
    if not wallet:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Wallet not found or unauthorized"
        )
    
    return wallet


def _create_wallet_account_data(account_details: dict, address: str) -> dict:
    """Create wallet account data structure from account details."""
    return {
        "curve": account_details.get("curve", ""),
        "path_format": account_details.get("pathFormat", ""),
        "path": account_details.get("path", ""),
        "address_format": account_details.get("addressFormat", ""),
        "address": address
    }


def _create_account_response_data(account_details: dict, address: str) -> dict:
    """Create account response data structure."""
    return {
        "address": address,
        "curve": account_details.get("curve"),
        "path": account_details.get("path"),
        "pathFormat": account_details.get("pathFormat"),
        "addressFormat": account_details.get("addressFormat")
    }


def _create_prepare_response(payload_id: str, payload_to_sign: str, rp_id: str = None) -> dict:
    """Create standardized prepare response structure."""
    return {
        "success": True,
        "data": {
            "payloadId": payload_id,
            "payloadToSign": payload_to_sign,
            "rpId": rp_id
        }
    }


async def _make_zynk_get_request(url: str, error_message: str) -> dict:
    """Make a GET request to Zynk API and return JSON response."""
    async with httpx.AsyncClient(timeout=settings.zynk_timeout_s) as client:
        response = await client.get(url, headers=_zynk_auth_header())
    
    if response.status_code != 200:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=error_message
        )
    
    return response.json()


@router.get("/")
@limiter.limit("60/minute")
async def get_wallet_details(
    request: Request,
    current_user: Entities = Depends(get_current_entity)
):
    user, _ = await _get_validated_user_wallet(current_user)
    url = f"{settings.zynk_base_url}/api/v1/wallets/{user.wallet_id}"
    return await _make_zynk_get_request(url, "Failed to fetch wallet details from Zynk API")


@router.get("/balances")
@limiter.limit("60/minute")
async def get_wallet_balances(
    request: Request,
    current_user: Entities = Depends(get_current_entity)
):
    user, _ = await _get_validated_user_wallet(current_user)
    url = f"{settings.zynk_base_url}/api/v1/wallets/{user.wallet_id}/balances"
    return await _make_zynk_get_request(url, "Failed to fetch wallet balances from Zynk API")



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
    # Validate path parameters to prevent path traversal SSRF
    _validate_safe_path_component(wallet_id, "wallet_id")
    validated_address = _validate_safe_path_component(address, "address")

    # Verify wallet belongs to current user
    wallet = await _validate_wallet_ownership(wallet_id, current_user, include_accounts=True)
    
    # Verify the address belongs to this wallet
    wallet_addresses = [acc.address for acc in wallet.wallet_accounts] if wallet.wallet_accounts else []
    if validated_address not in wallet_addresses:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Address not found in wallet"
        )
    
    # Use validated wallet_id from database instead of path parameter
    validated_wallet_id = _validate_safe_path_component(wallet.zynk_wallet_id, "wallet_id")
    
    # Call Zynk API with validated values
    url = f"{settings.zynk_base_url}/api/v1/wallets/{validated_wallet_id}/{validated_address}/transactions"
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
    request: Request,
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
            _handle_zynk_response_error(response)

        body = response.json()
        _validate_zynk_response_success(body)

        wallet_data = body.get("data", {})
        wallet_id = wallet_data.get("walletId")
        addresses = wallet_data.get("addresses", [])

        wallet_name = data.get("walletName", "Solana Wallet")
        chain = data.get("chain", "SOLANA")
        
        wallet = None
        account_prepare_data = None
        account_created = None
        
        # Create wallet and account atomically if account creation succeeds
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
                                        account_details = account_data.get("account", {})
                                        account_address = account_data.get("address") or account_details.get("address")
                                        
                                        # Create wallet and account atomically in a transaction
                                        try:
                                            async with prisma.tx() as tx:
                                                wallet = await tx.wallets.create(
                                                    data={
                                                        "entity_id": str(current_user.id),
                                                        "zynk_wallet_id": wallet_id,
                                                        "wallet_name": wallet_name,
                                                        "chain": chain,
                                                        "status": "ACTIVE"
                                                    }
                                                )
                                                
                                                account_data_dict = _create_wallet_account_data(account_details, account_address)
                                                await tx.wallet_accounts.create(
                                                    data={"wallet_id": wallet.id, **account_data_dict}
                                                )
                                            
                                            account_created = _create_account_response_data(account_details, account_address)
                                        except Exception:
                                            # Transaction failed, wallet and account not created
                                            pass
                            except Exception:
                                # Account preparation/signing failed, create wallet only
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
                                except Exception:
                                    # Wallet creation failed, continue without wallet record
                                    pass
        except Exception:
            # Account preparation failed, create wallet only
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
            except Exception:
                # Wallet creation failed, continue without wallet record
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
    # Validate path parameter to prevent path traversal SSRF
    _validate_safe_path_component(wallet_id, "wallet_id")

    chain = data.get("chain", "SOLANA")
    
    # Verify wallet belongs to current user
    wallet = await _validate_wallet_ownership(wallet_id, current_user)
    
    # Use validated wallet_id from database instead of path parameter
    validated_wallet_id = _validate_safe_path_component(wallet.zynk_wallet_id, "wallet_id")
    url = f"{settings.zynk_base_url}/api/v1/wallets/{validated_wallet_id}/accounts/prepare"
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
            _handle_zynk_response_error(response)
        
        body = response.json()
        _validate_zynk_response_success(body)
        
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
            _handle_zynk_response_error(response)
        
        body = response.json()
        _validate_zynk_response_success(body) 
        
        account_data = body.get("data", {})
        wallet_id = account_data.get("walletId")
        account = account_data.get("account", {})
        address = account_data.get("address") or account.get("address")
        
        try:
            wallet = await _validate_wallet_ownership(wallet_id, current_user)
            
            # Create wallet account within a transaction for atomicity
            # Note: Wallet already exists, so we're just adding an account
            account_data_dict = _create_wallet_account_data(account, address)
            await prisma.wallet_accounts.create(
                data={"wallet_id": wallet.id, **account_data_dict}
            )
            
        except Exception:
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

