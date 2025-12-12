import httpx
import base64
import uuid
import io
import os
import re
from fastapi import APIRouter, Depends, HTTPException, UploadFile, Form, File, Request
from starlette.requests import Request
from slowapi import Limiter
from slowapi.util import get_remote_address
from prisma.models import entities as Entities # type: ignore
from ..core.database import prisma
from ..core import auth
from ..core.config import settings
from ..schemas.zynk import (
    ZynkEntitiesResponse,
    ZynkEntityResponse,
    ZynkKycResponse,
    ZynkKycRequirementsResponse,
    ZynkKycDocumentsResponse,
    KycUploadResponse,
)
from ..utils.errors import upstream_error, internal_error
from PIL import Image # type: ignore

limiter = Limiter(key_func=get_remote_address)

MAX_FILE_SIZE = 10 * 1024 * 1024
ALLOWED_MIME_TYPES = ['image/jpeg', 'image/png', 'image/webp']
ALLOWED_EXTENSIONS = ['.jpg', '.jpeg', '.png', '.webp']

IMAGE_SIGNATURES = {
    b'\xff\xd8\xff': 'image/jpeg',
    b'\x89\x50\x4e\x47\x0d\x0a\x1a\x0a': 'image/png',
    b'RIFF': 'image/webp',
}

router = APIRouter(prefix="/api/v1/transformer", tags=["transformer"])

def _auth_header():
    if not settings.zynk_api_key:
        raise HTTPException(status_code=500, detail="ZyncLab API key not configured")
    return {
        "x-api-token": settings.zynk_api_key,
    }

def _validate_safe_path_component(value: str, param_name: str, max_length: int = 100) -> str:
    if not value or not isinstance(value, str):
        raise HTTPException(status_code=400, detail=f"Invalid {param_name}: must be a non-empty string")
    
    value = value.strip()
    if not value:
        raise HTTPException(status_code=400, detail=f"Invalid {param_name}: cannot be empty")
    
    if len(value) > max_length:
        raise HTTPException(status_code=400, detail=f"Invalid {param_name}: exceeds maximum length of {max_length}")
    
    if not re.match(r'^[a-zA-Z0-9_-]+$', value):
        raise HTTPException(status_code=400, detail=f"Invalid {param_name}: contains invalid characters. Only alphanumeric, hyphens, and underscores are allowed")
    
    if '..' in value or '/' in value or '\\' in value:
        raise HTTPException(status_code=400, detail=f"Invalid {param_name}: path traversal characters are not allowed")
    
    return value

def _validate_email_for_path(email: str) -> str:
    if not email or not isinstance(email, str):
        raise HTTPException(status_code=400, detail="Invalid email: must be a non-empty string")
    
    email = email.strip().lower()
    if not email:
        raise HTTPException(status_code=400, detail="Invalid email: cannot be empty")
    
    if len(email) > 254:
        raise HTTPException(status_code=400, detail="Invalid email: exceeds maximum length")
    
    email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    if not re.match(email_pattern, email):
        raise HTTPException(status_code=400, detail="Invalid email format")
    
    if '..' in email or '/' in email or '\\' in email:
        raise HTTPException(status_code=400, detail="Invalid email: path traversal characters are not allowed")
    
    return email

def _validate_magic_bytes(file_content: bytes) -> str:
    if len(file_content) < 12:
        raise HTTPException(status_code=400, detail="File too small to be a valid image")
    
    if file_content[:3] == b'\xff\xd8\xff':
        return 'image/jpeg'
    
    if file_content[:8] == b'\x89\x50\x4e\x47\x0d\x0a\x1a\x0a':
        return 'image/png'
    
    if file_content[:4] == b'RIFF' and file_content[8:12] == b'WEBP':
        return 'image/webp'
    
    raise HTTPException(status_code=400, detail="Invalid file type. Only JPEG, PNG, and WebP images are allowed.")


async def _upload_to_s3(file_content: bytes, file_name: str) -> str:
    if not settings.aws_access_key_id or not settings.aws_secret_access_key or not settings.aws_region or not settings.aws_s3_bucket_name:
        raise HTTPException(status_code=500, detail="AWS S3 configuration not set")

    try:
        import boto3
        s3_client = boto3.client(
            's3',
            aws_access_key_id=settings.aws_access_key_id,
            aws_secret_access_key=settings.aws_secret_access_key,
            region_name=settings.aws_region
        )
        s3_client.put_object(Bucket=settings.aws_s3_bucket_name, Key=file_name, Body=file_content)
        url = f"https://{settings.aws_s3_bucket_name}.s3.{settings.aws_region}.amazonaws.com/{file_name}"
        
        return url
    except Exception:
        raise internal_error(
            user_message="Failed to store uploaded file. Please try again later.",
        )

async def _make_zynk_request(
    method: str,
    url: str,
    headers: dict,
    json: dict = None,
    allow_404: bool = False,
    custom_404_message: str = None,
    reject_message: str = "Verification service rejected the request. Please contact support if this continues."
) -> dict:
    for attempt in range(2):
        try:
            async with httpx.AsyncClient(timeout=settings.zynk_timeout_s) as client:
                if method.upper() == "POST":
                    resp = await client.post(url, headers=headers, json=json)
                else:
                    resp = await client.get(url, headers=headers)
        except httpx.RequestError:
            if attempt == 0:
                continue
            raise upstream_error(
                user_message="Verification service is currently unreachable. Please try again later.",
            )

        try:
            body = resp.json()
        except ValueError:
            raise upstream_error(
                user_message="Verification service returned an invalid response. Please try again later.",
            )

        if not (200 <= resp.status_code < 300):
            if allow_404 and resp.status_code == 404:
                message = custom_404_message or "Resource not found in external service."
                raise HTTPException(status_code=404, detail=message)
            raise upstream_error(
                user_message="Verification service is currently unavailable. Please try again later.",
            )

        if not isinstance(body, dict):
            raise upstream_error(
                user_message="Verification service returned an unexpected response. Please try again later.",
            )

        if body.get("success") is not True:
            error_detail = body.get("message", body.get("error", "Request was not successful"))
            if allow_404 and "not found" in error_detail.lower():
                message = custom_404_message or "Resource not found in external service."
                raise HTTPException(status_code=404, detail=message)
            raise upstream_error(
                user_message=reject_message,
            )

        return body

    raise upstream_error(
        user_message="Verification service is currently unavailable. Please try again later.",
    )

async def _create_entity_in_zynk(payload: dict) -> dict:
    url = f"{settings.zynk_base_url}/api/v1/transformer/entity/create"
    headers = {**_auth_header(), "Content-Type": "application/json"}
    return await _make_zynk_request("POST", url, headers, json=payload)

async def _submit_kyc_to_zynk(entity_id: str, routing_id: str, payload: dict) -> dict:
    validated_entity_id = _validate_safe_path_component(entity_id, "entity_id")
    validated_routing_id = _validate_safe_path_component(routing_id, "routing_id")
    url = f"{settings.zynk_base_url}/api/v1/transformer/entity/kyc/{validated_entity_id}/{validated_routing_id}"
    headers = {**_auth_header(), "Content-Type": "application/json"}
    return await _make_zynk_request("POST", url, headers, json=payload)

@router.get("/entity/entities", response_model=ZynkEntitiesResponse)
async def get_all_entities(current: Entities = Depends(auth.get_current_entity)):
    url = f"{settings.zynk_base_url}/api/v1/transformer/entity/entities"
    headers = {**_auth_header(), "Accept": "application/json"}
    
    body = await _make_zynk_request("GET", url, headers)
    
    data = body.get("data")
    if data is None or "entities" not in data or "paginationData" not in data or "message" not in data:
        raise HTTPException(status_code=502, detail="Upstream service did not provide the expected data structure")

    return body

@router.get("/entity/{entity_id}", response_model=ZynkEntityResponse)
async def get_entity_by_id(
    entity_id: str,
    current: Entities = Depends(auth.get_current_entity)
):
    _validate_safe_path_component(entity_id, "entity_id")
    
    if not current.zynk_entity_id:
        raise HTTPException(status_code=404, detail="Entity not linked to external service. Please complete the entity creation process.")

    if current.zynk_entity_id != entity_id:
        raise HTTPException(status_code=403, detail="Access denied. You can only access your own entity data.")

    validated_entity_id = _validate_safe_path_component(current.zynk_entity_id, "entity_id")
    url = f"{settings.zynk_base_url}/api/v1/transformer/entity/{validated_entity_id}"
    headers = {**_auth_header(), "Accept": "application/json"}

    body = await _make_zynk_request("GET", url, headers, allow_404=True, custom_404_message="Entity not found in external service.")

    data = body.get("data")
    if data is None or "entity" not in data:
        raise upstream_error(
            user_message="Verification service returned an unexpected response. Please try again later.",
        )

    entity = data["entity"]
    required_fields = ["entityId", "type", "firstName", "lastName", "email"]
    for field in required_fields:
        if field not in entity:
            raise upstream_error(
                user_message="Verification service returned an unexpected response. Please try again later.",
            )

    return body

@router.post("/entity/kyc/{entity_id}/{routing_id}", response_model=KycUploadResponse)
@limiter.limit("30/minute")
async def upload_kyc_documents(
    request: Request,
    entity_id: str,
    routing_id: str,
    file: UploadFile = File(...),
    transactionHash: str = Form(None),
    base64Signature: str = Form(None),
    full_name: str = Form(None),
    date_of_birth: str = Form(None),
    current: Entities = Depends(auth.get_current_entity)
):
    _validate_safe_path_component(entity_id, "entity_id")
    _validate_safe_path_component(routing_id, "routing_id")
    
    if not current.zynk_entity_id:
        raise HTTPException(status_code=404, detail="Entity not linked to external service. Please complete the entity creation process.")

    if current.zynk_entity_id != entity_id:
        raise HTTPException(status_code=403, detail="Access denied. You can only upload KYC documents for your own entity.")
    
    validated_entity_id = _validate_safe_path_component(current.zynk_entity_id, "entity_id")
    validated_routing_id = _validate_safe_path_component(routing_id, "routing_id")

    file_content = await file.read()
    
    if len(file_content) > MAX_FILE_SIZE:
        raise HTTPException(
            status_code=413, 
            detail=f"File too large. Maximum size is {MAX_FILE_SIZE / (1024 * 1024):.0f}MB"
        )
    
    detected_mime_type = _validate_magic_bytes(file_content)
    if detected_mime_type not in ALLOWED_MIME_TYPES:
        raise HTTPException(status_code=400, detail="Invalid file type. Only JPEG, PNG, and WebP images are allowed.")
    
    try:
        img = Image.open(io.BytesIO(file_content))
        img.verify()
        img = Image.open(io.BytesIO(file_content))
        if img.format not in ['JPEG', 'PNG', 'WEBP']:
            raise HTTPException(status_code=400, detail=f"Unsupported image format: {img.format}")
    except Exception:
        raise HTTPException(status_code=400, detail="Corrupted or invalid image file")
    
    if file.filename:
        safe_filename = os.path.basename(file.filename)
        safe_extension = os.path.splitext(safe_filename)[1].lower()
    else:
        safe_extension = '.jpg'
    
    extension_map = {
        'image/jpeg': ['.jpg', '.jpeg'],
        'image/png': ['.png'],
        'image/webp': ['.webp']
    }
    if safe_extension not in extension_map.get(detected_mime_type, []):
        if detected_mime_type == 'image/jpeg':
            safe_extension = '.jpg'
        elif detected_mime_type == 'image/png':
            safe_extension = '.png'
        elif detected_mime_type == 'image/webp':
            safe_extension = '.webp'
    
    if safe_extension not in ALLOWED_EXTENSIONS:
        raise HTTPException(status_code=400, detail="Invalid file extension")
    
    secure_filename = f"kyc-{validated_entity_id}-{uuid.uuid4()}{safe_extension}"

    s3_url = await _upload_to_s3(file_content, secure_filename)

    base64_document = base64.b64encode(file_content).decode('utf-8')

    payload = {}
    if transactionHash:
        payload['transactionHash'] = transactionHash
        if base64Signature:
            payload['base64Signature'] = base64Signature
        else:
            raise HTTPException(status_code=400, detail="base64Signature is required when transactionHash is provided.")

    personal_details = {}
    if full_name:
        personal_details['full_name'] = full_name
    if date_of_birth:
        personal_details['date_of_birth'] = date_of_birth
    personal_details['identity_document_url'] = s3_url
    personal_details['identity_document'] = f"data:{detected_mime_type};base64,{base64_document}"
    payload['personal_details'] = personal_details

    zynk_response = await _submit_kyc_to_zynk(validated_entity_id, validated_routing_id, payload)

    return KycUploadResponse(
        success=True,
        message="KYC documents uploaded and submitted successfully.",
        data=zynk_response
    )

@router.get("/entity/kyc/{entity_id}", response_model=ZynkKycResponse)
@limiter.limit("30/minute")
async def get_entity_kyc_status(
    request: Request,
    entity_id: str,
    current: Entities = Depends(auth.get_current_entity)
):
    _validate_safe_path_component(entity_id, "entity_id")
    
    zynk_entity_id = getattr(current, "zynk_entity_id", None) or getattr(current, "external_entity_id", None)
    if not zynk_entity_id:
        raise HTTPException(status_code=404, detail="Entity not linked to external service. Please complete the entity creation process.")

    if zynk_entity_id != entity_id:
        raise HTTPException(status_code=403, detail="Access denied. You can only access your own KYC data.")

    validated_entity_id = _validate_safe_path_component(zynk_entity_id, "entity_id")
    url = f"{settings.zynk_base_url}/api/v1/transformer/entity/kyc/{validated_entity_id}"
    headers = {**_auth_header(), "Accept": "application/json"}

    body = await _make_zynk_request("GET", url, headers, allow_404=True, custom_404_message="KYC data not found for the entity in external service.", reject_message="Verification service rejected the request. Please try again later.")

    data = body.get("data")
    if data is None or "status" not in data:
        raise HTTPException(status_code=502, detail="Upstream service did not provide the expected data structure")

    status = data["status"]
    if not isinstance(status, list):
        raise HTTPException(status_code=502, detail="Upstream service response 'status' must be a list")
    if not status:
        raise HTTPException(status_code=502, detail="Upstream service response 'status' list is empty")

    return body

@router.get("/entity/kyc/requirements/{entity_id}/{routing_id}", response_model=ZynkKycRequirementsResponse)
@limiter.limit("30/minute")
async def get_entity_kyc_requirements(
    request: Request,
    entity_id: str,
    routing_id: str,
    current: Entities = Depends(auth.get_current_entity)
):
    _validate_safe_path_component(entity_id, "entity_id")
    _validate_safe_path_component(routing_id, "routing_id")
    
    if not current.zynk_entity_id:
        raise HTTPException(status_code=404, detail="Entity not linked to external service. Please complete the entity creation process.")

    if current.zynk_entity_id != entity_id:
        raise HTTPException(status_code=403, detail="Access denied. You can only access your own KYC requirements.")

    validated_entity_id = _validate_safe_path_component(current.zynk_entity_id, "entity_id")
    validated_routing_id = _validate_safe_path_component(routing_id, "routing_id")
    url = f"{settings.zynk_base_url}/api/v1/transformer/entity/kyc/requirements/{validated_entity_id}/{validated_routing_id}"
    headers = {**_auth_header(), "Accept": "application/json"}

    body = await _make_zynk_request("GET", url, headers, allow_404=True, custom_404_message="KYC requirements not found for the entity and routing ID in external service.")

    data = body.get("data")
    if data is None or "kycRequirements" not in data or "message" not in data:
        raise HTTPException(status_code=502, detail="Upstream service did not provide the expected data structure")

    kyc_requirements = data["kycRequirements"]
    if not isinstance(kyc_requirements, list):
        raise HTTPException(status_code=502, detail="Upstream service response 'kycRequirements' must be a list")

    return body

@router.get("/entity/{entity_id}/kyc/documents", response_model=ZynkKycDocumentsResponse)
@limiter.limit("30/minute")
async def get_entity_kyc_documents(
    request: Request,
    entity_id: str,
    current: Entities = Depends(auth.get_current_entity)
):
    _validate_safe_path_component(entity_id, "entity_id")
    
    if not current.zynk_entity_id:
        raise HTTPException(status_code=404, detail="Entity not linked to external service. Please complete the entity creation process.")

    if current.zynk_entity_id != entity_id:
        raise HTTPException(status_code=403, detail="Access denied. You can only access your own KYC documents.")

    validated_entity_id = _validate_safe_path_component(current.zynk_entity_id, "entity_id")
    url = f"{settings.zynk_base_url}/api/v1/transformer/entity/{validated_entity_id}/kyc/documents"
    headers = {**_auth_header(), "Accept": "application/json"}

    body = await _make_zynk_request("GET", url, headers, allow_404=True, custom_404_message="KYC documents not found for the entity in external service.")

    data = body.get("data")
    if data is None:
        raise HTTPException(status_code=502, detail="Upstream service did not provide the expected data structure")

    return body

@router.get("/entity/email/{email}", response_model=ZynkEntityResponse)
async def get_entity_by_email(
    email: str,
    current: Entities = Depends(auth.get_current_entity)
):
    validated_email = _validate_email_for_path(email)
    
    if current.email != validated_email:
        raise HTTPException(status_code=403, detail="Access denied. You can only access your own entity data.")

    if not current.zynk_entity_id:
        raise HTTPException(status_code=404, detail="Entity not linked to external service. Please complete the entity creation process.")

    safe_email = _validate_email_for_path(current.email)
    url = f"{settings.zynk_base_url}/api/v1/transformer/entity/email/{safe_email}"
    headers = {**_auth_header(), "Accept": "application/json"}

    body = await _make_zynk_request("GET", url, headers, allow_404=True, custom_404_message="Entity not found in external service.")

    data = body.get("data")
    if data is None or "entity" not in data:
        raise upstream_error(
            user_message="Verification service did not provide the expected data structure. Please try again later.",
        )

    entity = data["entity"]
    required_fields = ["entityId", "type", "firstName", "lastName", "email"]
    for field in required_fields:
        if field not in entity:
            raise upstream_error(
                user_message="Verification service response is incomplete. Please try again later.",
            )

    return body
