import httpx
import base64
import uuid
import io
import os
import logging
import re
from typing import Optional, Dict
from fastapi import APIRouter, Depends, HTTPException, UploadFile, Form, File, Request
from slowapi import Limiter
from slowapi.util import get_remote_address
from prisma.models import entities as Entities
from ..core.database import prisma
from ..core import auth
from ..core.config import settings
from ..schemas.zynk import (
    ZynkEntitiesResponse,
    ZynkEntityResponse,
    ZynkKycResponse,
    ZynkKycRequirementsResponse,
    ZynkKycDocumentsResponse,
    KycDocumentUpload,
    KycUploadResponse,
)
from ..utils.errors import upstream_error, internal_error
from PIL import Image

logger = logging.getLogger(__name__)

# FIXED: HIGH-04 - Rate limiter for preventing resource exhaustion attacks
limiter = Limiter(key_func=get_remote_address)

# FIXED: HIGH-05 - File upload validation constants
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB

# MIME type constants
MIME_TYPE_JPEG = "image/jpeg"
MIME_TYPE_PNG = "image/png"
MIME_TYPE_WEBP = "image/webp"

# Extension constants
EXT_JPG = ".jpg"
EXT_JPEG = ".jpeg"
EXT_PNG = ".png"
EXT_WEBP = ".webp"

ALLOWED_MIME_TYPES = [MIME_TYPE_JPEG, MIME_TYPE_PNG, MIME_TYPE_WEBP]
ALLOWED_EXTENSIONS = [EXT_JPG, EXT_JPEG, EXT_PNG, EXT_WEBP]

# Magic bytes (file signatures) for image validation
IMAGE_SIGNATURES = {
    b'\xff\xd8\xff': MIME_TYPE_JPEG,  # JPEG
    b'\x89\x50\x4e\x47\x0d\x0a\x1a\x0a': MIME_TYPE_PNG,  # PNG
    b'RIFF': MIME_TYPE_WEBP,  # WebP (starts with RIFF, but we check more specifically)
}

# Error message constants
ERR_VERIFICATION_UNREACHABLE = "Verification service is currently unreachable. Please try again later."
ERR_VERIFICATION_INVALID_RESPONSE = "Verification service returned an invalid response. Please try again later."
ERR_VERIFICATION_UNAVAILABLE = "Verification service is currently unavailable. Please try again later."
ERR_VERIFICATION_UNEXPECTED = "Verification service returned an unexpected response. Please try again later."
ERR_REQUEST_NOT_SUCCESSFUL = "Request was not successful"
ERR_VERIFICATION_REJECTED = "Verification service rejected the request. Please contact support if this continues."
ERR_VERIFICATION_REJECTED_RETRY = "Verification service rejected the request. Please try again later."
ERR_ENTITY_NOT_LINKED = "Entity not linked to external service. Please complete the entity creation process."
ERR_ENTITY_NOT_FOUND = "Entity not found in external service."
ERR_NOT_FOUND = "not found"
ERR_UPSTREAM_DATA_STRUCTURE = "Upstream service did not provide the expected data structure"

# Content type constants
CONTENT_TYPE_JSON = "application/json"

router = APIRouter(prefix="/api/v1/transformer", tags=["transformer"])

def _auth_header():
    """
    Generate authentication header for ZyncLab API.
    """
    if not settings.zynk_api_key:
        raise HTTPException(status_code=500, detail="ZyncLab API key not configured")
    return {
        "x-api-token": settings.zynk_api_key,
    }

def _validate_magic_bytes(file_content: bytes) -> str:
    """
    Validate file by checking magic bytes (file signature).
    Returns the detected MIME type or raises HTTPException.
    """
    if len(file_content) < 12:
        raise HTTPException(status_code=400, detail="File too small to be a valid image")
    
    # Check JPEG signature (FF D8 FF)
    if file_content[:3] == b'\xff\xd8\xff':
        return MIME_TYPE_JPEG
    
    # Check PNG signature (89 50 4E 47 0D 0A 1A 0A)
    if file_content[:8] == b'\x89\x50\x4e\x47\x0d\x0a\x1a\x0a':
        return MIME_TYPE_PNG
    
    # Check WebP signature (RIFF...WEBP)
    if file_content[:4] == b'RIFF' and file_content[8:12] == b'WEBP':
        return MIME_TYPE_WEBP
    
    raise HTTPException(status_code=400, detail="Invalid file type. Only JPEG, PNG, and WebP images are allowed.")


def _upload_to_s3(file_content: bytes, file_name: str) -> str:
    """
    Upload file content to S3 and return the URL.
    Updated to accept bytes instead of UploadFile for better security.
    """
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
    except Exception as e:
        # MED-02: Do not leak internal S3 error details to clients
        raise internal_error(
            log_message=f"[S3] Failed to upload file '{file_name}' to S3: {e}",
            user_message="Failed to store uploaded file. Please try again later.",
        )

async def _create_entity_in_zynk(payload: dict) -> dict:
    """
    Create an entity in ZynkLabs API.
    """
    url = f"{settings.zynk_base_url}/api/v1/transformer/entity/create"
    headers = {**_auth_header(), "Content-Type": CONTENT_TYPE_JSON}
    context = "while creating entity"
    return await _make_zynk_request("POST", url, headers, payload, context)

def _validate_response_status(resp: httpx.Response, body: dict, url: str, context: str, handle_404: bool, not_found_message: Optional[str]) -> None:
    """Validate HTTP response status code."""
    if not (200 <= resp.status_code < 300):
        error_detail = body.get("message", body.get("error", f"HTTP {resp.status_code}: Unknown upstream error"))
        if handle_404 and resp.status_code == 404:
            raise HTTPException(status_code=404, detail=not_found_message or ERR_ENTITY_NOT_FOUND)
        raise upstream_error(
            log_message=f"[ZYNK] Upstream error {resp.status_code} {context} at {url}: {error_detail}",
            user_message=ERR_VERIFICATION_UNAVAILABLE,
        )


def _validate_response_body(body: dict, url: str, context: str, handle_404: bool, not_found_message: Optional[str]) -> None:
    """Validate response body structure and success status."""
    if not isinstance(body, dict):
        raise upstream_error(
            log_message=f"[ZYNK] Unexpected response structure {context} at {url}: {body}",
            user_message=ERR_VERIFICATION_UNEXPECTED,
        )

    if body.get("success") is not True:
        error_detail = body.get("message", body.get("error", ERR_REQUEST_NOT_SUCCESSFUL))
        if handle_404 and ERR_NOT_FOUND in error_detail.lower():
            raise HTTPException(status_code=404, detail=not_found_message or ERR_ENTITY_NOT_FOUND)
        raise upstream_error(
            log_message=f"[ZYNK] Request rejected {context} at {url}: {error_detail}",
            user_message=ERR_VERIFICATION_REJECTED,
        )


async def _make_zynk_request(
    method: str,
    url: str,
    headers: Dict[str, str],
    json_payload: Optional[Dict] = None,
    context: str = "",
    handle_404: bool = False,
    not_found_message: Optional[str] = None,
) -> Dict:
    """
    Make a request to Zynk API with retry logic and response validation.
    Returns the response body as dict.
    """
    for attempt in range(2):  # 1 retry
        try:
            async with httpx.AsyncClient(timeout=settings.zynk_timeout_s) as client:
                if method.upper() == "GET":
                    resp = await client.get(url, headers=headers)
                else:
                    resp = await client.post(url, headers=headers, json=json_payload)
        except httpx.RequestError as exc:
            if attempt == 0:
                continue
            raise upstream_error(
                log_message=f"[ZYNK] Request error {context} at {url}: {exc}",
                user_message=ERR_VERIFICATION_UNREACHABLE,
            )

        try:
            body = resp.json()
        except ValueError:
            raise upstream_error(
                log_message=f"[ZYNK] Invalid JSON {context} at {url}. Response preview: {resp.text[:200]}",
                user_message=ERR_VERIFICATION_INVALID_RESPONSE,
            )

        _validate_response_status(resp, body, url, context, handle_404, not_found_message)
        _validate_response_body(body, url, context, handle_404, not_found_message)

        return body

    raise upstream_error(
        log_message=f"[ZYNK] Failed {context} at {url} after multiple attempts",
        user_message=ERR_VERIFICATION_UNAVAILABLE,
    )


def _validate_path_parameter(param: str, param_name: str) -> None:
    """
    Validate path parameter to prevent path traversal and injection attacks.
    Only allows alphanumeric characters, hyphens, and underscores (UUID format).
    """
    if not param or not isinstance(param, str):
        raise HTTPException(status_code=400, detail=f"Invalid {param_name}: must be a non-empty string")
    # Allow UUID format: alphanumeric, hyphens, underscores
    if not re.match(r'^[a-zA-Z0-9_-]+$', param):
        raise HTTPException(status_code=400, detail=f"Invalid {param_name}: contains invalid characters")


def _validate_entities_response(body: Dict) -> None:
    """Validate entities response has required fields."""
    data = body.get("data")
    if data is None or "entities" not in data or "paginationData" not in data or "message" not in data:
        raise HTTPException(status_code=502, detail=ERR_UPSTREAM_DATA_STRUCTURE)


async def _submit_kyc_to_zynk(entity_id: str, routing_id: str, payload: dict) -> dict:
    """
    Submit KYC documents to ZynkLabs API.
    """
    # SECURITY: Validate path parameters before constructing URL
    _validate_path_parameter(entity_id, "entity_id")
    _validate_path_parameter(routing_id, "routing_id")
    
    url = f"{settings.zynk_base_url}/api/v1/transformer/entity/kyc/{entity_id}/{routing_id}"
    headers = {**_auth_header(), "Content-Type": CONTENT_TYPE_JSON}
    context = f"while submitting KYC for entity {entity_id} routing {routing_id}"
    return await _make_zynk_request("POST", url, headers, payload, context)


@router.get("/entity/entities", response_model=ZynkEntitiesResponse)
async def get_all_entities(current: Entities = Depends(auth.get_current_entity)):
    """
    Fetch all entities from ZyncLab via their API.
    Requires authentication to ensure secure access in the banking system.
    """
    url = f"{settings.zynk_base_url}/api/v1/transformer/entity/entities"
    headers = {**_auth_header(), "Accept": CONTENT_TYPE_JSON}
    context = "while fetching entities"
    body = await _make_zynk_request("GET", url, headers, None, context)
    _validate_entities_response(body)
    return body

@router.get("/entity/{entity_id}", response_model=ZynkEntityResponse)
async def get_entity_by_id(
    entity_id: str,
    current: Entities = Depends(auth.get_current_entity)
):
    """
    Fetch a single entity by ID from ZyncLab via their API.
    Ensures that users can only access their own entity data for security.
    Requires authentication and ownership validation in the banking system.
    """
    # Ensure the entity has an zynk_entity_id set (means it's linked to ZyncLab)
    if not current.zynk_entity_id:
        raise HTTPException(status_code=404, detail=ERR_ENTITY_NOT_LINKED)

    # SECURITY: Validate path parameter before using
    _validate_path_parameter(entity_id, "entity_id")
    
    # FIXED: HIGH-02 - BOLA Protection: Explicit ownership validation
    # Security check: Ensure the requested entity belongs to the authenticated user
    # Prevents Broken Object Level Authorization (OWASP API #1 risk)
    if current.zynk_entity_id != entity_id:
        raise HTTPException(status_code=403, detail="Access denied. You can only access your own entity data.")

    # SECURITY: Use validated zynk_entity_id from authenticated user, not user-provided entity_id
    _validate_path_parameter(current.zynk_entity_id, "zynk_entity_id")
    url = f"{settings.zynk_base_url}/api/v1/transformer/entity/{current.zynk_entity_id}"
    headers = {**_auth_header(), "Accept": CONTENT_TYPE_JSON}

    # Make the request to ZyncLab with retry logic
    for attempt in range(2):  # 1 retry
        try:
            async with httpx.AsyncClient(timeout=settings.zynk_timeout_s) as client:
                resp = await client.get(url, headers=headers)
        except httpx.RequestError as exc:
            if attempt == 0:
                continue
            raise upstream_error(
                log_message=f"[ZYNK] Request error while fetching entity {entity_id} at {url}: {exc}",
                user_message=ERR_VERIFICATION_UNREACHABLE,
            )

        try:
            body = resp.json()
        except ValueError:
            raise upstream_error(
                log_message=f"[ZYNK] Invalid JSON while fetching entity {entity_id} at {url}. Response preview: {resp.text[:200]}",
                user_message=ERR_VERIFICATION_INVALID_RESPONSE,
            )

        if not (200 <= resp.status_code < 300):
            error_detail = body.get("message", body.get("error", f"HTTP {resp.status_code}: Unknown upstream error"))
            if resp.status_code == 404:
                # 404 is safe and meaningful to expose
                raise HTTPException(status_code=404, detail=ERR_ENTITY_NOT_FOUND)
            raise upstream_error(
                log_message=f"[ZYNK] Upstream error {resp.status_code} while fetching entity {entity_id} at {url}: {error_detail}",
                user_message=ERR_VERIFICATION_UNAVAILABLE,
            )

        if not isinstance(body, dict):
            raise upstream_error(
                log_message=f"[ZYNK] Unexpected response structure while fetching entity {entity_id} at {url}: {body}",
                user_message=ERR_VERIFICATION_UNEXPECTED,
            )

        if body.get("success") is not True:
            error_detail = body.get("message", body.get("error", ERR_REQUEST_NOT_SUCCESSFUL))
            # Preserve 404 semantics for "not found" without leaking upstream body
            if ERR_NOT_FOUND in error_detail.lower():
                raise HTTPException(status_code=404, detail=ERR_ENTITY_NOT_FOUND)
            raise upstream_error(
                log_message=f"[ZYNK] Fetch entity {entity_id} rejected by upstream at {url}: {error_detail}",
                user_message=ERR_VERIFICATION_REJECTED,
            )

        # Validate that data exists for the response schema
        data = body.get("data")
        if data is None or "entity" not in data:
            raise upstream_error(
                log_message=f"[ZYNK] Missing 'entity' in upstream response while fetching entity {entity_id} at {url}: {body}",
                user_message=ERR_VERIFICATION_UNEXPECTED,
            )

        # Additional validation to ensure entity contains essential fields
        entity = data["entity"]
        required_fields = ["entityId", "type", "firstName", "lastName", "email"]
        for field in required_fields:
            if field not in entity:
                raise upstream_error(
                    log_message=f"[ZYNK] Missing required field '{field}' in entity response for {entity_id} at {url}: {entity}",
                    user_message=ERR_VERIFICATION_UNEXPECTED,
                )

        # Return the upstream response as it matches our schema
        return body

    raise upstream_error(
        log_message=f"[ZYNK] Failed to fetch entity {entity_id} at {url} after multiple attempts",
        user_message=ERR_VERIFICATION_UNAVAILABLE,
    )

@router.post("/entity/kyc/{entity_id}/{routing_id}", response_model=KycUploadResponse)
@limiter.limit("30/minute")  # FIXED: HIGH-04 - Rate limit to prevent KYC resource exhaustion
async def upload_kyc_documents(
    entity_id: str,
    routing_id: str,
    file: UploadFile = File(...),
    transaction_hash: str = Form(None),
    base64_signature: str = Form(None),
    full_name: str = Form(None),
    date_of_birth: str = Form(None),
    current: Entities = Depends(auth.get_current_entity),
    request: Request = None
):
    """
    Upload KYC documents to S3 and submit to ZynkLabs API.
    Requires authentication and ownership validation for security.
    """
    # SECURITY: Validate path parameters before using
    _validate_path_parameter(entity_id, "entity_id")
    _validate_path_parameter(routing_id, "routing_id")
    
    # Ensure the entity has an zynk_entity_id set
    if not current.zynk_entity_id:
        raise HTTPException(status_code=404, detail=ERR_ENTITY_NOT_LINKED)

    # FIXED: HIGH-02 - BOLA Protection: Explicit ownership validation
    # Security check: Ensure the requested entity belongs to the authenticated user
    # Prevents Broken Object Level Authorization (OWASP API #1 risk)
    if current.zynk_entity_id != entity_id:
        raise HTTPException(status_code=403, detail="Access denied. You can only upload KYC documents for your own entity.")

    # FIXED: HIGH-05 - Comprehensive file upload validation
    # 1. Read file content first (needed for all validations)
    file_content = await file.read()
    
    # 2. Check file size
    if len(file_content) > MAX_FILE_SIZE:
        raise HTTPException(
            status_code=413, 
            detail=f"File too large. Maximum size is {MAX_FILE_SIZE / (1024 * 1024):.0f}MB"
        )
    
    # 3. Validate magic bytes (file signature) - prevents Content-Type spoofing
    detected_mime_type = _validate_magic_bytes(file_content)
    if detected_mime_type not in ALLOWED_MIME_TYPES:
        logger.warning(f"[KYC] Rejected file with detected MIME type: {detected_mime_type}")
        raise HTTPException(status_code=400, detail="Invalid file type. Only JPEG, PNG, and WebP images are allowed.")
    
    # 4. Validate with PIL (ensures it's a real, valid image)
    try:
        img = Image.open(io.BytesIO(file_content))
        img.verify()  # Verify it's a valid image (doesn't load into memory)
        # Reopen after verify (verify() closes the image)
        img = Image.open(io.BytesIO(file_content))
        # Additional check: ensure it's a supported format
        if img.format not in ['JPEG', 'PNG', 'WEBP']:
            raise HTTPException(status_code=400, detail=f"Unsupported image format: {img.format}")
    except Exception as e:
        logger.warning(f"[KYC] PIL verification failed: {e}")
        raise HTTPException(status_code=400, detail="Corrupted or invalid image file")
    
    # 5. Sanitize filename (remove path traversal attempts)
    if file.filename:
        # Extract extension from original filename (basename prevents path traversal)
        safe_filename = os.path.basename(file.filename)
        safe_extension = os.path.splitext(safe_filename)[1].lower()
    else:
        # Default to .jpg if no filename provided
        safe_extension = '.jpg'
    
    # Validate extension matches detected type
    extension_map = {
        MIME_TYPE_JPEG: [EXT_JPG, EXT_JPEG],
        MIME_TYPE_PNG: [EXT_PNG],
        MIME_TYPE_WEBP: [EXT_WEBP]
    }
    if safe_extension not in extension_map.get(detected_mime_type, []):
        # Use extension based on detected MIME type
        if detected_mime_type == MIME_TYPE_JPEG:
            safe_extension = EXT_JPG
        elif detected_mime_type == MIME_TYPE_PNG:
            safe_extension = EXT_PNG
        elif detected_mime_type == MIME_TYPE_WEBP:
            safe_extension = EXT_WEBP
    
    if safe_extension not in ALLOWED_EXTENSIONS:
        raise HTTPException(status_code=400, detail="Invalid file extension")
    
    # 6. Generate secure random filename (no user input in filename)
    secure_filename = f"kyc-{entity_id}-{uuid.uuid4()}{safe_extension}"
    
    # 7. Upload to S3 with validated file content
    s3_url = _upload_to_s3(file_content, secure_filename)
    
    # 8. Encode file to base64 for ZynkLabs (using detected MIME type, not client-provided)
    base64_document = base64.b64encode(file_content).decode('utf-8')

    # Construct payload
    payload = {}
    if transaction_hash:
        payload['transactionHash'] = transaction_hash
        if base64_signature:
            payload['base64Signature'] = base64_signature
        else:
            raise HTTPException(status_code=400, detail="base64Signature is required when transactionHash is provided.")

    personal_details = {}
    if full_name:
        personal_details['full_name'] = full_name
    if date_of_birth:
        personal_details['date_of_birth'] = date_of_birth
    personal_details['identity_document_url'] = s3_url
    # Use detected MIME type instead of client-provided content_type for security
    personal_details['identity_document'] = f"data:{detected_mime_type};base64,{base64_document}"
    payload['personal_details'] = personal_details

    # Submit to ZynkLabs
    zynk_response = await _submit_kyc_to_zynk(entity_id, routing_id, payload)

    # Return success response
    return KycUploadResponse(
        success=True,
        message="KYC documents uploaded and submitted successfully.",
        data=zynk_response
    )

@router.get("/entity/kyc/{entity_id}", response_model=ZynkKycResponse)
@limiter.limit("30/minute")  # FIXED: HIGH-04 - Rate limit to prevent KYC resource exhaustion
async def get_entity_kyc_status(
    entity_id: str,
    current: Entities = Depends(auth.get_current_entity),
    request: Request = None
):
    """
    Fetch KYC status for a specific entity from ZyncLab via their API.
    Ensures that users can only access their own KYC data for security.
    Requires authentication and ownership validation in the banking system.
    """
    # Ensure the entity has a zynk_entity_id set (means it's linked to ZyncLab)
    # Try both possible attribute names for compatibility
    zynk_entity_id = getattr(current, "zynk_entity_id", None) or getattr(current, "external_entity_id", None)
    if not zynk_entity_id:
        raise HTTPException(status_code=404, detail=ERR_ENTITY_NOT_LINKED)

    # FIXED: HIGH-02 - BOLA Protection: Explicit ownership validation
    # Security check: Ensure the requested entity belongs to the authenticated user
    # Prevents Broken Object Level Authorization (OWASP API #1 risk)
    if zynk_entity_id != entity_id:
        raise HTTPException(status_code=403, detail="Access denied. You can only access your own KYC data.")

    # Construct the URL using the zynk_entity_id for the upstream call
    url = f"{settings.zynk_base_url}/api/v1/transformer/entity/kyc/{zynk_entity_id}"
    headers = {**_auth_header(), "Accept": CONTENT_TYPE_JSON}

    # Make the request to ZyncLab with retry logic
    for attempt in range(2):  # 1 retry
        try:
            async with httpx.AsyncClient(timeout=settings.zynk_timeout_s) as client:
                resp = await client.get(url, headers=headers)
        except httpx.RequestError as exc:
            if attempt == 0:
                continue
            raise upstream_error(
                log_message=f"[ZYNK] Request error while fetching KYC status for entity {entity_id} at {url}: {exc}",
                user_message=ERR_VERIFICATION_UNREACHABLE,
            )

        try:
            body = resp.json()
        except ValueError:
            raise upstream_error(
                log_message=f"[ZYNK] Invalid JSON while fetching KYC status for entity {entity_id} at {url}. Response preview: {resp.text[:200]}",
                user_message=ERR_VERIFICATION_INVALID_RESPONSE,
            )

        if not (200 <= resp.status_code < 300):
            error_detail = body.get("message", body.get("error", f"HTTP {resp.status_code}: Unknown upstream error"))
            if resp.status_code == 404:
                raise HTTPException(status_code=404, detail="KYC data not found for the entity in external service.")
            raise upstream_error(
                log_message=f"[ZYNK] Upstream error {resp.status_code} while fetching KYC status for entity {entity_id} at {url}: {error_detail}",
                user_message=ERR_VERIFICATION_UNAVAILABLE,
            )

        if not isinstance(body, dict):
            raise upstream_error(
                log_message=f"[ZYNK] Unexpected response structure while fetching KYC status for entity {entity_id} at {url}",
                user_message=ERR_VERIFICATION_UNEXPECTED,
            )

        if body.get("success") is not True:
            error_detail = body.get("message", body.get("error", ERR_REQUEST_NOT_SUCCESSFUL))
            if ERR_NOT_FOUND in error_detail.lower():
                raise HTTPException(status_code=404, detail="KYC data not found for the entity in external service.")
            raise upstream_error(
                log_message=f"[ZYNK] Upstream rejected request while fetching KYC status for entity {entity_id} at {url}: {error_detail}",
                user_message=ERR_VERIFICATION_REJECTED_RETRY,
            )

        # Validate that data exists for the response schema
        data = body.get("data")
        if data is None or "status" not in data:
            raise HTTPException(status_code=502, detail=ERR_UPSTREAM_DATA_STRUCTURE)

        # Additional validation to ensure status is a list and contains items
        status = data["status"]
        if not isinstance(status, list):
            raise HTTPException(status_code=502, detail="Upstream service response 'status' must be a list")
        if not status:
            raise HTTPException(status_code=502, detail="Upstream service response 'status' list is empty")

        # Return the upstream response as it matches our schema
        return body

    raise upstream_error(
        log_message=f"[ZYNK] Failed to fetch KYC status for entity {entity_id} at {url} after multiple attempts",
        user_message=ERR_VERIFICATION_UNAVAILABLE,
    )

@router.get("/entity/kyc/requirements/{entity_id}/{routing_id}", response_model=ZynkKycRequirementsResponse)
@limiter.limit("30/minute")  # FIXED: HIGH-04 - Rate limit to prevent KYC resource exhaustion
async def get_entity_kyc_requirements(
    entity_id: str,
    routing_id: str,
    current: Entities = Depends(auth.get_current_entity),
    request: Request = None
):
    """
    Fetch KYC requirements for a specific entity and routing ID from ZyncLab via their API.
    Ensures that users can only access their own KYC requirements for security.
    Requires authentication and ownership validation in the banking system.
    """
    # Ensure the entity has an zynk_entity_id set (means it's linked to ZyncLab)
    if not current.zynk_entity_id:
        raise HTTPException(status_code=404, detail=ERR_ENTITY_NOT_LINKED)

    # SECURITY: Validate path parameters before using in URL
    _validate_path_parameter(entity_id, "entity_id")
    _validate_path_parameter(routing_id, "routing_id")
    
    # FIXED: HIGH-02 - BOLA Protection: Explicit ownership validation
    # Security check: Ensure the requested entity belongs to the authenticated user
    # Prevents Broken Object Level Authorization (OWASP API #1 risk)
    if current.zynk_entity_id != entity_id:
        raise HTTPException(status_code=403, detail="Access denied. You can only access your own KYC requirements.")

    # SECURITY: Use validated zynk_entity_id from authenticated user, validate routing_id
    _validate_path_parameter(current.zynk_entity_id, "zynk_entity_id")
    url = f"{settings.zynk_base_url}/api/v1/transformer/entity/kyc/requirements/{current.zynk_entity_id}/{routing_id}"
    headers = {**_auth_header(), "Accept": CONTENT_TYPE_JSON}

    # Make the request to ZyncLab with retry logic
    for attempt in range(2):  # 1 retry
        try:
            async with httpx.AsyncClient(timeout=settings.zynk_timeout_s) as client:
                resp = await client.get(url, headers=headers)
        except httpx.RequestError as exc:
            if attempt == 0:
                continue
            raise upstream_error(
                log_message=f"[ZYNK] Request error while fetching KYC requirements for entity {entity_id} routing {routing_id} at {url}: {exc}",
                user_message=ERR_VERIFICATION_UNREACHABLE,
            )

        try:
            body = resp.json()
        except ValueError:
            raise upstream_error(
                log_message=f"[ZYNK] Invalid JSON while fetching KYC requirements for entity {entity_id} routing {routing_id} at {url}. Response preview: {resp.text[:200]}",
                user_message=ERR_VERIFICATION_INVALID_RESPONSE,
            )

        if not (200 <= resp.status_code < 300):
            error_detail = body.get("message", body.get("error", f"HTTP {resp.status_code}: Unknown upstream error"))
            if resp.status_code == 404:
                raise HTTPException(status_code=404, detail="KYC requirements not found for the entity and routing ID in external service.")
            raise upstream_error(
                log_message=f"[ZYNK] Upstream error {resp.status_code} while fetching KYC requirements for entity {entity_id} routing {routing_id} at {url}: {error_detail}",
                user_message=ERR_VERIFICATION_UNAVAILABLE,
            )

        if not isinstance(body, dict):
            raise upstream_error(
                log_message=f"[ZYNK] Unexpected response structure while fetching KYC requirements for entity {entity_id} routing {routing_id} at {url}",
                user_message=ERR_VERIFICATION_UNEXPECTED,
            )

        if body.get("success") is not True:
            error_detail = body.get("message", body.get("error", ERR_REQUEST_NOT_SUCCESSFUL))
            if ERR_NOT_FOUND in error_detail.lower():
                raise HTTPException(status_code=404, detail="KYC requirements not found for the entity and routing ID in external service.")
            raise upstream_error(
                log_message=f"[ZYNK] Upstream rejected request while fetching KYC requirements for entity {entity_id} routing {routing_id} at {url}: {error_detail}",
                user_message=ERR_VERIFICATION_REJECTED_RETRY,
            )

        # Validate that data exists for the response schema
        data = body.get("data")
        if data is None or "kycRequirements" not in data or "message" not in data:
            raise HTTPException(status_code=502, detail=ERR_UPSTREAM_DATA_STRUCTURE)

        # Additional validation to ensure kycRequirements is a list
        kyc_requirements = data["kycRequirements"]
        if not isinstance(kyc_requirements, list):
            raise HTTPException(status_code=502, detail="Upstream service response 'kycRequirements' must be a list")

        # Return the upstream response as it matches our schema
        return body

    raise upstream_error(
        log_message=f"[ZYNK] Failed to fetch KYC requirements for entity {entity_id} routing {routing_id} at {url} after multiple attempts",
        user_message=ERR_VERIFICATION_UNAVAILABLE,
    )

@router.get("/entity/{entity_id}/kyc/documents", response_model=ZynkKycDocumentsResponse)
@limiter.limit("30/minute")  # FIXED: HIGH-04 - Rate limit to prevent KYC resource exhaustion
async def get_entity_kyc_documents(
    entity_id: str,
    current: Entities = Depends(auth.get_current_entity),
    request: Request = None
):
    """
    Fetch KYC documents for a specific entity from ZyncLab via their API.
    Ensures that users can only access their own KYC documents for security.
    Requires authentication and ownership validation in the banking system.
    """
    # Ensure the entity has an zynk_entity_id set (means it's linked to ZyncLab)
    if not current.zynk_entity_id:
        raise HTTPException(status_code=404, detail=ERR_ENTITY_NOT_LINKED)

    # FIXED: HIGH-02 - BOLA Protection: Explicit ownership validation
    # Security check: Ensure the requested entity belongs to the authenticated user
    # Prevents Broken Object Level Authorization (OWASP API #1 risk)
    if current.zynk_entity_id != entity_id:
        raise HTTPException(status_code=403, detail="Access denied. You can only access your own KYC documents.")

    # Construct the URL using the zynk_entity_id for the upstream call
    url = f"{settings.zynk_base_url}/api/v1/transformer/entity/{current.zynk_entity_id}/kyc/documents"
    headers = {**_auth_header(), "Accept": CONTENT_TYPE_JSON}

    # Make the request to ZyncLab with retry logic
    for attempt in range(2):  # 1 retry
        try:
            async with httpx.AsyncClient(timeout=settings.zynk_timeout_s) as client:
                resp = await client.get(url, headers=headers)
        except httpx.RequestError as exc:
            if attempt == 0:
                continue
            raise upstream_error(
                log_message=f"[ZYNK] Request error while fetching KYC documents for entity {current.id} at {url}: {exc}",
                user_message=ERR_VERIFICATION_UNREACHABLE,
            )

        try:
            body = resp.json()
        except ValueError:
            raise upstream_error(
                log_message=f"[ZYNK] Invalid JSON while fetching KYC documents for entity {current.id} at {url}. Response preview: {resp.text[:200]}",
                user_message=ERR_VERIFICATION_INVALID_RESPONSE,
            )

        if not (200 <= resp.status_code < 300):
            error_detail = body.get("message", body.get("error", f"HTTP {resp.status_code}: Unknown upstream error"))
            if resp.status_code == 404:
                raise HTTPException(status_code=404, detail="KYC documents not found for the entity in external service.")
            raise upstream_error(
                log_message=f"[ZYNK] Upstream error {resp.status_code} while fetching KYC documents for entity {current.id} at {url}: {error_detail}",
                user_message=ERR_VERIFICATION_UNAVAILABLE,
            )

        if not isinstance(body, dict):
            raise upstream_error(
                log_message=f"[ZYNK] Unexpected response structure while fetching KYC documents for entity {current.id} at {url}",
                user_message=ERR_VERIFICATION_UNEXPECTED,
            )

        if body.get("success") is not True:
            error_detail = body.get("message", body.get("error", ERR_REQUEST_NOT_SUCCESSFUL))
            if ERR_NOT_FOUND in error_detail.lower():
                raise HTTPException(status_code=404, detail="KYC documents not found for the entity in external service.")
            raise upstream_error(
                log_message=f"[ZYNK] Upstream rejected request while fetching KYC documents for entity {current.id} at {url}: {error_detail}",
                user_message=ERR_VERIFICATION_REJECTED_RETRY,
            )

        # Validate that data exists for the response schema
        data = body.get("data")
        if data is None:
            raise HTTPException(status_code=502, detail=ERR_UPSTREAM_DATA_STRUCTURE)

        # Additional validation to ensure documents is a list
        # documents = data["documents"]
        # if not isinstance(documents, list):
        #     raise HTTPException(status_code=502, detail="Upstream service response 'documents' must be a list")

        # Return the upstream response as it matches our schema
        return body

    raise upstream_error(
        log_message=f"[ZYNK] Failed to fetch KYC documents for entity {current.id} at {url} after multiple attempts",
        user_message=ERR_VERIFICATION_UNAVAILABLE,
    )

@router.get("/entity/email/{email}", response_model=ZynkEntityResponse)
async def get_entity_by_email(
    email: str,
    current: Entities = Depends(auth.get_current_entity)
):
    """
    Fetch a single entity by email from ZyncLab via their API.
    Ensures that users can only access their own entity data based on email for security.
    Requires authentication and ownership validation in the banking system.
    """
    # Ensure the authenticated user's email matches the requested email
    if current.email != email:
        raise HTTPException(status_code=403, detail="Access denied. You can only access your own entity data.")

    # Ensure the entity has an zynk_entity_id set (means it's linked to ZyncLab)
    if not current.zynk_entity_id:
        raise HTTPException(status_code=404, detail=ERR_ENTITY_NOT_LINKED)

    # Construct the URL using the email for the upstream call
    url = f"{settings.zynk_base_url}/api/v1/transformer/entity/email/{email}"
    headers = {**_auth_header(), "Accept": CONTENT_TYPE_JSON}

    # Make the request to ZyncLab with retry logic
    for attempt in range(2):  # 1 retry
        try:
            async with httpx.AsyncClient(timeout=settings.zynk_timeout_s) as client:
                resp = await client.get(url, headers=headers)
        except httpx.RequestError as exc:
            if attempt == 0:
                continue
            raise upstream_error(
                log_message=f"[ZYNK] Request error while fetching entity by email {email} at {url}: {exc}",
                user_message=ERR_VERIFICATION_UNREACHABLE,
            )

        try:
            body = resp.json()
        except ValueError:
            raise upstream_error(
                log_message=f"[ZYNK] Invalid JSON while fetching entity by email {email} at {url}. Response preview: {resp.text[:200]}",
                user_message=ERR_VERIFICATION_INVALID_RESPONSE,
            )

        if not (200 <= resp.status_code < 300):
            error_detail = body.get("message", body.get("error", f"HTTP {resp.status_code}: Unknown upstream error"))
            if resp.status_code == 404:
                raise HTTPException(status_code=404, detail=ERR_ENTITY_NOT_FOUND)
            raise upstream_error(
                log_message=f"[ZYNK] Upstream error {resp.status_code} while fetching entity by email {email} at {url}: {error_detail}",
                user_message=ERR_VERIFICATION_UNAVAILABLE,
            )

        if not isinstance(body, dict):
            raise upstream_error(
                log_message=f"[ZYNK] Unexpected response structure while fetching entity by email {email} at {url}",
                user_message=ERR_VERIFICATION_UNEXPECTED,
            )

        if body.get("success") is not True:
            error_detail = body.get("message", body.get("error", ERR_REQUEST_NOT_SUCCESSFUL))
            if ERR_NOT_FOUND in error_detail.lower():
                raise HTTPException(status_code=404, detail=ERR_ENTITY_NOT_FOUND)
            raise upstream_error(
                log_message=f"[ZYNK] Upstream rejected request while fetching entity by email {email} at {url}: {error_detail}",
                user_message=ERR_VERIFICATION_REJECTED_RETRY,
            )

        # Validate that data exists for the response schema
        data = body.get("data")
        if data is None or "entity" not in data:
            raise upstream_error(
                log_message=f"[ZYNK] Missing data structure while fetching entity by email {email} at {url}",
                user_message="Verification service did not provide the expected data structure. Please try again later.",
            )

        # Additional validation to ensure entity contains essential fields
        entity = data["entity"]
        required_fields = ["entityId", "type", "firstName", "lastName", "email"]
        for field in required_fields:
            if field not in entity:
                raise upstream_error(
                    log_message=f"[ZYNK] Missing required field '{field}' while fetching entity by email {email} at {url}",
                    user_message="Verification service response is incomplete. Please try again later.",
                )

        # Return the upstream response as it matches our schema
        return body

    raise upstream_error(
        log_message=f"[ZYNK] Failed to fetch entity by email {email} at {url} after multiple attempts",
        user_message=ERR_VERIFICATION_UNAVAILABLE,
    )
