import httpx
import base64
import uuid
import io
import os
import logging
from fastapi import APIRouter, Depends, HTTPException, UploadFile, Form, File, Request
from slowapi import Limiter
from slowapi.util import get_remote_address
from prisma.models import entities as Entities
from ..core.database import prisma
from ..core import auth
from ..core.config import settings
from ..schemas.zynk import ZynkEntitiesResponse, ZynkEntityResponse, ZynkKycResponse, ZynkKycRequirementsResponse, ZynkKycDocumentsResponse, KycDocumentUpload, KycUploadResponse
from PIL import Image

logger = logging.getLogger(__name__)

# FIXED: HIGH-04 - Rate limiter for preventing resource exhaustion attacks
limiter = Limiter(key_func=get_remote_address)

# FIXED: HIGH-05 - File upload validation constants
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB
ALLOWED_MIME_TYPES = ['image/jpeg', 'image/png', 'image/webp']
ALLOWED_EXTENSIONS = ['.jpg', '.jpeg', '.png', '.webp']

# Magic bytes (file signatures) for image validation
IMAGE_SIGNATURES = {
    b'\xff\xd8\xff': 'image/jpeg',  # JPEG
    b'\x89\x50\x4e\x47\x0d\x0a\x1a\x0a': 'image/png',  # PNG
    b'RIFF': 'image/webp',  # WebP (starts with RIFF, but we check more specifically)
}

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
        return 'image/jpeg'
    
    # Check PNG signature (89 50 4E 47 0D 0A 1A 0A)
    if file_content[:8] == b'\x89\x50\x4e\x47\x0d\x0a\x1a\x0a':
        return 'image/png'
    
    # Check WebP signature (RIFF...WEBP)
    if file_content[:4] == b'RIFF' and file_content[8:12] == b'WEBP':
        return 'image/webp'
    
    raise HTTPException(status_code=400, detail="Invalid file type. Only JPEG, PNG, and WebP images are allowed.")


async def _upload_to_s3(file_content: bytes, file_name: str) -> str:
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
        raise HTTPException(status_code=500, detail=f"Failed to upload file to S3: {str(e)}")

async def _create_entity_in_zynk(payload: dict) -> dict:
    """
    Create an entity in ZynkLabs API.
    """
    url = f"{settings.zynk_base_url}/api/v1/transformer/entity/create"
    headers = {**_auth_header(), "Content-Type": "application/json"}

    for attempt in range(2):  # 1 retry
        try:
            async with httpx.AsyncClient(timeout=settings.zynk_timeout_s) as client:
                resp = await client.post(url, headers=headers, json=payload)
        except httpx.RequestError:
            if attempt == 0:
                continue
            raise HTTPException(status_code=502, detail="Upstream service unreachable. Please try again later.")

        try:
            body = resp.json()
        except ValueError:
            raise HTTPException(status_code=502, detail=f"Received invalid response format from upstream service. Response preview: {resp.text[:200]}")

        if not (200 <= resp.status_code < 300):
            error_detail = body.get("message", body.get("error", f"HTTP {resp.status_code}: Unknown upstream error"))
            raise HTTPException(status_code=502, detail=f"Upstream service error: {error_detail}")

        if not isinstance(body, dict):
            raise HTTPException(status_code=502, detail="Upstream service returned unexpected response structure")

        if body.get("success") is not True:
            error_detail = body.get("message", body.get("error", "Request was not successful"))
            raise HTTPException(status_code=502, detail=f"Upstream service rejected the request: {error_detail}")

        return body

    raise HTTPException(status_code=502, detail="Failed to create entity in upstream service after multiple attempts")

async def _submit_kyc_to_zynk(entity_id: str, routing_id: str, payload: dict) -> dict:
    """
    Submit KYC documents to ZynkLabs API.
    """
    url = f"{settings.zynk_base_url}/api/v1/transformer/entity/kyc/{entity_id}/{routing_id}"
    headers = {**_auth_header(), "Content-Type": "application/json"}

    for attempt in range(2):  # 1 retry
        try:
            async with httpx.AsyncClient(timeout=settings.zynk_timeout_s) as client:
                resp = await client.post(url, headers=headers, json=payload)
        except httpx.RequestError:
            if attempt == 0:
                continue
            raise HTTPException(status_code=502, detail="Upstream service unreachable. Please try again later.")

        try:
            body = resp.json()
        except ValueError:
            raise HTTPException(status_code=502, detail=f"Received invalid response format from upstream service. Response preview: {resp.text[:200]}")

        if not (200 <= resp.status_code < 300):
            error_detail = body.get("message", body.get("error", f"HTTP {resp.status_code}: Unknown upstream error"))
            raise HTTPException(status_code=502, detail=f"Upstream service error: {error_detail}")

        if not isinstance(body, dict):
            raise HTTPException(status_code=502, detail="Upstream service returned unexpected response structure")

        if body.get("success") is not True:
            error_detail = body.get("message", body.get("error", "Request was not successful"))
            raise HTTPException(status_code=502, detail=f"Upstream service rejected the request: {error_detail}")

        return body

    raise HTTPException(status_code=502, detail="Failed to submit KYC to upstream service after multiple attempts")


@router.get("/entity/entities", response_model=ZynkEntitiesResponse)
async def get_all_entities(current: Entities = Depends(auth.get_current_entity)):
    """
    Fetch all entities from ZyncLab via their API.
    Requires authentication to ensure secure access in the banking system.
    """
    url = f"{settings.zynk_base_url}/api/v1/transformer/entity/entities"
    headers = {**_auth_header(), "Accept": "application/json"}

    for attempt in range(2):  # 1 retry
        try:
            async with httpx.AsyncClient(timeout=settings.zynk_timeout_s) as client:
                resp = await client.get(url, headers=headers)
        except httpx.RequestError:
            if attempt == 0:
                continue
            raise HTTPException(status_code=502, detail="Upstream service unreachable. Please try again later.")

        try:
            body = resp.json()
        except ValueError:
            raise HTTPException(status_code=502, detail=f"Received invalid response format from upstream service. Response preview: {resp.text[:200]}")

        if not (200 <= resp.status_code < 300):
            # Extract upstream error details for user-friendly messaging
            error_detail = body.get("message", body.get("error", f"HTTP {resp.status_code}: Unknown upstream error"))
            raise HTTPException(status_code=502, detail=f"Upstream service error: {error_detail}")

        if not isinstance(body, dict):
            raise HTTPException(status_code=502, detail="Upstream service returned unexpected response structure")

        if body.get("success") is not True:
            error_detail = body.get("message", body.get("error", "Request was not successful"))
            raise HTTPException(status_code=502, detail=f"Upstream service rejected the request: {error_detail}")

        # Validate that data exists and has required fields for the response schema
        data = body.get("data")
        if data is None or "entities" not in data or "paginationData" not in data or "message" not in data:
            raise HTTPException(status_code=502, detail="Upstream service did not provide the expected data structure")

        # Return the entire upstream response as it matches our schema
        return body

    raise HTTPException(status_code=502, detail="Failed to fetch entities from upstream service after multiple attempts")

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
        raise HTTPException(status_code=404, detail="Entity not linked to external service. Please complete the entity creation process.")

    # FIXED: HIGH-02 - BOLA Protection: Explicit ownership validation
    # Security check: Ensure the requested entity belongs to the authenticated user
    # Prevents Broken Object Level Authorization (OWASP API #1 risk)
    if current.zynk_entity_id != entity_id:
        raise HTTPException(status_code=403, detail="Access denied. You can only access your own entity data.")


    # Construct the URL using the zynk_entity_id for the upstream call
    url = f"{settings.zynk_base_url}/api/v1/transformer/entity/{current.zynk_entity_id}"
    headers = {**_auth_header(), "Accept": "application/json"}

    # Make the request to ZyncLab with retry logic
    for attempt in range(2):  # 1 retry
        try:
            async with httpx.AsyncClient(timeout=settings.zynk_timeout_s) as client:
                resp = await client.get(url, headers=headers)
        except httpx.RequestError:
            if attempt == 0:
                continue
            raise HTTPException(status_code=502, detail="Upstream service unreachable. Please try again later.")

        try:
            body = resp.json()
        except ValueError:
            raise HTTPException(status_code=502, detail=f"Received invalid response format from upstream service. Response preview: {resp.text[:200]}")

        if not (200 <= resp.status_code < 300):
            # Extract upstream error details for user-friendly messaging
            error_detail = body.get("message", body.get("error", f"HTTP {resp.status_code}: Unknown upstream error"))
            if resp.status_code == 404:
                raise HTTPException(status_code=404, detail="Entity not found in external service.")
            raise HTTPException(status_code=502, detail=f"Upstream service error: {error_detail}")

        if not isinstance(body, dict):
            raise HTTPException(status_code=502, detail="Upstream service returned unexpected response structure")

        if body.get("success") is not True:
            error_detail = body.get("message", body.get("error", "Request was not successful"))
            if "not found" in error_detail.lower():
                raise HTTPException(status_code=404, detail="Entity not found in external service.")
            raise HTTPException(status_code=502, detail=f"Upstream service rejected the request: {error_detail}")

        # Validate that data exists for the response schema
        data = body.get("data")
        if data is None or "entity" not in data:
            raise HTTPException(status_code=502, detail="Upstream service did not provide the expected data structure")

        # Additional validation to ensure entity contains essential fields
        entity = data["entity"]
        required_fields = ["entityId", "type", "firstName", "lastName", "email"]
        for field in required_fields:
            if field not in entity:
                raise HTTPException(status_code=502, detail=f"Upstream service response missing required field: {field}")

        # Return the upstream response as it matches our schema
        return body

    raise HTTPException(status_code=502, detail="Failed to fetch entity from upstream service after multiple attempts")

@router.post("/entity/kyc/{entity_id}/{routing_id}", response_model=KycUploadResponse)
@limiter.limit("30/minute")  # FIXED: HIGH-04 - Rate limit to prevent KYC resource exhaustion
async def upload_kyc_documents(
    entity_id: str,
    routing_id: str,
    file: UploadFile = File(...),
    transactionHash: str = Form(None),
    base64Signature: str = Form(None),
    full_name: str = Form(None),
    date_of_birth: str = Form(None),
    current: Entities = Depends(auth.get_current_entity),
    request: Request = None
):
    """
    Upload KYC documents to S3 and submit to ZynkLabs API.
    Requires authentication and ownership validation for security.
    """
    # Ensure the entity has an zynk_entity_id set
    if not current.zynk_entity_id:
        raise HTTPException(status_code=404, detail="Entity not linked to external service. Please complete the entity creation process.")

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
        'image/jpeg': ['.jpg', '.jpeg'],
        'image/png': ['.png'],
        'image/webp': ['.webp']
    }
    if safe_extension not in extension_map.get(detected_mime_type, []):
        # Use extension based on detected MIME type
        if detected_mime_type == 'image/jpeg':
            safe_extension = '.jpg'
        elif detected_mime_type == 'image/png':
            safe_extension = '.png'
        elif detected_mime_type == 'image/webp':
            safe_extension = '.webp'
    
    if safe_extension not in ALLOWED_EXTENSIONS:
        raise HTTPException(status_code=400, detail="Invalid file extension")
    
    # 6. Generate secure random filename (no user input in filename)
    secure_filename = f"kyc-{entity_id}-{uuid.uuid4()}{safe_extension}"
    
    # 7. Upload to S3 with validated file content
    s3_url = await _upload_to_s3(file_content, secure_filename)
    
    # 8. Encode file to base64 for ZynkLabs (using detected MIME type, not client-provided)
    base64_document = base64.b64encode(file_content).decode('utf-8')

    # Construct payload
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
        raise HTTPException(status_code=404, detail="Entity not linked to external service. Please complete the entity creation process.")

    # FIXED: HIGH-02 - BOLA Protection: Explicit ownership validation
    # Security check: Ensure the requested entity belongs to the authenticated user
    # Prevents Broken Object Level Authorization (OWASP API #1 risk)
    if zynk_entity_id != entity_id:
        raise HTTPException(status_code=403, detail="Access denied. You can only access your own KYC data.")

    # Construct the URL using the zynk_entity_id for the upstream call
    url = f"{settings.zynk_base_url}/api/v1/transformer/entity/kyc/{zynk_entity_id}"
    headers = {**_auth_header(), "Accept": "application/json"}

    # Make the request to ZyncLab with retry logic
    for attempt in range(2):  # 1 retry
        try:
            async with httpx.AsyncClient(timeout=settings.zynk_timeout_s) as client:
                resp = await client.get(url, headers=headers)
        except httpx.RequestError:
            if attempt == 0:
                continue
            raise HTTPException(status_code=502, detail="Upstream service unreachable. Please try again later.")

        try:
            body = resp.json()
        except ValueError:
            raise HTTPException(status_code=502, detail=f"Received invalid response format from upstream service. Response preview: {resp.text[:200]}")

        if not (200 <= resp.status_code < 300):
            # Extract upstream error details for user-friendly messaging
            error_detail = body.get("message", body.get("error", f"HTTP {resp.status_code}: Unknown upstream error"))
            if resp.status_code == 404:
                raise HTTPException(status_code=404, detail="KYC data not found for the entity in external service.")
            raise HTTPException(status_code=502, detail=f"Upstream service error: {error_detail}")

        if not isinstance(body, dict):
            raise HTTPException(status_code=502, detail="Upstream service returned unexpected response structure")

        if body.get("success") is not True:
            error_detail = body.get("message", body.get("error", "Request was not successful"))
            if "not found" in error_detail.lower():
                raise HTTPException(status_code=404, detail="KYC data not found for the entity in external service.")
            raise HTTPException(status_code=502, detail=f"Upstream service rejected the request: {error_detail}")

        # Validate that data exists for the response schema
        data = body.get("data")
        if data is None or "status" not in data:
            raise HTTPException(status_code=502, detail="Upstream service did not provide the expected data structure")

        # Additional validation to ensure status is a list and contains items
        status = data["status"]
        if not isinstance(status, list):
            raise HTTPException(status_code=502, detail="Upstream service response 'status' must be a list")
        if not status:
            raise HTTPException(status_code=502, detail="Upstream service response 'status' list is empty")

        # Return the upstream response as it matches our schema
        return body

    raise HTTPException(status_code=502, detail="Failed to fetch KYC status from upstream service after multiple attempts")

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
        raise HTTPException(status_code=404, detail="Entity not linked to external service. Please complete the entity creation process.")

    # FIXED: HIGH-02 - BOLA Protection: Explicit ownership validation
    # Security check: Ensure the requested entity belongs to the authenticated user
    # Prevents Broken Object Level Authorization (OWASP API #1 risk)
    if current.zynk_entity_id != entity_id:
        raise HTTPException(status_code=403, detail="Access denied. You can only access your own KYC requirements.")

    # Construct the URL using the zynk_entity_id and routing_id for the upstream call
    url = f"{settings.zynk_base_url}/api/v1/transformer/entity/kyc/requirements/{current.zynk_entity_id}/{routing_id}"
    headers = {**_auth_header(), "Accept": "application/json"}

    # Make the request to ZyncLab with retry logic
    for attempt in range(2):  # 1 retry
        try:
            async with httpx.AsyncClient(timeout=settings.zynk_timeout_s) as client:
                resp = await client.get(url, headers=headers)
        except httpx.RequestError:
            if attempt == 0:
                continue
            raise HTTPException(status_code=502, detail="Upstream service unreachable. Please try again later.")

        try:
            body = resp.json()
        except ValueError:
            raise HTTPException(status_code=502, detail=f"Received invalid response format from upstream service. Response preview: {resp.text[:200]}")

        if not (200 <= resp.status_code < 300):
            # Extract upstream error details for user-friendly messaging
            error_detail = body.get("message", body.get("error", f"HTTP {resp.status_code}: Unknown upstream error"))
            if resp.status_code == 404:
                raise HTTPException(status_code=404, detail="KYC requirements not found for the entity and routing ID in external service.")
            raise HTTPException(status_code=502, detail=f"Upstream service error: {error_detail}")

        if not isinstance(body, dict):
            raise HTTPException(status_code=502, detail="Upstream service returned unexpected response structure")

        if body.get("success") is not True:
            error_detail = body.get("message", body.get("error", "Request was not successful"))
            if "not found" in error_detail.lower():
                raise HTTPException(status_code=404, detail="KYC requirements not found for the entity and routing ID in external service.")
            raise HTTPException(status_code=502, detail=f"Upstream service rejected the request: {error_detail}")

        # Validate that data exists for the response schema
        data = body.get("data")
        if data is None or "kycRequirements" not in data or "message" not in data:
            raise HTTPException(status_code=502, detail="Upstream service did not provide the expected data structure")

        # Additional validation to ensure kycRequirements is a list
        kyc_requirements = data["kycRequirements"]
        if not isinstance(kyc_requirements, list):
            raise HTTPException(status_code=502, detail="Upstream service response 'kycRequirements' must be a list")

        # Return the upstream response as it matches our schema
        return body

    raise HTTPException(status_code=502, detail="Failed to fetch KYC requirements from upstream service after multiple attempts")

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
        raise HTTPException(status_code=404, detail="Entity not linked to external service. Please complete the entity creation process.")

    # FIXED: HIGH-02 - BOLA Protection: Explicit ownership validation
    # Security check: Ensure the requested entity belongs to the authenticated user
    # Prevents Broken Object Level Authorization (OWASP API #1 risk)
    if current.zynk_entity_id != entity_id:
        raise HTTPException(status_code=403, detail="Access denied. You can only access your own KYC documents.")

    # Construct the URL using the zynk_entity_id for the upstream call
    url = f"{settings.zynk_base_url}/api/v1/transformer/entity/{current.zynk_entity_id}/kyc/documents"
    headers = {**_auth_header(), "Accept": "application/json"}

    # Make the request to ZyncLab with retry logic
    for attempt in range(2):  # 1 retry
        try:
            async with httpx.AsyncClient(timeout=settings.zynk_timeout_s) as client:
                resp = await client.get(url, headers=headers)
        except httpx.RequestError:
            if attempt == 0:
                continue
            raise HTTPException(status_code=502, detail="Upstream service unreachable. Please try again later.")

        try:
            body = resp.json()
        except ValueError:
            raise HTTPException(status_code=502, detail=f"Received invalid response format from upstream service. Response preview: {resp.text[:200]}")

        if not (200 <= resp.status_code < 300):
            # Extract upstream error details for user-friendly messaging
            error_detail = body.get("message", body.get("error", f"HTTP {resp.status_code}: Unknown upstream error"))
            if resp.status_code == 404:
                raise HTTPException(status_code=404, detail="KYC documents not found for the entity in external service.")
            raise HTTPException(status_code=502, detail=f"Upstream service error: {error_detail}")

        if not isinstance(body, dict):
            raise HTTPException(status_code=502, detail="Upstream service returned unexpected response structure")

        if body.get("success") is not True:
            error_detail = body.get("message", body.get("error", "Request was not successful"))
            if "not found" in error_detail.lower():
                raise HTTPException(status_code=404, detail="KYC documents not found for the entity in external service.")
            raise HTTPException(status_code=502, detail=f"Upstream service rejected the request: {error_detail}")

        # Validate that data exists for the response schema
        data = body.get("data")
        if data is None:
            raise HTTPException(status_code=502, detail="Upstream service did not provide the expected data structure")

        # Additional validation to ensure documents is a list
        # documents = data["documents"]
        # if not isinstance(documents, list):
        #     raise HTTPException(status_code=502, detail="Upstream service response 'documents' must be a list")

        # Return the upstream response as it matches our schema
        return body

    raise HTTPException(status_code=502, detail="Failed to fetch KYC documents from upstream service after multiple attempts")

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
        raise HTTPException(status_code=404, detail="Entity not linked to external service. Please complete the entity creation process.")

    # Construct the URL using the email for the upstream call
    url = f"{settings.zynk_base_url}/api/v1/transformer/entity/email/{email}"
    headers = {**_auth_header(), "Accept": "application/json"}

    # Make the request to ZyncLab with retry logic
    for attempt in range(2):  # 1 retry
        try:
            async with httpx.AsyncClient(timeout=settings.zynk_timeout_s) as client:
                resp = await client.get(url, headers=headers)
        except httpx.RequestError:
            if attempt == 0:
                continue
            raise HTTPException(status_code=502, detail="Upstream service unreachable. Please try again later.")

        try:
            body = resp.json()
        except ValueError:
            raise HTTPException(status_code=502, detail=f"Received invalid response format from upstream service. Response preview: {resp.text[:200]}")

        if not (200 <= resp.status_code < 300):
            # Extract upstream error details for user-friendly messaging
            error_detail = body.get("message", body.get("error", f"HTTP {resp.status_code}: Unknown upstream error"))
            if resp.status_code == 404:
                raise HTTPException(status_code=404, detail="Entity not found in external service.")
            raise HTTPException(status_code=502, detail=f"Upstream service error: {error_detail}")

        if not isinstance(body, dict):
            raise HTTPException(status_code=502, detail="Upstream service returned unexpected response structure")

        if body.get("success") is not True:
            error_detail = body.get("message", body.get("error", "Request was not successful"))
            if "not found" in error_detail.lower():
                raise HTTPException(status_code=404, detail="Entity not found in external service.")
            raise HTTPException(status_code=502, detail=f"Upstream service rejected the request: {error_detail}")

        # Validate that data exists for the response schema
        data = body.get("data")
        if data is None or "entity" not in data:
            raise HTTPException(status_code=502, detail="Upstream service did not provide the expected data structure")

        # Additional validation to ensure entity contains essential fields
        entity = data["entity"]
        required_fields = ["entityId", "type", "firstName", "lastName", "email"]
        for field in required_fields:
            if field not in entity:
                raise HTTPException(status_code=502, detail=f"Upstream service response missing required field: {field}")

        # Return the upstream response as it matches our schema
        return body

    raise HTTPException(status_code=502, detail="Failed to fetch entity from upstream service after multiple attempts")
