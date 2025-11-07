import httpx
import base64
import uuid
from fastapi import APIRouter, Depends, HTTPException, UploadFile, Form, File
from prisma.models import entities as Entities
from ..core.database import db
from ..core import auth
from ..core.config import settings
from ..schemas.zynk import ZynkEntitiesResponse, ZynkEntityResponse, ZynkKycResponse, ZynkKycRequirementsResponse, ZynkKycDocumentsResponse, KycDocumentUpload, KycUploadResponse

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

async def _upload_to_s3(file: UploadFile, file_name: str) -> str:
    """
    Upload file to S3 and return the URL.
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
        file_content = await file.read()
        s3_client.put_object(Bucket=settings.aws_s3_bucket_name, Key=file_name, Body=file_content)
        url = f"https://{settings.aws_s3_bucket_name}.s3.{settings.aws_region}.amazonaws.com/{file_name}"
        
        return url
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to upload file to S3: {str(e)}")

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
    # Ensure the entity has an external_entity_id set (means it's linked to ZyncLab)
    if not current.external_entity_id:
        raise HTTPException(status_code=404, detail="Entity not linked to external service. Please complete the entity creation process.")

    # Security check: Ensure the requested entity belongs to the authenticated user
    if current.external_entity_id != entity_id:
        raise HTTPException(status_code=403, detail="Access denied. You can only access your own entity data.")


    # Construct the URL using the external_entity_id for the upstream call
    url = f"{settings.zynk_base_url}/api/v1/transformer/entity/{current.external_entity_id}"
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
async def upload_kyc_documents(
    entity_id: str,
    routing_id: str,
    file: UploadFile = File(...),
    transactionHash: str = Form(None),
    base64Signature: str = Form(None),
    full_name: str = Form(None),
    date_of_birth: str = Form(None),
    current: Entities = Depends(auth.get_current_entity)
):
    """
    Upload KYC documents to S3 and submit to ZynkLabs API.
    Requires authentication and ownership validation for security.
    """
    # Ensure the entity has an external_entity_id set
    if not current.external_entity_id:
        raise HTTPException(status_code=404, detail="Entity not linked to external service. Please complete the entity creation process.")

    # Security check: Ensure the requested entity belongs to the authenticated user
    if current.external_entity_id != entity_id:
        raise HTTPException(status_code=403, detail="Access denied. You can only upload KYC documents for your own entity.")

    # Validate file type (basic security)
    if not file.content_type.startswith('image/'):
        raise HTTPException(status_code=400, detail="Only image files are allowed for KYC documents.")

    # Generate unique file name
    file_extension = file.filename.split('.')[-1] if '.' in file.filename else 'jpg'
    file_name = f"kyc-{entity_id}-{routing_id}-{uuid.uuid4()}.{file_extension}"

    # Upload to S3 and get URL
    s3_url = await _upload_to_s3(file, file_name)

    # Encode file to base64 for ZynkLabs
    await file.seek(0)  # Reset file pointer
    file_content = await file.read()
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
    personal_details['identity_document'] = f"data:{file.content_type};base64,{base64_document}"
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
async def get_entity_kyc_status(
    entity_id: str,
    current: Entities = Depends(auth.get_current_entity)
):
    """
    Fetch KYC status for a specific entity from ZyncLab via their API.
    Ensures that users can only access their own KYC data for security.
    Requires authentication and ownership validation in the banking system.
    """
    # Ensure the entity has an external_entity_id set (means it's linked to ZyncLab)
    if not current.external_entity_id:
        raise HTTPException(status_code=404, detail="Entity not linked to external service. Please complete the entity creation process.")

    # Security check: Ensure the requested entity belongs to the authenticated user
    if current.external_entity_id != entity_id:
        raise HTTPException(status_code=403, detail="Access denied. You can only access your own KYC data.")

    # Construct the URL using the external_entity_id for the upstream call
    url = f"{settings.zynk_base_url}/api/v1/transformer/entity/kyc/{current.external_entity_id}"
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
async def get_entity_kyc_requirements(
    entity_id: str,
    routing_id: str,
    current: Entities = Depends(auth.get_current_entity)
):
    """
    Fetch KYC requirements for a specific entity and routing ID from ZyncLab via their API.
    Ensures that users can only access their own KYC requirements for security.
    Requires authentication and ownership validation in the banking system.
    """
    # Ensure the entity has an external_entity_id set (means it's linked to ZyncLab)
    if not current.external_entity_id:
        raise HTTPException(status_code=404, detail="Entity not linked to external service. Please complete the entity creation process.")

    # Security check: Ensure the requested entity belongs to the authenticated user
    if current.external_entity_id != entity_id:
        raise HTTPException(status_code=403, detail="Access denied. You can only access your own KYC requirements.")

    # Construct the URL using the external_entity_id and routing_id for the upstream call
    url = f"{settings.zynk_base_url}/api/v1/transformer/entity/kyc/requirements/{current.external_entity_id}/{routing_id}"
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
async def get_entity_kyc_documents(
    entity_id: str,
    current: Entities = Depends(auth.get_current_entity)
):
    """
    Fetch KYC documents for a specific entity from ZyncLab via their API.
    Ensures that users can only access their own KYC documents for security.
    Requires authentication and ownership validation in the banking system.
    """
    # Ensure the entity has an external_entity_id set (means it's linked to ZyncLab)
    if not current.external_entity_id:
        raise HTTPException(status_code=404, detail="Entity not linked to external service. Please complete the entity creation process.")

    # Security check: Ensure the requested entity belongs to the authenticated user
    if current.external_entity_id != entity_id:
        raise HTTPException(status_code=403, detail="Access denied. You can only access your own KYC documents.")

    # Construct the URL using the external_entity_id for the upstream call
    url = f"{settings.zynk_base_url}/api/v1/transformer/entity/{current.external_entity_id}/kyc/documents"
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

    # Ensure the entity has an external_entity_id set (means it's linked to ZyncLab)
    if not current.external_entity_id:
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
