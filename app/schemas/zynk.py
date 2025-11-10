from __future__ import annotations
from pydantic import BaseModel
from typing import Optional, List, Dict, Any

class PermanentAddress(BaseModel):
    addressLine1: str
    addressLine2: str | None = None
    locality: str | None = None
    city: str
    state: str
    country: str
    postalCode: str

class CreateZynkEntityIn(BaseModel):
    type: str
    firstName: str
    lastName: str
    email: str
    phoneNumberPrefix: str
    phoneNumber: str
    nationality: str
    dateOfBirth: str
    permanentAddress: PermanentAddress

# Model for individual entity in the response
class ZynkEntityOut(BaseModel):
    entityId: str
    type: str
    firstName: str
    lastName: str
    email: str
    phoneNumberPrefix: Optional[str] = None
    phoneNumber: Optional[str] = None
    nationality: Optional[str] = None
    dateOfBirth: Optional[str] = None
    permanentAddress: Optional[PermanentAddress] = None
    metadata: Dict[str, Any] = {}
    counterpartyRiskAllowed: bool = False

# Pagination data for entities response
class PaginationData(BaseModel):
    currentPage: int
    totalPages: int
    totalRecordsCount: int
    hasNextPage: bool
    hasPrevPage: bool

# Data structure for entities response
class ZynkEntitiesData(BaseModel):
    message: str
    entities: List[ZynkEntityOut]
    paginationData: PaginationData

# Data structure for single entity response
class ZynkSingleEntityData(BaseModel):
    message: str
    entity: ZynkEntityOut

# Response model for get single entity
class ZynkEntityResponse(BaseModel):
    success: bool
    data: ZynkSingleEntityData

# Model for KYC fees in the response
class ZynkKycFees(BaseModel):
    network: str
    currency: str
    tokenAddress: str
    amount: float
    toWalletAddress: str
    paymentReceived: bool

# Model for KYC status item in the response
class ZynkKycStatusItem(BaseModel):
    routingId: str
    supportedRoutes: List[str]
    kycStatus: str
    routingEnabled: bool
    kycFees: ZynkKycFees

# Data structure for KYC response
class ZynkKycData(BaseModel):
    message: str
    status: List[ZynkKycStatusItem]

# Response model for get KYC
class ZynkKycResponse(BaseModel):
    success: bool
    data: ZynkKycData

# Model for KYC requirement field
class ZynkKycRequirementField(BaseModel):
    fieldId: str
    fieldName: str
    fieldType: str
    fieldChoices: List[str]
    fieldRequired: bool
    fieldDescription: Optional[str] = None
    fieldDefaultValue: Optional[str] = None
    isEditable: bool
    children: Optional[List['ZynkKycRequirementField']] = []

# Data structure for KYC requirements response
class ZynkKycRequirementsData(BaseModel):
    message: str
    kycRequirements: List[ZynkKycRequirementField]

# Response model for get KYC requirements
class ZynkKycRequirementsResponse(BaseModel):
    success: bool
    data: ZynkKycRequirementsData

# Model for KYC document
class ZynkKycDocument(BaseModel):
    documentId: str
    fieldId: str
    fieldName: str
    status: str
    submittedAt: Optional[str] = None
    content: Optional[str] = None  # Base64 or URL

# Data structure for KYC documents response
class ZynkKycDocumentsData(BaseModel):
    message: str
    documents: List[ZynkKycDocument]

# Response model for get KYC documents
class ZynkKycDocumentsResponse(BaseModel):
    success: bool
    data: ZynkKycDocumentsData

# Response model for get all entities
class ZynkEntitiesResponse(BaseModel):
    success: bool
    data: ZynkEntitiesData

# Model for personal details in KYC upload
class PersonalDetails(BaseModel):
    full_name: Optional[str] = None
    date_of_birth: Optional[str] = None  # ISO 8601 format e.g. 1985-07-15T00:00:00Z
    identity_document_url: Optional[str] = None  # S3 URL
    identity_document: Optional[str] = None  # Base64 encoded document data

# Request model for uploading KYC documents
class KycDocumentUpload(BaseModel):
    transactionHash: Optional[str] = None
    base64Signature: Optional[str] = None
    personal_details: Optional[PersonalDetails] = None

# Response model for KYC upload
class KycUploadResponse(BaseModel):
    success: bool
    message: str
    data: Optional[Dict[str, Any]] = None

