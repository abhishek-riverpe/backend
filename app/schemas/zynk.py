from __future__ import annotations
from pydantic import BaseModel, Field
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

class PaginationData(BaseModel):
    currentPage: int
    totalPages: int
    totalRecordsCount: int
    hasNextPage: bool
    hasPrevPage: bool

class ZynkEntitiesData(BaseModel):
    message: str
    entities: List[ZynkEntityOut]
    paginationData: PaginationData

class ZynkSingleEntityData(BaseModel):
    message: str
    entity: ZynkEntityOut

class ZynkEntityResponse(BaseModel):
    success: bool
    data: ZynkSingleEntityData

class ZynkKycFees(BaseModel):
    network: str
    currency: str
    tokenAddress: str
    amount: float
    toWalletAddress: str
    paymentReceived: bool

class JurisdictionInfo(BaseModel):
    jurisdictionId: str
    jurisdictionName: str
    jurisdictionType: str
    currency: str

class SupportedRoute(BaseModel):
    from_: JurisdictionInfo = Field(alias="from")
    to: JurisdictionInfo
    
    class Config:
        populate_by_name = True

class ZynkKycStatusItem(BaseModel):
    routingId: str
    supportedRoutes: List[SupportedRoute]
    kycStatus: str
    routingEnabled: bool
    kycFees: ZynkKycFees
    
    class Config:
        populate_by_name = True

class ZynkKycData(BaseModel):
    message: str
    status: List[ZynkKycStatusItem]

class ZynkKycResponse(BaseModel):
    success: bool
    data: ZynkKycData

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

class ZynkKycRequirementsData(BaseModel):
    message: str
    kycRequirements: List[ZynkKycRequirementField]

class ZynkKycRequirementsResponse(BaseModel):
    success: bool
    data: ZynkKycRequirementsData

class ZynkKycDocument(BaseModel):
    documentId: str
    fieldId: str
    fieldName: str
    status: str
    submittedAt: Optional[str] = None
    content: Optional[str] = None

class ZynkKycDocumentsData(BaseModel):
    message: str
    documents: List[ZynkKycDocument]

class ZynkKycDocumentsResponse(BaseModel):
    success: bool
    data: ZynkKycDocumentsData

class ZynkEntitiesResponse(BaseModel):
    success: bool
    data: ZynkEntitiesData

class PersonalDetails(BaseModel):
    full_name: Optional[str] = None
    date_of_birth: Optional[str] = None
    identity_document_url: Optional[str] = None
    identity_document: Optional[str] = None

class KycDocumentUpload(BaseModel):
    transactionHash: Optional[str] = None
    base64Signature: Optional[str] = None
    personal_details: Optional[PersonalDetails] = None

class KycUploadResponse(BaseModel):
    success: bool
    message: str
    data: Optional[Dict[str, Any]] = None

