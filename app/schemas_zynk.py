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

# Response model for get all entities
class ZynkEntitiesResponse(BaseModel):
    success: bool
    data: ZynkEntitiesData
