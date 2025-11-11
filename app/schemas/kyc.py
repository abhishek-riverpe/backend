from pydantic import BaseModel, Field
from typing import Optional, Dict, Any
from uuid import UUID


class KycLinkData(BaseModel):
    kyc_link: Optional[str] = None


class KycLinkResponse(BaseModel):
    success: bool
    message: str
    data: Optional[KycLinkData] = None
    error: Optional[Dict[str, Any]] = None
    meta: Dict[str, Any] = Field(default_factory=dict)

class KycLinkRequest(BaseModel):
    entity_id: UUID
    routing_id: str