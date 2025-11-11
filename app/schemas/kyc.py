from pydantic import BaseModel, Field
from typing import Optional, Dict, Any


class KycLinkData(BaseModel):
    """KYC link data returned to the frontend"""
    message: str = Field(..., description="Success message")
    kycLink: Optional[str] = Field(None, description="Persona verification link")
    tosLink: Optional[str] = Field(None, description="Terms of service link")
    kycStatus: str = Field(..., description="Current KYC status")
    tosStatus: str = Field(..., description="Terms of service acceptance status")


class KycLinkResponse(BaseModel):
    """Standard API response for KYC link endpoint"""
    success: bool
    data: Optional[KycLinkData] = None
    error: Optional[Dict[str, Any]] = None
    meta: Dict[str, Any] = Field(default_factory=dict)