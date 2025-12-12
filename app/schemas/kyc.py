from datetime import datetime
from pydantic import BaseModel, Field
from typing import Optional, Dict, Any


class KycLinkData(BaseModel):
    message: str = Field(..., description="Success message")
    kycLink: Optional[str] = Field(None, description="Persona verification link")
    tosLink: Optional[str] = Field(None, description="Terms of service link")
    kycStatus: str = Field(..., description="Current KYC status")
    tosStatus: str = Field(..., description="Terms of service acceptance status")


class KycLinkResponse(BaseModel):
    success: bool
    data: Optional[KycLinkData] = None
    error: Optional[Dict[str, Any]] = None
    meta: Dict[str, Any] = Field(default_factory=dict)


class KycStatusData(BaseModel):
    status: str = Field(..., description="Current KYC status for the user")
    routing_id: Optional[str] = Field(None, description="Routing identifier used for the KYC flow")
    kyc_link: Optional[str] = Field(None, description="KYC verification link if it exists")
    initiated_at: Optional[datetime] = Field(None, description="Timestamp when KYC was initiated")
    completed_at: Optional[datetime] = Field(None, description="Timestamp when KYC was completed")
    rejection_reason: Optional[str] = Field(None, description="Reason for KYC rejection, if applicable")


class KycStatusResponse(BaseModel):
    success: bool
    data: Optional[KycStatusData] = None
    error: Optional[Dict[str, Any]] = None
    meta: Dict[str, Any] = Field(default_factory=dict)