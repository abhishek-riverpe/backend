from datetime import datetime
from pydantic import BaseModel, Field
from typing import Optional, Dict, Any


class FundingAccountData(BaseModel):
    """Funding account data for the authenticated user"""
    id: str = Field(..., description="Funding account ID")
    entity_id: str = Field(..., description="Entity ID that owns this funding account")
    jurisdiction_id: str = Field(..., description="Jurisdiction identifier")
    provider_id: str = Field(..., description="Provider identifier")
    status: str = Field(..., description="Account status (ACTIVE or INACTIVE)")
    currency: str = Field(..., description="Account currency (e.g., USD)")
    bank_name: str = Field(..., description="Bank name")
    bank_address: str = Field(..., description="Bank address")
    bank_routing_number: str = Field(..., description="Bank routing number")
    bank_account_number: str = Field(..., description="Bank account number (masked in responses)")
    bank_beneficiary_name: str = Field(..., description="Bank beneficiary name")
    bank_beneficiary_address: str = Field(..., description="Bank beneficiary address")
    payment_rail: str = Field(..., description="Payment rail type (e.g., ach_push, wire)")
    created_at: datetime = Field(..., description="Timestamp when funding account was created")
    updated_at: datetime = Field(..., description="Timestamp when funding account was last updated")


class FundingAccountResponse(BaseModel):
    """Standard API response for funding account endpoint"""
    success: bool
    data: Optional[FundingAccountData] = None
    error: Optional[Dict[str, Any]] = None
    meta: Dict[str, Any] = Field(default_factory=dict)

