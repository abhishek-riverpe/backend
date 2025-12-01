from pydantic import BaseModel, Field
from typing import Optional
from .auth import ApiResponse

class CreateTeleportRequest(BaseModel):
    fundingAccountId: str = Field(..., description="Funding account ID")
    externalAccountId: str = Field(..., description="External account ID")

class TeleportData(BaseModel):
    teleportId: str

class CreateTeleportResponse(ApiResponse):
    data: TeleportData

