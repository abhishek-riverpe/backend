from pydantic import BaseModel, Field
from typing import Optional
from .auth import ApiResponse

class CreateTeleportRequest(BaseModel):
    walletAccountId: Optional[str] = Field(None, description="Wallet account ID (optional, uses first if not provided)")

class TeleportData(BaseModel):
    teleportId: str

class CreateTeleportResponse(ApiResponse):
    data: TeleportData

class FundingAccountInfo(BaseModel):
    id: str
    bank_name: str
    bank_account_number: str
    bank_routing_number: str
    currency: str
    status: str

class WalletAccountInfo(BaseModel):
    id: str
    address: str
    chain: str
    wallet_name: str

class TeleportDetailsData(BaseModel):
    teleportId: Optional[str] = None
    fundingAccount: Optional[FundingAccountInfo] = None
    walletAccount: Optional[WalletAccountInfo] = None

class TeleportDetailsResponse(ApiResponse):
    data: TeleportDetailsData

