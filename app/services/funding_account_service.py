import uuid
from typing import Any, Dict

from prisma.errors import UniqueViolationError
from prisma.enums import AccountStatusEnum # type: ignore

from ..core.database import prisma

US_FUNDING_JURISDICTION_ID = "jurisdiction_51607ba7_c0b2_428c_a8c5_75ad94c9ffb1"


async def save_funding_account_to_db(
    entity_id: str,
    zynk_response_data: Dict[str, Any]
) -> Any:
    account_info = zynk_response_data.get("accountInfo", {})
    
    status_value = zynk_response_data.get("status", "active").lower()
    db_status = AccountStatusEnum.ACTIVE if status_value == "active" else AccountStatusEnum.INACTIVE
    
    currency = account_info.get("currency", "USD").upper()
    
    funding_account_data = {
        "id": str(uuid.uuid4()),  # Generate new UUID for our DB
        "entity_id": entity_id,
        "zynk_funding_account_id": zynk_response_data.get("id"),  # Store Zynk funding account ID
        "jurisdiction_id": zynk_response_data.get("jurisdictionId") or US_FUNDING_JURISDICTION_ID,
        "provider_id": zynk_response_data.get("providerId", ""),
        "status": db_status,
        "currency": currency,
        "bank_name": account_info.get("bank_name", ""),
        "bank_address": account_info.get("bank_address", ""),
        "bank_routing_number": account_info.get("bank_routing_number", ""),
        "bank_account_number": account_info.get("bank_account_number", ""),
        "bank_beneficiary_name": account_info.get("bank_beneficiary_name") or "",
        "bank_beneficiary_address": account_info.get("bank_beneficiary_address", ""),
        "payment_rail": account_info.get("payment_rail", ""),
    }
    
    try:
        funding_account = await prisma.funding_accounts.create(data=funding_account_data)
        return funding_account
    except UniqueViolationError:
        existing = await prisma.funding_accounts.find_first(
            where={"entity_id": entity_id, "deleted_at": None}
        )
        if existing:
            return existing
        raise
    except Exception as exc:
        raise

