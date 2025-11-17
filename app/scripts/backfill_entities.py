"""
Script to fetch all entities from Zynk API and print the response.
"""
import asyncio
from datetime import datetime, timezone
import httpx
import sys
from pathlib import Path

# Add parent directory to path to import app modules
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from app.core.config import settings
from app.core.database import prisma


async def fetch_entities_from_zynk(max_pages: int = 4, limit: int = 30):
    """
    Make API call to /api/v1/transformer/entity/entities and return all entities.
    Handles pagination internally.
    """
    base_url = f"{settings.zynk_base_url}/api/v1/transformer/entity/entities"
    headers = {
        "x-api-token": settings.zynk_api_key,
        "Accept": "application/json",
    }

    entities = []    
    

    async with httpx.AsyncClient(timeout=settings.zynk_timeout_s) as client:
        for page in range(1, max_pages + 1):
            url = f"{base_url}?page={page}&limit={limit}"

            try:
                resp = await client.get(url, headers=headers)
            except Exception as err:
                print(f"[Zynk] Network error on page {page}: {err}")
                continue

            if resp.status_code != 200:
                print(f"[Zynk] Error: {resp.status_code} on page {page}")
                continue

            data = resp.json()
            if "data" not in data or "entities" not in data["data"]:
                print(f"[Zynk] Unexpected response format on page {page}")
                continue

            entities.extend(data["data"]["entities"])

    return entities


async def connect_to_prisma():
    """
    Connect to Prisma database.
    """
    await prisma.connect()
    return prisma


async def fetch_entities_from_db(prisma):
    """
    Fetch entities from Prisma database.
    """
    entities = await prisma.entities.find_many()
    print(f"[DB] Retrieved {len(entities)} entities from local DB.")
    return entities


def print_entity_pretty(entity: dict):
    """
    Pretty-print a single entity from Zynk.
    """
    try:
        addr = entity.get("permanentAddress", {})
        print(
            entity.get("email"),
            entity.get("entityId"),
            entity.get("type"),
            entity.get("firstName"),
            entity.get("lastName"),
            entity.get("phoneNumberPrefix"),
            entity.get("phoneNumber"),
            entity.get("nationality"),
            entity.get("dateOfBirth"),
            addr.get("addressLine1"),
            addr.get("addressLine2"),
            addr.get("locality"),
            addr.get("city"),
            addr.get("state"),
            addr.get("country"),
            addr.get("postalCode"),
            entity.get("counterpartyRiskAllowed"),
            sep=" | "
        )
    except Exception as e:
        print(f"[Print Error] {e}")

def get_entity_type(zynk_entity: dict):
    """
    Get entity type from Zynk entity.
    """
    return "INDIVIDUAL" if zynk_entity["type"] == "individual" else "BUSINESS"

async def main():
    prisma_conn = await connect_to_prisma()
    local_entities = await fetch_entities_from_db(prisma_conn)
    print(f"[DB] Fetched {len(local_entities)} entities from local DB.")

    # Create a set of existing zynk_entity_ids for quick lookup
    existing_zynk_ids = {entity.zynk_entity_id for entity in local_entities if entity.zynk_entity_id}
    existing_emails = {entity.email for entity in local_entities}

    print("Total entities existing in local DB: ", len(existing_zynk_ids))

    # Fetch entities from Zynk
    zynk_entities = await fetch_entities_from_zynk()
    print(f"[Zynk] Fetched {len(zynk_entities)} entities from Zynk.")

    created_count = 0
    skipped_count = 0

    for zynk_entity in zynk_entities:
        zynk_entity_id = zynk_entity.get("entityId")
        email = zynk_entity.get("email")

        # Check if entity already exists by zynk_entity_id (unique constraint)
        if zynk_entity_id and zynk_entity_id in existing_zynk_ids:
            print(f"[Skip] Entity with zynk_entity_id '{zynk_entity_id}' (email: {email}) already exists in local DB.")
            skipped_count += 1
            continue

        # Also check by email as a fallback
        if email and email in existing_emails:
            print(f"[Skip] Entity with email '{email}' already exists in local DB.")
            skipped_count += 1
            continue

        # Create new entity
        try:
            await prisma_conn.entities.create(
                data={
                    "zynk_entity_id": zynk_entity_id,
                    "entity_type": get_entity_type(zynk_entity),
                    "email": email,
                    "first_name": zynk_entity.get("firstName", ""),
                    "last_name": zynk_entity.get("lastName", ""),
                    "password": "",
                    "date_of_birth": zynk_entity.get("dateOfBirth"),
                    "nationality": zynk_entity.get("nationality"),
                    "phone_number": zynk_entity.get("phoneNumber"),
                    "country_code": zynk_entity.get("phoneNumberPrefix"),
                    "status": "ACTIVE",
                    "created_at": datetime.now(timezone.utc),
                    "updated_at": datetime.now(timezone.utc),
                }
            )
            print(f"[Created] Entity {email} (zynk_entity_id: {zynk_entity_id}) created in local DB.")
            created_count += 1
            # Update the sets to avoid duplicate checks
            if zynk_entity_id:
                existing_zynk_ids.add(zynk_entity_id)
            if email:
                existing_emails.add(email)
        except Exception as e:
            print(f"[Error] Failed to create entity {email}: {e}")
            continue

    print(f"\n[Summary] Created: {created_count}, Skipped: {skipped_count}, Total processed: {len(zynk_entities)}")
    await prisma_conn.disconnect()


if __name__ == "__main__":
    asyncio.run(main())
