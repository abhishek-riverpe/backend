from fastapi import APIRouter, HTTPException, status, Request
import json
import hmac
import hashlib
import base64
import time
import re
import uuid
from typing import Optional, Dict, Any
from ..core.config import settings
from ..core.database import prisma
from prisma.enums import WebhookEventCategory, KycStatusEnum # type: ignore
from datetime import datetime, timezone
try:
    from prisma import types
    Json = types.Json if hasattr(types, 'Json') else None
except ImportError:
    Json = None

router = APIRouter(prefix="/api/v1/webhooks", tags=["webhooks"])


def verify_webhook_signature(payload: dict, received_signature: str, secret: str) -> bool:
    if not secret:
        return False
    
    try:
        match = re.match(r'^(\d+):(.+)$', received_signature)
        if not match:
            return False
        
        timestamp, signature = match.groups()
        
        signed_body = {**payload, "signedAt": timestamp}
        body_json = json.dumps(signed_body, separators=(',', ':'))
        
        expected_signature = hmac.new(
            secret.encode('utf-8'),
            body_json.encode('utf-8'),
            hashlib.sha256
        ).digest()
        
        expected_signature_b64 = base64.b64encode(expected_signature).decode('utf-8')
        
        return hmac.compare_digest(
            signature.encode('utf-8'),
            expected_signature_b64.encode('utf-8')
        )
    except Exception:
        return False


@router.post("/zynk")
async def receive_zynk_webhook(request: Request):
    client_ip = request.client.host if request.client else "unknown"
    
    received_signature = request.headers.get("z-webhook-signature")
    if not received_signature:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing webhook signature"
        )
    
    if not settings.zynk_webhook_secret:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Webhook verification not configured"
        )
    
    raw_body = await request.body()
    try:
        body = json.loads(raw_body)
    except json.JSONDecodeError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid JSON payload"
        )
    
    if not verify_webhook_signature(body, received_signature, settings.zynk_webhook_secret):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid webhook signature"
        )
    
    signed_at = body.get("signedAt")
    if signed_at:
        try:
            timestamp = int(signed_at)
            current_time = int(time.time())
            if abs(current_time - timestamp) > 300:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Webhook timestamp expired or too far in future"
                )
        except (ValueError, TypeError):
            pass
    
    event_category = body.get("eventCategory")
    
    if event_category == "webhook":
        try:
            await _save_webhook_event(body, WebhookEventCategory.WEBHOOK, client_ip)
        except Exception:
            pass
    elif event_category == "kyc":
        try:
            await _save_webhook_event(body, WebhookEventCategory.KYC, client_ip)
        except Exception:
            pass
        
        try:
            await _update_kyc_status_from_webhook(body)
        except Exception:
            pass
    elif event_category == "TRANSFER":
        try:
            await _save_webhook_event(body, WebhookEventCategory.TRANSFER, client_ip)
        except Exception:
            pass
    else:
        try:
            await _save_webhook_event(body, WebhookEventCategory.WEBHOOK, client_ip)
        except Exception:
            pass
    
    return {"success": True, "message": "Webhook received and verified"}


def _extract_entity_id_from_payload(payload: Dict[str, Any]) -> Optional[str]:
    if "entityId" in payload:
        return payload["entityId"]
    if "entity_id" in payload:
        return payload["entity_id"]
    
    event_object = payload.get("eventObject", {})
    if isinstance(event_object, dict):
        if "entityId" in event_object:
            return event_object["entityId"]
        if "entity_id" in event_object:
            return event_object["entity_id"]
    
    data = payload.get("data", {})
    if isinstance(data, dict):
        if "entityId" in data:
            return data["entityId"]
        if "entity_id" in data:
            return data["entity_id"]
    
    return None


def _extract_kyc_session_id_from_payload(payload: Dict[str, Any]) -> Optional[str]:
    if "kycSessionId" in payload:
        return payload["kycSessionId"]
    if "kyc_session_id" in payload:
        return payload["kyc_session_id"]
    if "routingId" in payload:
        return payload["routingId"]
    if "routing_id" in payload:
        return payload["routing_id"]
    
    event_object = payload.get("eventObject", {})
    if isinstance(event_object, dict):
        if "kycSessionId" in event_object:
            return event_object["kycSessionId"]
        if "routingId" in event_object:
            return event_object["routingId"]
    
    data = payload.get("data", {})
    if isinstance(data, dict):
        if "kycSessionId" in data:
            return data["kycSessionId"]
        if "routingId" in data:
            return data["routingId"]
    
    return None


def _extract_teleport_id_from_payload(payload: Dict[str, Any]) -> Optional[str]:
    if "teleportId" in payload:
        return payload["teleportId"]
    if "teleport_id" in payload:
        return payload["teleport_id"]
    
    event_object = payload.get("eventObject", {})
    if isinstance(event_object, dict):
        if "teleportId" in event_object:
            return event_object["teleportId"]
    
    data = payload.get("data", {})
    if isinstance(data, dict):
        if "teleportId" in data:
            return data["teleportId"]
    
    return None


def _map_webhook_status_to_kyc_status(webhook_status: str) -> Optional[KycStatusEnum]:
    status_mapping = {
        "approved": KycStatusEnum.APPROVED,
        "rejected": KycStatusEnum.REJECTED,
        "reviewing": KycStatusEnum.REVIEWING,
        "additional_info_required": KycStatusEnum.ADDITIONAL_INFO_REQUIRED,
        "additional_docs_required": KycStatusEnum.ADDITIONAL_INFO_REQUIRED,
        "initiated": KycStatusEnum.INITIATED,
        "not_started": KycStatusEnum.NOT_STARTED,
        "pending": KycStatusEnum.REVIEWING,  # Pending usually means under review
        "in_review": KycStatusEnum.REVIEWING,
    }
    
    normalized_status = webhook_status.lower().strip() if webhook_status else None
    return status_mapping.get(normalized_status) if normalized_status else None


async def _update_kyc_status_from_webhook(payload: Dict[str, Any]) -> None:
    try:
        event_object = payload.get("eventObject", {})
        if not event_object:
            return
        
        routing_id = event_object.get("routingId") or event_object.get("routing_id")
        if not routing_id:
            return
        
        entity_id_str = _extract_entity_id_from_payload(payload)
        if not entity_id_str:
            return
        
        entity = None
        try:
            entity = await prisma.entities.find_unique(
                where={"zynk_entity_id": entity_id_str}
            )
            if not entity:
                try:
                    uuid.UUID(entity_id_str)
                    entity = await prisma.entities.find_unique(where={"id": entity_id_str})
                except ValueError:
                    pass
        except Exception:
            return
        
        if not entity:
            return
        
        kyc_session = await prisma.kyc_sessions.find_first(
            where={
                "routing_id": routing_id,
                "entity_id": str(entity.id),
                "deleted_at": None
            }
        )
        
        if not kyc_session:
            return
        
        webhook_status = event_object.get("status")
        if not webhook_status:
            return
        
        kyc_status = _map_webhook_status_to_kyc_status(webhook_status)
        if not kyc_status:
            return
        
        update_data = {
            "status": kyc_status,
        }
        
        routing_enabled = event_object.get("routingEnabled")
        if routing_enabled is not None:
            update_data["routing_enabled"] = bool(routing_enabled)
        
        if kyc_status in [KycStatusEnum.APPROVED, KycStatusEnum.REJECTED]:
            if not kyc_session.completed_at:
                update_data["completed_at"] = datetime.now(timezone.utc)
        
        if kyc_status == KycStatusEnum.REJECTED:
            rejection_reasons = event_object.get("rejectionReasons") or event_object.get("rejection_reasons")
            comments = event_object.get("comments") or event_object.get("comment")
            
            rejection_reason = rejection_reasons or comments
            if rejection_reason:
                update_data["rejection_reason"] = str(rejection_reason)
            elif not kyc_session.rejection_reason:
                update_data["rejection_reason"] = "KYC verification rejected"
        
        if kyc_status == KycStatusEnum.INITIATED and not kyc_session.initiated_at:
            update_data["initiated_at"] = datetime.now(timezone.utc)
        
        await prisma.kyc_sessions.update(
            where={"id": kyc_session.id},
            data=update_data
        )
        
        if kyc_status == KycStatusEnum.APPROVED:
            try:
                existing_funding_account = await prisma.funding_accounts.find_first(
                    where={"entity_id": str(entity.id), "deleted_at": None}
                )
                
                if not existing_funding_account and entity.zynk_entity_id:
                    from ..services.zynk_client import create_funding_account_from_zynk
                    from ..services.funding_account_service import save_funding_account_to_db, US_FUNDING_JURISDICTION_ID
                    from ..services.email_service import email_service
                    
                    zynk_response_data = await create_funding_account_from_zynk(
                        entity.zynk_entity_id,
                        US_FUNDING_JURISDICTION_ID
                    )
                    
                    await save_funding_account_to_db(str(entity.id), zynk_response_data)
                    
                    try:
                        account_info = zynk_response_data.get("accountInfo", {})
                        user_name = f"{entity.first_name or ''} {entity.last_name or ''}".strip() or "User"
                        currency = account_info.get("currency", "USD").upper()
                        await email_service.send_funding_account_created_notification(
                            email=entity.email,
                            user_name=user_name,
                            bank_name=account_info.get("bank_name", ""),
                            bank_account_number=account_info.get("bank_account_number", ""),
                            bank_routing_number=account_info.get("bank_routing_number", ""),
                            currency=currency,
                            timestamp=datetime.now(timezone.utc),
                        )
                    except Exception:
                        pass
            except Exception:
                pass
        
    except Exception:
        raise


async def _save_webhook_event(
    payload: Dict[str, Any], 
    event_category: WebhookEventCategory, 
    client_ip: str
) -> None:
    try:
        event_type = payload.get("eventType", "unknown")
        if not event_type:
            event_type = "unknown"
        
        event_status = payload.get("eventStatus")
        
        entity_id_str = _extract_entity_id_from_payload(payload)
        kyc_session_id_str = _extract_kyc_session_id_from_payload(payload)
        teleport_id_str = _extract_teleport_id_from_payload(payload)
        
        entity_id = None
        if entity_id_str:
            try:
                try:
                    uuid.UUID(entity_id_str)
                    entity = await prisma.entities.find_unique(where={"id": entity_id_str})
                    if entity:
                        entity_id = entity_id_str
                    else:
                        entity = await prisma.entities.find_unique(
                            where={"zynk_entity_id": entity_id_str}
                        )
                        if entity:
                            entity_id = str(entity.id)
                except ValueError:
                    entity = await prisma.entities.find_unique(
                        where={"zynk_entity_id": entity_id_str}
                    )
                    if entity:
                        entity_id = str(entity.id)
            except Exception:
                pass
        
        kyc_session_id = None
        if kyc_session_id_str and entity_id:
            try:
                kyc_session = await prisma.kyc_sessions.find_first(
                    where={
                        "routing_id": kyc_session_id_str,
                        "entity_id": entity_id,
                        "deleted_at": None
                    }
                )
                if kyc_session:
                    kyc_session_id = str(kyc_session.id)
            except Exception:
                pass
        
        event_payload_json = json.dumps(payload, default=str)
        
        query = """
            INSERT INTO webhook_events (
                id, event_category, event_type, event_status, 
                entity_id, kyc_session_id, teleport_id, event_payload, created_at, updated_at
            ) VALUES (
                gen_random_uuid(), $1::"WebhookEventCategory", $2, $3, $4, $5, $6, $7::jsonb, NOW(), NOW()
            ) RETURNING id
        """
        
        result = await prisma.query_raw(
            query,
            event_category.value,
            event_type,
            event_status,
            entity_id,
            kyc_session_id,
            teleport_id_str,
            event_payload_json,
        )
        
        if not result or len(result) == 0:
            raise Exception("Failed to create webhook event - no ID returned")
        
    except Exception:
        raise