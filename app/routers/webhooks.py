from fastapi import APIRouter, HTTPException, status, Request
import json
import hmac
import hashlib
import base64
import time
import re
import logging
import uuid
from typing import Optional, Dict, Any
from ..core.config import settings
from ..core.database import prisma
from prisma.enums import WebhookEventCategory, KycStatusEnum, AccountStatusEnum
from datetime import datetime, timezone
try:
    from prisma import types
    # Prisma Python Json type wrapper if available
    Json = types.Json if hasattr(types, 'Json') else None
except ImportError:
    Json = None

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/webhooks", tags=["webhooks"])


async def _validate_webhook_request(request: Request) -> tuple[str, dict]:
    """Validate webhook request and return client_ip and parsed body."""
    client_ip = request.client.host if request.client else "unknown"
    
    received_signature = request.headers.get("z-webhook-signature")
    if not received_signature:
        logger.warning(f"[WEBHOOK] Missing signature header from {client_ip}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing webhook signature"
        )
    
    if not settings.zynk_webhook_secret:
        logger.error("[WEBHOOK] Webhook secret not configured in settings")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Webhook verification not configured"
        )
    
    raw_body = await request.body()
    try:
        body = json.loads(raw_body)
    except json.JSONDecodeError as e:
        logger.warning(f"[WEBHOOK] Invalid JSON from {client_ip}: {e}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid JSON payload"
        )
    
    return client_ip, body


def _validate_webhook_signature(body: dict, received_signature: str, client_ip: str) -> None:
    """Validate webhook signature."""
    if not verify_webhook_signature(body, received_signature, settings.zynk_webhook_secret):
        logger.warning(
            f"[WEBHOOK] Invalid signature from {client_ip}. "
            f"Event: {body.get('eventCategory', 'unknown')}"
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid webhook signature"
        )


def _validate_webhook_timestamp(body: dict, client_ip: str) -> None:
    """Validate webhook timestamp to prevent replay attacks."""
    signed_at = body.get("signedAt")
    if not signed_at:
        return
    
    try:
        timestamp = int(signed_at)
        current_time = int(time.time())
        if abs(current_time - timestamp) > 300:
            logger.warning(
                f"[WEBHOOK] Expired webhook from {client_ip}. "
                f"Timestamp: {timestamp}, Current: {current_time}, Diff: {abs(current_time - timestamp)}s"
            )
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Webhook timestamp expired or too far in future"
            )
    except (ValueError, TypeError):
        logger.warning(f"[WEBHOOK] Invalid timestamp format from {client_ip}")


async def _process_webhook_event(body: dict, event_category: str, client_ip: str) -> None:
    """Process webhook event based on category."""
    if event_category == "webhook":
        await _handle_webhook_config_event(body, client_ip)
    elif event_category == "kyc":
        await _handle_kyc_event(body, client_ip)
    elif event_category == "TRANSFER":
        await _handle_transfer_event(body, client_ip)
    else:
        await _handle_unknown_event(body, event_category, client_ip)


async def _handle_webhook_config_event(body: dict, client_ip: str) -> None:
    """Handle webhook configuration event."""
    logger.info(f"[WEBHOOK] Webhook configuration event: {body}")
    try:
        await _save_webhook_event(body, WebhookEventCategory.WEBHOOK)
    except Exception as e:
        logger.error(f"[WEBHOOK] Failed to save webhook event to database: {e}", exc_info=True)


async def _handle_kyc_event(body: dict, client_ip: str) -> None:
    """Handle KYC event."""
    logger.info(f"[WEBHOOK] KYC event received: {body}")
    try:
        await _save_webhook_event(body, WebhookEventCategory.KYC)
    except Exception as e:
        logger.error(f"[WEBHOOK] Failed to save KYC webhook event to database: {e}", exc_info=True)
    
    try:
        await _update_kyc_status_from_webhook(body)
    except Exception as e:
        logger.error(f"[WEBHOOK] Failed to update KYC status from webhook: {e}", exc_info=True)


async def _handle_transfer_event(body: dict, client_ip: str) -> None:
    """Handle transfer event."""
    logger.info(f"[WEBHOOK] Transfer event received: {body}")
    try:
        await _save_webhook_event(body, WebhookEventCategory.TRANSFER)
    except Exception as e:
        logger.error(f"[WEBHOOK] Failed to save TRANSFER webhook event to database: {e}", exc_info=True)
    # Transfer processing logic can be implemented here when needed
    # For now, we just save the event to the database


async def _handle_unknown_event(body: dict, event_category: str, client_ip: str) -> None:
    """Handle unknown event category."""
    logger.warning(f"[WEBHOOK] Unknown event category: {event_category} with payload: {body}")
    try:
        await _save_webhook_event(body, WebhookEventCategory.WEBHOOK)
    except Exception as e:
        logger.error(f"[WEBHOOK] Failed to save unknown webhook event to database: {e}", exc_info=True)


def verify_webhook_signature(payload: dict, received_signature: str, secret: str) -> bool:
    """
    Verify webhook signature according to Zynk API documentation.
    
    Process:
    1. Extract timestamp and signature from z-webhook-signature header (format: timestamp:signature)
    2. Recreate the signed body by adding signedAt: timestamp to the payload
    3. Generate expected signature using HMAC-SHA256 with the secret
    4. Compare received signature with expected signature using constant-time comparison
    
    Args:
        payload: The webhook payload (dict)
        received_signature: The signature from z-webhook-signature header (format: timestamp:signature)
        secret: The webhook secret for HMAC verification
        
    Returns:
        True if signature is valid, False otherwise
    """
    if not secret:
        logger.error("[WEBHOOK] Webhook secret not configured")
        return False
    
    try:
        # Extract timestamp and signature from header (format: timestamp:signature)
        match = re.match(r'^(\d+):(.+)$', received_signature)
        if not match:
            logger.warning(f"[WEBHOOK] Invalid signature format: {received_signature}")
            return False
        
        timestamp, signature = match.groups()
        
        # Recreate the signed body by adding signedAt: timestamp to the payload
        # Note: We overwrite signedAt if it exists in payload to use the timestamp from header
        signed_body = {**payload, "signedAt": timestamp}
        # Use default JSON serialization (no key sorting) to match JavaScript's JSON.stringify behavior
        body_json = json.dumps(signed_body, separators=(',', ':'))
        
        # Generate expected signature using HMAC-SHA256
        expected_signature = hmac.new(
            secret.encode('utf-8'),
            body_json.encode('utf-8'),
            hashlib.sha256
        ).digest()
        
        # Encode to base64 for comparison
        expected_signature_b64 = base64.b64encode(expected_signature).decode('utf-8')
        
        # Constant-time comparison to prevent timing attacks
        return hmac.compare_digest(
            signature.encode('utf-8'),
            expected_signature_b64.encode('utf-8')
        )
    except Exception as e:
        logger.error(f"[WEBHOOK] Signature verification error: {e}")
        return False


@router.post("/zynk")
async def receive_zynk_webhook(request: Request):
    """
    Receive and process webhooks from Zynk Labs.
    
    SECURITY: Verifies webhook signature before processing to prevent forged webhooks.
    """
    client_ip, body = await _validate_webhook_request(request)
    received_signature = request.headers.get("z-webhook-signature")
    
    _validate_webhook_signature(body, received_signature, client_ip)
    _validate_webhook_timestamp(body, client_ip)
    
    event_category = body.get("eventCategory")
    logger.info(f"[WEBHOOK] Verified webhook received from {client_ip}. Event: {event_category}")
    
    await _process_webhook_event(body, event_category, client_ip)
    
    return {"success": True, "message": "Webhook received and verified"}


def _extract_entity_id_from_payload(payload: Dict[str, Any]) -> Optional[str]:
    """
    Extract entity_id from webhook payload.
    Entity ID might be in various locations depending on event type.
    """
    # Try direct entity_id field
    if "entityId" in payload:
        return payload["entityId"]
    if "entity_id" in payload:
        return payload["entity_id"]
    
    # Try in eventObject
    event_object = payload.get("eventObject", {})
    if isinstance(event_object, dict):
        if "entityId" in event_object:
            return event_object["entityId"]
        if "entity_id" in event_object:
            return event_object["entity_id"]
    
    # Try in data field
    data = payload.get("data", {})
    if isinstance(data, dict):
        if "entityId" in data:
            return data["entityId"]
        if "entity_id" in data:
            return data["entity_id"]
    
    return None


def _extract_kyc_session_id_from_payload(payload: Dict[str, Any]) -> Optional[str]:
    """
    Extract kyc_session_id from webhook payload.
    KYC session ID might be in various locations depending on event type.
    """
    # Try direct kycSessionId or routingId fields
    if "kycSessionId" in payload:
        return payload["kycSessionId"]
    if "kyc_session_id" in payload:
        return payload["kyc_session_id"]
    if "routingId" in payload:
        return payload["routingId"]
    if "routing_id" in payload:
        return payload["routing_id"]
    
    # Try in eventObject
    event_object = payload.get("eventObject", {})
    if isinstance(event_object, dict):
        if "kycSessionId" in event_object:
            return event_object["kycSessionId"]
        if "routingId" in event_object:
            return event_object["routingId"]
    
    # Try in data field
    data = payload.get("data", {})
    if isinstance(data, dict):
        if "kycSessionId" in data:
            return data["kycSessionId"]
        if "routingId" in data:
            return data["routingId"]
    
    return None


def _extract_teleport_id_from_payload(payload: Dict[str, Any]) -> Optional[str]:
    """
    Extract teleport_id from webhook payload.
    Teleport ID might be in various locations depending on event type.
    """
    # Try direct teleportId field
    if "teleportId" in payload:
        return payload["teleportId"]
    if "teleport_id" in payload:
        return payload["teleport_id"]
    
    # Try in eventObject
    event_object = payload.get("eventObject", {})
    if isinstance(event_object, dict) and "teleportId" in event_object:
        return event_object["teleportId"]
    
    # Try in data field
    data = payload.get("data", {})
    if isinstance(data, dict) and "teleportId" in data:
        return data["teleportId"]
    
    return None


def _map_webhook_status_to_kyc_status(webhook_status: str) -> Optional[KycStatusEnum]:
    """
    Map webhook KYC status string to internal KycStatusEnum.
    
    Args:
        webhook_status: Status string from webhook (e.g., "approved", "rejected", "reviewing")
    
    Returns:
        KycStatusEnum value or None if status is not recognized
    """
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
    
    # Normalize to lowercase for case-insensitive matching
    normalized_status = webhook_status.lower().strip() if webhook_status else None
    return status_mapping.get(normalized_status) if normalized_status else None


async def _find_entity_by_id(entity_id_str: str):
    """Find entity by zynk_entity_id or internal UUID."""
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
        return entity
    except Exception as e:
        logger.warning(f"[WEBHOOK] Error looking up entity for KYC update: {e}")
        return None


def _prepare_kyc_update_data(
    event_object: dict,
    kyc_status: KycStatusEnum,
    kyc_session: Any,
) -> dict:
    """Prepare update data for KYC session."""
    update_data = {"status": kyc_status}
    
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
    
    return update_data


async def _create_funding_account_on_kyc_approval(entity: Any) -> None:
    """Create funding account when KYC is approved."""
    existing_funding_account = await prisma.funding_accounts.find_first(
        where={"entity_id": str(entity.id), "deleted_at": None}
    )
    
    if existing_funding_account:
        logger.info(
            f"[WEBHOOK] Funding account already exists for entity_id={entity.id}, "
            f"skipping auto-creation"
        )
        return
    
    if not entity.zynk_entity_id:
        logger.warning(
            f"[WEBHOOK] Entity {entity.id} not linked to Zynk Labs. "
            f"Cannot auto-create funding account."
        )
        return
    
    from ..services.zynk_client import create_funding_account_from_zynk
    from ..services.funding_account_service import save_funding_account_to_db, US_FUNDING_JURISDICTION_ID
    from ..services.email_service import email_service
    
    logger.info(
        f"[WEBHOOK] KYC approved for entity_id={entity.id}. "
        f"Auto-creating funding account via Zynk Labs API."
    )
    
    zynk_response_data = await create_funding_account_from_zynk(
        entity.zynk_entity_id,
        US_FUNDING_JURISDICTION_ID
    )
    
    funding_account = await save_funding_account_to_db(str(entity.id), zynk_response_data)
    logger.info(
        f"[WEBHOOK] Successfully created funding account {funding_account.id} "
        f"for entity_id={entity.id} after KYC approval"
    )
    
    try:
        account_info = zynk_response_data.get("accountInfo", {})
        user_name = f"{entity.first_name or ''} {entity.last_name or ''}".strip() or "User"
        currency = account_info.get("currency", "USD").upper()
        email_sent = await email_service.send_funding_account_created_notification(
            email=entity.email,
            user_name=user_name,
            bank_name=account_info.get("bank_name", ""),
            bank_account_number=account_info.get("bank_account_number", ""),
            bank_routing_number=account_info.get("bank_routing_number", ""),
            currency=currency,
            timestamp=datetime.now(timezone.utc),
        )
        if email_sent:
            logger.info(f"[WEBHOOK] Funding account creation email sent to {entity.email}")
        else:
            logger.warning(f"[WEBHOOK] Failed to send funding account creation email to {entity.email}")
    except Exception as email_exc:
        logger.error(
            f"[WEBHOOK] Error sending funding account creation email: {email_exc}",
            exc_info=email_exc,
        )


async def _update_kyc_status_from_webhook(payload: Dict[str, Any]) -> None:
    """
    Update KYC session status based on webhook payload.
    
    Args:
        payload: The verified KYC webhook payload
    """
    try:
        event_object = payload.get("eventObject", {})
        if not event_object:
            logger.warning("[WEBHOOK] KYC webhook missing eventObject, skipping status update")
            return
        
        routing_id = event_object.get("routingId") or event_object.get("routing_id")
        if not routing_id:
            logger.warning("[WEBHOOK] KYC webhook missing routingId, cannot update status")
            return
        
        entity_id_str = _extract_entity_id_from_payload(payload)
        if not entity_id_str:
            logger.warning("[WEBHOOK] KYC webhook missing entityId, cannot update status")
            return
        
        entity = await _find_entity_by_id(entity_id_str)
        if not entity:
            logger.warning(f"[WEBHOOK] Entity not found for KYC update: {entity_id_str}")
            return
        
        kyc_session = await prisma.kyc_sessions.find_first(
            where={
                "routing_id": routing_id,
                "entity_id": str(entity.id),
                "deleted_at": None
            }
        )
        
        if not kyc_session:
            logger.warning(
                f"[WEBHOOK] KYC session not found for routing_id: {routing_id}, "
                f"entity_id: {entity.id}"
            )
            return
        
        webhook_status = event_object.get("status")
        if not webhook_status:
            logger.warning("[WEBHOOK] KYC webhook missing status in eventObject")
            return
        
        kyc_status = _map_webhook_status_to_kyc_status(webhook_status)
        if not kyc_status:
            logger.warning(f"[WEBHOOK] Unknown KYC status from webhook: {webhook_status}")
            return
        
        update_data = _prepare_kyc_update_data(event_object, kyc_status, kyc_session)
        
        await prisma.kyc_sessions.update(
            where={"id": kyc_session.id},
            data=update_data
        )
        
        logger.info(
            f"[WEBHOOK] Updated KYC session {kyc_session.id} status to {kyc_status.value} "
            f"(routing_id: {routing_id}, entity_id: {entity.id})"
        )
        
        if kyc_status == KycStatusEnum.APPROVED:
            try:
                await _create_funding_account_on_kyc_approval(entity)
            except Exception as funding_exc:
                logger.error(
                    f"[WEBHOOK] Error auto-creating funding account for entity_id={entity.id} "
                    f"after KYC approval: {funding_exc}",
                    exc_info=funding_exc,
                )
        
    except Exception as e:
        logger.error(f"[WEBHOOK] Error updating KYC status from webhook: {e}", exc_info=True)
        raise


async def _find_entity_id_from_payload(entity_id_str: Optional[str]) -> Optional[str]:
    """Find internal entity_id from zynk_entity_id or UUID."""
    if not entity_id_str:
        return None
    
    try:
        try:
            uuid.UUID(entity_id_str)
            entity = await prisma.entities.find_unique(where={"id": entity_id_str})
            if entity:
                return entity_id_str
        except ValueError:
            pass
        
        entity = await prisma.entities.find_unique(
            where={"zynk_entity_id": entity_id_str}
        )
        if entity:
            return str(entity.id)
        logger.debug(f"[WEBHOOK] Entity not found for zynk_entity_id: {entity_id_str}")
    except Exception as e:
        logger.warning(f"[WEBHOOK] Error looking up entity: {e}")
    
    return None


async def _find_kyc_session_id_from_payload(
    kyc_session_id_str: Optional[str],
    entity_id: Optional[str],
) -> Optional[str]:
    """Find internal kyc_session_id from routing_id."""
    if not kyc_session_id_str or not entity_id:
        return None
    
    try:
        kyc_session = await prisma.kyc_sessions.find_first(
            where={
                "routing_id": kyc_session_id_str,
                "entity_id": entity_id,
                "deleted_at": None
            }
        )
        if kyc_session:
            return str(kyc_session.id)
        logger.debug(
            f"[WEBHOOK] KYC session not found for routing_id: {kyc_session_id_str}, "
            f"entity_id: {entity_id}"
        )
    except Exception as e:
        logger.warning(f"[WEBHOOK] Error looking up KYC session: {e}")
    
    return None


async def _save_webhook_event(
    payload: Dict[str, Any], 
    event_category: WebhookEventCategory,
) -> None:
    """
    Save webhook event to database after verification.
    
    Args:
        payload: The verified webhook payload
        event_category: The event category enum
    """
    try:
        event_type = payload.get("eventType", "unknown") or "unknown"
        event_status = payload.get("eventStatus")
        
        entity_id_str = _extract_entity_id_from_payload(payload)
        kyc_session_id_str = _extract_kyc_session_id_from_payload(payload)
        teleport_id_str = _extract_teleport_id_from_payload(payload)
        
        entity_id = await _find_entity_id_from_payload(entity_id_str)
        kyc_session_id = await _find_kyc_session_id_from_payload(kyc_session_id_str, entity_id)
        
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
            raise RuntimeError("Failed to create webhook event - no ID returned")
        
        row = result[0]
        if isinstance(row, dict):
            webhook_event_id = row.get('id')
        elif isinstance(row, (list, tuple)):
            webhook_event_id = row[0]
        else:
            webhook_event_id = str(row)
        
        logger.info(
            f"[WEBHOOK] Saved webhook event to database: "
            f"id={webhook_event_id}, category={event_category}, type={event_type}, "
            f"entity_id={entity_id}, kyc_session_id={kyc_session_id}"
        )
        
    except (RuntimeError, ValueError, TypeError) as e:
        logger.error(f"[WEBHOOK] Error saving webhook event to database: {e}", exc_info=True)
        raise