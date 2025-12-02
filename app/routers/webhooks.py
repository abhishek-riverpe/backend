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
    # Get client IP for logging
    client_ip = request.client.host if request.client else "unknown"
    
    # 1. Get signature from header
    received_signature = request.headers.get("z-webhook-signature")
    if not received_signature:
        logger.warning(f"[WEBHOOK] Missing signature header from {client_ip}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing webhook signature"
        )
    
    # 2. Check if webhook secret is configured
    if not settings.zynk_webhook_secret:
        logger.error("[WEBHOOK] Webhook secret not configured in settings")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Webhook verification not configured"
        )
    
    # 3. Get raw body and parse payload
    raw_body = await request.body()
    try:
        body = json.loads(raw_body)
    except json.JSONDecodeError as e:
        logger.warning(f"[WEBHOOK] Invalid JSON from {client_ip}: {e}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid JSON payload"
        )
    
    # 4. Verify signature
    if not verify_webhook_signature(body, received_signature, settings.zynk_webhook_secret):
        logger.warning(
            f"[WEBHOOK] Invalid signature from {client_ip}. "
            f"Event: {body.get('eventCategory', 'unknown')}"
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid webhook signature"
        )
    
    # 5. Validate timestamp to prevent replay attacks (if present in payload)
    # Note: Zynk may include timestamp in the payload, but we verify it's within reasonable window
    signed_at = body.get("signedAt")
    if signed_at:
        try:
            timestamp = int(signed_at)
            current_time = int(time.time())
            # Allow 5 minute window for clock skew and processing delays
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
            # Don't fail if timestamp is invalid format, just log it
    
    # 6. Process webhook (signature verified)
    event_category = body.get("eventCategory")
    logger.info(f"[WEBHOOK] Verified webhook received from {client_ip}. Event: {event_category}")
    
    if event_category == "webhook":
        logger.info(f"[WEBHOOK] Webhook configuration event: {body}")
        # Save webhook event to database
        try:
            await _save_webhook_event(body, WebhookEventCategory.WEBHOOK, client_ip)
        except Exception as e:
            logger.error(f"[WEBHOOK] Failed to save webhook event to database: {e}", exc_info=True)
        # Process webhook configuration event
    elif event_category == "kyc":
        logger.info(f"[WEBHOOK] KYC event received: {body}")
        # Save webhook event to database
        try:
            await _save_webhook_event(body, WebhookEventCategory.KYC, client_ip)
        except Exception as e:
            logger.error(f"[WEBHOOK] Failed to save KYC webhook event to database: {e}", exc_info=True)
        
        # Process KYC event - Update KYC session status
        try:
            await _update_kyc_status_from_webhook(body)
        except Exception as e:
            logger.error(f"[WEBHOOK] Failed to update KYC status from webhook: {e}", exc_info=True)
            # Don't raise - webhook event is already saved, status update failure is logged
    elif event_category == "TRANSFER":
        logger.info(f"[WEBHOOK] Transfer event received: {body}")
        # Save webhook event to database
        try:
            await _save_webhook_event(body, WebhookEventCategory.TRANSFER, client_ip)
        except Exception as e:
            logger.error(f"[WEBHOOK] Failed to save TRANSFER webhook event to database: {e}", exc_info=True)
        # Process transfer event
        # TODO: Implement transfer processing logic here
    else:
        logger.warning(f"[WEBHOOK] Unknown event category: {event_category} with payload: {body}")
        # Save unknown event category as WEBHOOK for now
        try:
            await _save_webhook_event(body, WebhookEventCategory.WEBHOOK, client_ip)
        except Exception as e:
            logger.error(f"[WEBHOOK] Failed to save unknown webhook event to database: {e}", exc_info=True)
    
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
    if isinstance(event_object, dict):
        if "teleportId" in event_object:
            return event_object["teleportId"]
    
    # Try in data field
    data = payload.get("data", {})
    if isinstance(data, dict):
        if "teleportId" in data:
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


async def _update_kyc_status_from_webhook(payload: Dict[str, Any]) -> None:
    """
    Update KYC session status based on webhook payload.
    
    Args:
        payload: The verified KYC webhook payload
    """
    try:
        # Extract eventObject which contains KYC status information
        event_object = payload.get("eventObject", {})
        if not event_object:
            logger.warning("[WEBHOOK] KYC webhook missing eventObject, skipping status update")
            return
        
        # Extract routing_id (used to find KYC session)
        routing_id = event_object.get("routingId") or event_object.get("routing_id")
        if not routing_id:
            logger.warning("[WEBHOOK] KYC webhook missing routingId, cannot update status")
            return
        
        # Extract entity_id (zynk entity ID)
        entity_id_str = _extract_entity_id_from_payload(payload)
        if not entity_id_str:
            logger.warning("[WEBHOOK] KYC webhook missing entityId, cannot update status")
            return
        
        # Find internal entity_id
        entity = None
        try:
            # Try as zynk_entity_id first
            entity = await prisma.entities.find_unique(
                where={"zynk_entity_id": entity_id_str}
            )
            if not entity:
                # Try as internal UUID
                try:
                    uuid.UUID(entity_id_str)
                    entity = await prisma.entities.find_unique(where={"id": entity_id_str})
                except ValueError:
                    pass
        except Exception as e:
            logger.warning(f"[WEBHOOK] Error looking up entity for KYC update: {e}")
            return
        
        if not entity:
            logger.warning(f"[WEBHOOK] Entity not found for KYC update: {entity_id_str}")
            return
        
        # Find KYC session by routing_id and entity_id
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
        
        # Extract status from eventObject
        webhook_status = event_object.get("status")
        if not webhook_status:
            logger.warning("[WEBHOOK] KYC webhook missing status in eventObject")
            return
        
        # Map webhook status to internal enum
        kyc_status = _map_webhook_status_to_kyc_status(webhook_status)
        if not kyc_status:
            logger.warning(f"[WEBHOOK] Unknown KYC status from webhook: {webhook_status}")
            return
        
        # Prepare update data
        update_data = {
            "status": kyc_status,
        }
        
        # Update routing_enabled if provided
        routing_enabled = event_object.get("routingEnabled")
        if routing_enabled is not None:
            update_data["routing_enabled"] = bool(routing_enabled)
        
        # Update completed_at if status is APPROVED or REJECTED
        if kyc_status in [KycStatusEnum.APPROVED, KycStatusEnum.REJECTED]:
            if not kyc_session.completed_at:  # Only update if not already set
                update_data["completed_at"] = datetime.now(timezone.utc)
        
        # Update rejection_reason if status is REJECTED
        if kyc_status == KycStatusEnum.REJECTED:
            rejection_reasons = event_object.get("rejectionReasons") or event_object.get("rejection_reasons")
            comments = event_object.get("comments") or event_object.get("comment")
            
            # Use rejectionReasons if available, otherwise use comments
            rejection_reason = rejection_reasons or comments
            if rejection_reason:
                update_data["rejection_reason"] = str(rejection_reason)
            elif not kyc_session.rejection_reason:
                # Set a default message if no reason provided
                update_data["rejection_reason"] = "KYC verification rejected"
        
        # Update initiated_at if status is INITIATED and not already set
        if kyc_status == KycStatusEnum.INITIATED and not kyc_session.initiated_at:
            update_data["initiated_at"] = datetime.now(timezone.utc)
        
        # Update KYC session
        await prisma.kyc_sessions.update(
            where={"id": kyc_session.id},
            data=update_data
        )
        
        logger.info(
            f"[WEBHOOK] Updated KYC session {kyc_session.id} status to {kyc_status.value} "
            f"(routing_id: {routing_id}, entity_id: {entity.id})"
        )
        
        # Automatically create funding account when KYC is approved
        if kyc_status == KycStatusEnum.APPROVED:
            try:
                # Check if funding account already exists
                existing_funding_account = await prisma.funding_accounts.find_first(
                    where={"entity_id": str(entity.id), "deleted_at": None}
                )
                
                if existing_funding_account:
                    logger.info(
                        f"[WEBHOOK] Funding account already exists for entity_id={entity.id}, "
                        f"skipping auto-creation"
                    )
                elif entity.zynk_entity_id:
                    # Import here to avoid circular dependencies
                    from ..services.zynk_client import create_funding_account_from_zynk
                    from ..services.funding_account_service import save_funding_account_to_db, US_FUNDING_JURISDICTION_ID
                    from ..services.email_service import email_service
                    
                    logger.info(
                        f"[WEBHOOK] KYC approved for entity_id={entity.id}. "
                        f"Auto-creating funding account via Zynk Labs API."
                    )
                    
                    # Create funding account via Zynk Labs
                    zynk_response_data = await create_funding_account_from_zynk(
                        entity.zynk_entity_id,
                        US_FUNDING_JURISDICTION_ID
                    )
                    
                    # Save to database using shared service function
                    funding_account = await save_funding_account_to_db(str(entity.id), zynk_response_data)
                    logger.info(
                        f"[WEBHOOK] Successfully created funding account {funding_account.id} "
                        f"for entity_id={entity.id} after KYC approval"
                    )
                    
                    # Send email notification
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
                            logger.info(
                                f"[WEBHOOK] Funding account creation email sent to {entity.email}"
                            )
                        else:
                            logger.warning(
                                f"[WEBHOOK] Failed to send funding account creation email to {entity.email}"
                            )
                    except Exception as email_exc:
                        # Don't fail webhook processing if email fails
                        logger.error(
                            f"[WEBHOOK] Error sending funding account creation email: {email_exc}",
                            exc_info=email_exc,
                        )
                else:
                    logger.warning(
                        f"[WEBHOOK] Entity {entity.id} not linked to Zynk Labs. "
                        f"Cannot auto-create funding account."
                    )
                    
            except Exception as funding_exc:
                # Log error but don't fail webhook processing
                # Funding account creation can be retried later via manual endpoint
                logger.error(
                    f"[WEBHOOK] Error auto-creating funding account for entity_id={entity.id} "
                    f"after KYC approval: {funding_exc}",
                    exc_info=funding_exc,
                )
        
    except Exception as e:
        logger.error(f"[WEBHOOK] Error updating KYC status from webhook: {e}", exc_info=True)
        raise


async def _save_webhook_event(
    payload: Dict[str, Any], 
    event_category: WebhookEventCategory, 
    client_ip: str
) -> None:
    """
    Save webhook event to database after verification.
    
    Args:
        payload: The verified webhook payload
        event_category: The event category enum
        client_ip: IP address of the webhook sender
    """
    try:
        # Extract event type (required field)
        event_type = payload.get("eventType", "unknown")
        if not event_type:
            event_type = "unknown"
        
        # Extract event status (optional)
        event_status = payload.get("eventStatus")
        
        # Extract entity_id, kyc_session_id, and teleport_id
        entity_id_str = _extract_entity_id_from_payload(payload)
        kyc_session_id_str = _extract_kyc_session_id_from_payload(payload)
        teleport_id_str = _extract_teleport_id_from_payload(payload)
        
        # Try to find entity_id in database if we have zynk_entity_id
        entity_id = None
        if entity_id_str:
            try:
                # First, check if it's already a UUID (our internal entity ID)
                try:
                    # Try to parse as UUID - if successful, it might be our internal ID
                    uuid.UUID(entity_id_str)
                    # Check if this UUID exists in our entities table
                    entity = await prisma.entities.find_unique(where={"id": entity_id_str})
                    if entity:
                        entity_id = entity_id_str
                    else:
                        # Not found as internal ID, try as zynk_entity_id
                        entity = await prisma.entities.find_unique(
                            where={"zynk_entity_id": entity_id_str}
                        )
                        if entity:
                            entity_id = str(entity.id)
                except ValueError:
                    # Not a UUID, try as zynk_entity_id
                    entity = await prisma.entities.find_unique(
                        where={"zynk_entity_id": entity_id_str}
                    )
                    if entity:
                        entity_id = str(entity.id)
                    else:
                        logger.debug(f"[WEBHOOK] Entity not found for zynk_entity_id: {entity_id_str}")
            except Exception as e:
                logger.warning(f"[WEBHOOK] Error looking up entity: {e}")
        
        # Try to find kyc_session_id in database if we have routing_id
        kyc_session_id = None
        if kyc_session_id_str and entity_id:
            try:
                # Look up KYC session by routing_id and entity_id
                kyc_session = await prisma.kyc_sessions.find_first(
                    where={
                        "routing_id": kyc_session_id_str,
                        "entity_id": entity_id,
                        "deleted_at": None
                    }
                )
                if kyc_session:
                    kyc_session_id = str(kyc_session.id)
                else:
                    logger.debug(f"[WEBHOOK] KYC session not found for routing_id: {kyc_session_id_str}, entity_id: {entity_id}")
            except Exception as e:
                logger.warning(f"[WEBHOOK] Error looking up KYC session: {e}")
        
        # Store the full payload as JSON
        # Ensure payload is JSON-serializable
        event_payload_json = json.dumps(payload, default=str)  # default=str handles any non-serializable types
        
        # Build SQL query with parameters to safely insert JSON data
        # Using raw SQL as workaround for Prisma Python Json field type issue
        # Cast event_category to enum type and event_payload to jsonb
        query = """
            INSERT INTO webhook_events (
                id, event_category, event_type, event_status, 
                entity_id, kyc_session_id, teleport_id, event_payload, created_at, updated_at
            ) VALUES (
                gen_random_uuid(), $1::"WebhookEventCategory", $2, $3, $4, $5, $6, $7::jsonb, NOW(), NOW()
            ) RETURNING id
        """
        
        # Execute raw query with parameters
        # Use query_raw for INSERT ... RETURNING (execute_raw returns int, not result set)
        result = await prisma.query_raw(
            query,
            event_category.value,  # Convert enum to string value
            event_type,
            event_status,
            entity_id,
            kyc_session_id,
            teleport_id_str,
            event_payload_json,  # Pass as JSON string, PostgreSQL will parse it
        )
        
        # Get the created record ID from result
        # query_raw returns a list of rows (result set)
        if result and len(result) > 0:
            row = result[0]
            # Handle both dict and tuple results
            if isinstance(row, dict):
                webhook_event_id = row.get('id')
            elif isinstance(row, (list, tuple)):
                webhook_event_id = row[0]
            else:
                webhook_event_id = str(row)
        else:
            raise Exception("Failed to create webhook event - no ID returned")
        
        logger.info(
            f"[WEBHOOK] Saved webhook event to database: "
            f"id={webhook_event_id}, category={event_category}, type={event_type}, "
            f"entity_id={entity_id}, kyc_session_id={kyc_session_id}"
        )
        
    except Exception as e:
        logger.error(f"[WEBHOOK] Error saving webhook event to database: {e}", exc_info=True)
        raise