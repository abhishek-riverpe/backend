from fastapi import APIRouter, HTTPException, status, Request
import json
import hmac
import hashlib
import base64
import time
import re
import logging
from ..core.config import settings

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
        # Process webhook configuration event
    elif event_category == "kyc":
        logger.info(f"[WEBHOOK] KYC event received: {body}")
        # Process KYC event
        # TODO: Implement KYC status update logic here
    else:
        logger.warning(f"[WEBHOOK] Unknown event category: {event_category} with payload: {body}")
    
    return {"success": True, "message": "Webhook received and verified"}