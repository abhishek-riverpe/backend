from fastapi import APIRouter, HTTPException, status, Request
import json

router = APIRouter(prefix="/api/v1/webhooks", tags=["webhooks"])

@router.post("/zynk")
async def receive_zynk_webhook(request: Request):
    raw_body = await request.body()
    body = json.loads(raw_body)
    event_category = body["eventCategory"]
    if event_category == "webhook":
        print("Webhook event received for configuration with payload:", body)
    elif event_category == "kyc":
        print("KYC event received with payload:", body)
    else:
        print("Unknown event category:", event_category, "with payload:", body)
    return {"message": "Webhook received"}