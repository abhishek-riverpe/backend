import pytest
import json
import hmac
import hashlib
import base64
import time
from unittest.mock import AsyncMock, MagicMock, patch
from fastapi.testclient import TestClient
from fastapi import status
from datetime import datetime, timezone
from ...main import app
from ...core.database import prisma
from prisma.enums import WebhookEventCategory, KycStatusEnum


@pytest.fixture
def client():
    return TestClient(app)


def generate_webhook_signature(payload: dict, secret: str) -> str:
    """Helper function to generate webhook signature for testing"""
    timestamp = str(int(time.time()))
    signed_body = {**payload, "signedAt": timestamp}
    body_json = json.dumps(signed_body, separators=(',', ':'))
    
    signature = hmac.new(
        secret.encode('utf-8'),
        body_json.encode('utf-8'),
        hashlib.sha256
    ).digest()
    
    signature_b64 = base64.b64encode(signature).decode('utf-8')
    return f"{timestamp}:{signature_b64}"


class TestZynkWebhook:
    @pytest.mark.asyncio
    async def test_receive_webhook_success_kyc(self, client):
        """Test successful KYC webhook reception"""
        payload = {
            "eventCategory": "kyc",
            "eventType": "kyc_status_update",
            "eventStatus": "approved",
            "eventObject": {
                "routingId": "routing-123",
                "status": "approved"
            },
            "data": {
                "entityId": "zynk-entity-123"
            }
        }
        
        secret = "test-webhook-secret"
        signature = generate_webhook_signature(payload, secret)
        
        with patch('app.routers.webhooks.settings') as mock_settings:
            mock_settings.zynk_webhook_secret = secret
            
            with patch('app.routers.webhooks.prisma') as mock_prisma:
                mock_entity = MagicMock()
                mock_entity.id = "test-user-id-123"
                mock_entity.zynk_entity_id = "zynk-entity-123"
                mock_prisma.entities.find_unique = AsyncMock(return_value=mock_entity)
                mock_kyc_session = MagicMock()
                mock_kyc_session.id = "kyc-session-123"
                mock_kyc_session.completed_at = None
                mock_kyc_session.rejection_reason = None
                mock_prisma.kyc_sessions.find_first = AsyncMock(return_value=mock_kyc_session)
                mock_prisma.kyc_sessions.update = AsyncMock(return_value=mock_kyc_session)
                mock_prisma.query_raw = AsyncMock(return_value=[{"id": "webhook-event-123"}])
                
                response = client.post(
                    "/api/v1/webhooks/zynk",
                    json=payload,
                    headers={"z-webhook-signature": signature}
                )
                
                assert response.status_code == status.HTTP_200_OK
                data = response.json()
                assert data["success"] is True
                assert "received and verified" in data["message"]
    
    @pytest.mark.asyncio
    async def test_receive_webhook_missing_signature(self, client):
        """Test webhook reception without signature"""
        payload = {
            "eventCategory": "kyc",
            "eventType": "kyc_status_update"
        }
        
        response = client.post(
            "/api/v1/webhooks/zynk",
            json=payload
        )
        
        assert response.status_code == status.HTTP_401_UNAUTHORIZED
        assert "Missing webhook signature" in response.json()["detail"]
    
    @pytest.mark.asyncio
    async def test_receive_webhook_invalid_signature(self, client):
        """Test webhook reception with invalid signature"""
        payload = {
            "eventCategory": "kyc",
            "eventType": "kyc_status_update"
        }
        
        with patch('app.routers.webhooks.settings') as mock_settings:
            mock_settings.zynk_webhook_secret = "test-webhook-secret"
            
            response = client.post(
                "/api/v1/webhooks/zynk",
                json=payload,
                headers={"z-webhook-signature": "invalid:signature"}
            )
            
            assert response.status_code == status.HTTP_401_UNAUTHORIZED
            assert "Invalid webhook signature" in response.json()["detail"]
    
    @pytest.mark.asyncio
    async def test_receive_webhook_expired_timestamp(self, client):
        """Test webhook reception with expired timestamp"""
        payload = {
            "eventCategory": "kyc",
            "eventType": "kyc_status_update",
            "signedAt": str(int(time.time()) - 400)  # 400 seconds ago
        }
        
        secret = "test-webhook-secret"
        signature = generate_webhook_signature(payload, secret)
        
        with patch('app.routers.webhooks.settings') as mock_settings:
            mock_settings.zynk_webhook_secret = secret
            
            response = client.post(
                "/api/v1/webhooks/zynk",
                json=payload,
                headers={"z-webhook-signature": signature}
            )
            
            assert response.status_code == status.HTTP_400_BAD_REQUEST
            assert "timestamp expired" in response.json()["detail"].lower()
    
    @pytest.mark.asyncio
    async def test_receive_webhook_invalid_json(self, client):
        """Test webhook reception with invalid JSON"""
        secret = "test-webhook-secret"
        
        with patch('app.routers.webhooks.settings') as mock_settings:
            mock_settings.zynk_webhook_secret = secret
            
            response = client.post(
                "/api/v1/webhooks/zynk",
                data="invalid json",
                headers={"z-webhook-signature": "123:signature", "Content-Type": "application/json"}
            )
            
            assert response.status_code == status.HTTP_400_BAD_REQUEST
            assert "Invalid JSON" in response.json()["detail"]
    
    @pytest.mark.asyncio
    async def test_receive_webhook_transfer_event(self, client):
        """Test webhook reception for TRANSFER event"""
        payload = {
            "eventCategory": "TRANSFER",
            "eventType": "transfer_completed",
            "eventStatus": "completed"
        }
        
        secret = "test-webhook-secret"
        signature = generate_webhook_signature(payload, secret)
        
        with patch('app.routers.webhooks.settings') as mock_settings:
            mock_settings.zynk_webhook_secret = secret
            
            with patch('app.routers.webhooks.prisma') as mock_prisma:
                mock_prisma.query_raw = AsyncMock(return_value=[{"id": "webhook-event-123"}])
                
                response = client.post(
                    "/api/v1/webhooks/zynk",
                    json=payload,
                    headers={"z-webhook-signature": signature}
                )
                
                assert response.status_code == status.HTTP_200_OK
                data = response.json()
                assert data["success"] is True
    
    @pytest.mark.asyncio
    async def test_receive_webhook_kyc_approved_creates_funding_account(self, client):
        """Test KYC approved webhook creates funding account"""
        payload = {
            "eventCategory": "kyc",
            "eventType": "kyc_status_update",
            "eventStatus": "approved",
            "eventObject": {
                "routingId": "routing-123",
                "status": "approved"
            },
            "data": {
                "entityId": "zynk-entity-123"
            }
        }
        
        secret = "test-webhook-secret"
        signature = generate_webhook_signature(payload, secret)
        
        with patch('app.routers.webhooks.settings') as mock_settings:
            mock_settings.zynk_webhook_secret = secret
            
            with patch('app.routers.webhooks.prisma') as mock_prisma:
                mock_entity = MagicMock()
                mock_entity.id = "test-user-id-123"
                mock_entity.zynk_entity_id = "zynk-entity-123"
                mock_entity.first_name = "Test"
                mock_entity.last_name = "User"
                mock_entity.email = "test@example.com"
                mock_prisma.entities.find_unique = AsyncMock(return_value=mock_entity)
                
                mock_kyc_session = MagicMock()
                mock_kyc_session.id = "kyc-session-123"
                mock_kyc_session.completed_at = None
                mock_prisma.kyc_sessions.find_first = AsyncMock(return_value=mock_kyc_session)
                mock_prisma.kyc_sessions.update = AsyncMock(return_value=mock_kyc_session)
                mock_prisma.query_raw = AsyncMock(return_value=[{"id": "webhook-event-123"}])
                
                mock_prisma.funding_accounts.find_first = AsyncMock(return_value=None)
                
                with patch('app.services.zynk_client.create_funding_account_from_zynk', new_callable=AsyncMock) as mock_create:
                    mock_create.return_value = {
                        "accountInfo": {
                            "bank_name": "Test Bank",
                            "bank_account_number": "123456",
                            "bank_routing_number": "987654",
                            "currency": "USD"
                        }
                    }
                    
                    with patch('app.services.funding_account_service.save_funding_account_to_db', new_callable=AsyncMock) as mock_save:
                        mock_save.return_value = MagicMock()
                        
                        with patch('app.services.email_service.email_service') as mock_email:
                            mock_email.send_funding_account_created_notification = AsyncMock()
                            
                            response = client.post(
                                "/api/v1/webhooks/zynk",
                                json=payload,
                                headers={"z-webhook-signature": signature}
                            )
                            
                            assert response.status_code == status.HTTP_200_OK
                            mock_create.assert_called_once()
                            mock_save.assert_called_once()

