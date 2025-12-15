import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from fastapi.testclient import TestClient
from fastapi import status
from datetime import datetime, timezone
from ...main import app
from ...core import auth
from ...core.database import prisma


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def mock_user():
    """Create a mock user entity"""
    from types import SimpleNamespace
    return SimpleNamespace(
        id="test-user-id-123",
        email="test@example.com",
        first_name="Test",
        last_name="User",
        zynk_entity_id="zynk-123",
        status="ACTIVE",
    )


@pytest.fixture(autouse=True)
def cleanup_dependency_overrides():
    """Automatically clean up dependency overrides after each test"""
    yield
    app.dependency_overrides.clear()


def get_auth_headers(user):
    """Helper function to create authorization headers"""
    return {"Authorization": f"Bearer {auth.create_access_token(data={'sub': str(user.id), 'type': 'access'})}"}


def setup_dependency_override(user):
    """Helper function to set up dependency override"""
    from ...core.auth import get_current_entity
    app.dependency_overrides[get_current_entity] = lambda: user


class TestGetKycStatus:
    @pytest.mark.asyncio
    async def test_get_kyc_status_existing_session(self, client, mock_user):
        """Test getting KYC status with existing session"""
        setup_dependency_override(mock_user)
        
        mock_kyc_session = MagicMock()
        mock_kyc_session.status = "INITIATED"
        mock_kyc_session.routing_id = "routing-123"
        mock_kyc_session.kyc_link = "https://kyc.example.com/link"
        mock_kyc_session.initiated_at = datetime.now(timezone.utc)
        mock_kyc_session.completed_at = None
        mock_kyc_session.rejection_reason = None
        
        with patch('app.routers.kyc_router.prisma') as mock_prisma:
            mock_prisma.kyc_sessions.find_first = AsyncMock(return_value=mock_kyc_session)
            
            response = client.get(
                "/api/v1/kyc/status",
                headers=get_auth_headers(mock_user)
            )
            
            assert response.status_code == status.HTTP_200_OK
            data = response.json()
            assert data["success"] is True
            assert data["data"]["status"] == "INITIATED"
            assert data["data"]["routing_id"] == "routing-123"
    
    @pytest.mark.asyncio
    async def test_get_kyc_status_no_session(self, client, mock_user):
        """Test getting KYC status when no session exists"""
        setup_dependency_override(mock_user)
        
        mock_kyc_session = MagicMock()
        mock_kyc_session.status = "NOT_STARTED"
        mock_kyc_session.routing_id = None
        mock_kyc_session.kyc_link = None
        mock_kyc_session.initiated_at = None
        mock_kyc_session.completed_at = None
        mock_kyc_session.rejection_reason = None
        
        with patch('app.routers.kyc_router.prisma') as mock_prisma:
            mock_prisma.kyc_sessions.find_first = AsyncMock(return_value=None)
            mock_prisma.kyc_sessions.create = AsyncMock(return_value=mock_kyc_session)
            
            response = client.get(
                "/api/v1/kyc/status",
                headers=get_auth_headers(mock_user)
            )
            
            assert response.status_code == status.HTTP_200_OK
            data = response.json()
            assert data["success"] is True
            assert data["data"]["status"] == "NOT_STARTED"
    
    @pytest.mark.asyncio
    async def test_get_kyc_status_unauthorized(self, client):
        """Test getting KYC status without authentication"""
        response = client.get("/api/v1/kyc/status")
        
        assert response.status_code == status.HTTP_401_UNAUTHORIZED


class TestGetKycLink:
    @pytest.mark.asyncio
    async def test_get_kyc_link_not_started(self, client, mock_user):
        """Test getting KYC link when status is NOT_STARTED"""
        setup_dependency_override(mock_user)
        
        mock_kyc_session = MagicMock()
        mock_kyc_session.id = "session-123"
        mock_kyc_session.status = "NOT_STARTED"
        mock_kyc_session.routing_id = None
        mock_kyc_session.kyc_link = None
        
        kyc_data = {
            "kycLink": "https://kyc.example.com/link",
            "tosLink": "https://tos.example.com/link",
            "kycStatus": "initiated",
            "tosStatus": "pending",
            "message": "KYC link generated",
            "kycCompleted": False
        }
        
        with patch('app.routers.kyc_router.prisma') as mock_prisma:
            mock_prisma.kyc_sessions.find_first = AsyncMock(return_value=mock_kyc_session)
            mock_prisma.kyc_sessions.update = AsyncMock(return_value=mock_kyc_session)
            
            with patch('app.routers.kyc_router.get_kyc_link_from_zynk', new_callable=AsyncMock) as mock_get_link:
                mock_get_link.return_value = kyc_data
                
                with patch('app.routers.kyc_router.email_service') as mock_email:
                    mock_email.send_kyc_link_email = AsyncMock()
                    
                    response = client.get(
                        "/api/v1/kyc/link",
                        headers=get_auth_headers(mock_user)
                    )
                    
                    assert response.status_code == status.HTTP_200_OK
                    data = response.json()
                    assert data["success"] is True
                    assert data["data"]["kycLink"] == "https://kyc.example.com/link"
    
    @pytest.mark.asyncio
    async def test_get_kyc_link_already_initiated(self, client, mock_user):
        """Test getting KYC link when already initiated"""
        setup_dependency_override(mock_user)
        
        mock_kyc_session = MagicMock()
        mock_kyc_session.status = "INITIATED"
        mock_kyc_session.kyc_link = "https://kyc.example.com/existing-link"
        
        with patch('app.routers.kyc_router.prisma') as mock_prisma:
            mock_prisma.kyc_sessions.find_first = AsyncMock(return_value=mock_kyc_session)
            
            response = client.get(
                "/api/v1/kyc/link",
                headers=get_auth_headers(mock_user)
            )
            
            assert response.status_code == status.HTTP_200_OK
            data = response.json()
            assert data["success"] is True
            assert data["data"]["kycLink"] == "https://kyc.example.com/existing-link"
    
    @pytest.mark.asyncio
    async def test_get_kyc_link_approved(self, client, mock_user):
        """Test getting KYC link when already approved"""
        setup_dependency_override(mock_user)
        
        mock_kyc_session = MagicMock()
        mock_kyc_session.status = "APPROVED"
        mock_kyc_session.kyc_link = None
        
        with patch('app.routers.kyc_router.prisma') as mock_prisma:
            mock_prisma.kyc_sessions.find_first = AsyncMock(return_value=mock_kyc_session)
            
            response = client.get(
                "/api/v1/kyc/link",
                headers=get_auth_headers(mock_user)
            )
            
            assert response.status_code == status.HTTP_200_OK
            data = response.json()
            assert data["success"] is True
            assert data["data"]["kycStatus"] == "approved"
            assert data["data"]["kycLink"] is None
    
    @pytest.mark.asyncio
    async def test_get_kyc_link_no_zynk_entity_id(self, client, mock_user):
        """Test getting KYC link without zynk_entity_id"""
        mock_user_no_zynk = MagicMock()
        mock_user_no_zynk.id = "test-user-id-123"
        mock_user_no_zynk.zynk_entity_id = None
        setup_dependency_override(mock_user_no_zynk)
        
        response = client.get(
            "/api/v1/kyc/link",
            headers=get_auth_headers(mock_user_no_zynk)
        )
        
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        data = response.json()
        assert "profile setup" in data["detail"]["error"]["message"].lower()
    
    @pytest.mark.asyncio
    async def test_get_kyc_link_kyc_already_completed(self, client, mock_user):
        """Test getting KYC link when KYC is already completed"""
        setup_dependency_override(mock_user)
        
        mock_kyc_session = MagicMock()
        mock_kyc_session.id = "session-123"
        mock_kyc_session.status = "NOT_STARTED"
        
        kyc_data = {
            "kycCompleted": True,
            "message": "KYC already completed"
        }
        
        with patch('app.routers.kyc_router.prisma') as mock_prisma:
            mock_prisma.kyc_sessions.find_first = AsyncMock(return_value=mock_kyc_session)
            mock_prisma.kyc_sessions.update = AsyncMock(return_value=mock_kyc_session)
            
            with patch('app.routers.kyc_router.get_kyc_link_from_zynk', new_callable=AsyncMock) as mock_get_link:
                mock_get_link.return_value = kyc_data
                
                response = client.get(
                    "/api/v1/kyc/link",
                    headers=get_auth_headers(mock_user)
                )
                
                assert response.status_code == status.HTTP_200_OK
                data = response.json()
                assert data["success"] is True
                assert data["data"]["kycStatus"] == "approved"

