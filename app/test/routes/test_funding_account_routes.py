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


@pytest.fixture
def mock_funding_account():
    """Create a mock funding account"""
    from types import SimpleNamespace
    return SimpleNamespace(
        id="funding-account-123",
        entity_id="test-user-id-123",
        jurisdiction_id="jurisdiction-123",
        provider_id="provider-123",
        status="ACTIVE",
        currency="USD",
        bank_name="Test Bank",
        bank_address="123 Test St",
        bank_routing_number="123456789",
        bank_account_number="987654321",
        bank_beneficiary_name="Test User",
        bank_beneficiary_address="123 Test St",
        payment_rail="ACH",
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
        deleted_at=None,
        zynk_funding_account_id="zynk-funding-123",
    )


class TestGetFundingAccount:
    @pytest.mark.asyncio
    async def test_get_funding_account_success(self, client, mock_user, mock_funding_account):
        """Test successful funding account retrieval"""
        from ...core.auth import get_current_entity
        app.dependency_overrides[get_current_entity] = lambda: mock_user
        
        mock_kyc_session = MagicMock()
        mock_kyc_session.status = "APPROVED"
        
        with patch('app.routers.funding_account_router.prisma') as mock_prisma:
            mock_prisma.kyc_sessions.find_first = AsyncMock(return_value=mock_kyc_session)
            mock_prisma.funding_accounts.find_first = AsyncMock(return_value=mock_funding_account)
            
            response = client.get(
                "/api/v1/account/funding",
                headers={"Authorization": f"Bearer {auth.create_access_token(data={'sub': str(mock_user.id), 'type': 'access'})}"}
            )
            
            assert response.status_code == status.HTTP_200_OK
            data = response.json()
            assert data["success"] is True
            assert data["data"] is not None
            assert data["data"]["bank_name"] == "Test Bank"
            assert data["data"]["currency"] == "USD"
        
        app.dependency_overrides.clear()
    
    @pytest.mark.asyncio
    async def test_get_funding_account_not_found(self, client, mock_user):
        """Test funding account not found"""
        from ...core.auth import get_current_entity
        app.dependency_overrides[get_current_entity] = lambda: mock_user
        
        mock_kyc_session = MagicMock()
        mock_kyc_session.status = "APPROVED"
        
        with patch('app.routers.funding_account_router.prisma') as mock_prisma:
            mock_prisma.kyc_sessions.find_first = AsyncMock(return_value=mock_kyc_session)
            mock_prisma.funding_accounts.find_first = AsyncMock(return_value=None)
            
            response = client.get(
                "/api/v1/account/funding",
                headers={"Authorization": f"Bearer {auth.create_access_token(data={'sub': str(mock_user.id), 'type': 'access'})}"}
            )
            
            assert response.status_code == status.HTTP_200_OK
            data = response.json()
            assert data["success"] is True
            assert data["data"] is None
        
        app.dependency_overrides.clear()
    
    @pytest.mark.asyncio
    async def test_get_funding_account_kyc_not_completed(self, client, mock_user):
        """Test funding account access without KYC completion"""
        from ...core.auth import get_current_entity
        app.dependency_overrides[get_current_entity] = lambda: mock_user
        
        with patch('app.routers.funding_account_router.prisma') as mock_prisma:
            mock_prisma.kyc_sessions.find_first = AsyncMock(return_value=None)
            
            response = client.get(
                "/api/v1/account/funding",
                headers={"Authorization": f"Bearer {auth.create_access_token(data={'sub': str(mock_user.id), 'type': 'access'})}"}
            )
            
            assert response.status_code == status.HTTP_403_FORBIDDEN
            data = response.json()
            assert "KYC verification" in data["detail"]["error"]["message"]
        
        app.dependency_overrides.clear()
    
    @pytest.mark.asyncio
    async def test_get_funding_account_no_zynk_entity_id(self, client, mock_user):
        """Test funding account access without zynk_entity_id"""
        from ...core.auth import get_current_entity
        mock_user_no_zynk = MagicMock()
        mock_user_no_zynk.id = "test-user-id-123"
        mock_user_no_zynk.zynk_entity_id = None
        app.dependency_overrides[get_current_entity] = lambda: mock_user_no_zynk
        
        mock_kyc_session = MagicMock()
        mock_kyc_session.status = "APPROVED"
        
        with patch('app.routers.funding_account_router.prisma') as mock_prisma:
            mock_prisma.kyc_sessions.find_first = AsyncMock(return_value=mock_kyc_session)
            
            response = client.get(
                "/api/v1/account/funding",
                headers={"Authorization": f"Bearer {auth.create_access_token(data={'sub': str(mock_user_no_zynk.id), 'type': 'access'})}"}
            )
            
            assert response.status_code == status.HTTP_400_BAD_REQUEST
            data = response.json()
            assert "profile setup" in data["detail"]["error"]["message"].lower()
        
        app.dependency_overrides.clear()


class TestCreateFundingAccount:
    @pytest.mark.asyncio
    async def test_create_funding_account_success(self, client, mock_user, mock_funding_account):
        """Test successful funding account creation"""
        from ...core.auth import get_current_entity
        app.dependency_overrides[get_current_entity] = lambda: mock_user
        
        mock_kyc_session = MagicMock()
        mock_kyc_session.status = "APPROVED"
        
        zynk_response = {
            "accountInfo": {
                "bank_name": "Test Bank",
                "bank_account_number": "987654321",
                "bank_routing_number": "123456789",
                "currency": "USD"
            }
        }
        
        with patch('app.routers.funding_account_router.prisma') as mock_prisma:
            mock_prisma.kyc_sessions.find_first = AsyncMock(return_value=mock_kyc_session)
            mock_prisma.funding_accounts.find_first = AsyncMock(return_value=None)
            
            with patch('app.routers.funding_account_router.create_funding_account_from_zynk', new_callable=AsyncMock) as mock_create:
                mock_create.return_value = zynk_response
                
                with patch('app.routers.funding_account_router.save_funding_account_to_db', new_callable=AsyncMock) as mock_save:
                    mock_save.return_value = mock_funding_account
                    
                    with patch('app.routers.funding_account_router.email_service') as mock_email:
                        mock_email.send_funding_account_created_notification = AsyncMock()
                        
                        response = client.post(
                            "/api/v1/account/funding/create",
                            headers={"Authorization": f"Bearer {auth.create_access_token(data={'sub': str(mock_user.id), 'type': 'access'})}"}
                        )
                        
                        assert response.status_code == status.HTTP_201_CREATED
                        data = response.json()
                        assert data["success"] is True
                        assert data["data"] is not None
        
        app.dependency_overrides.clear()
    
    @pytest.mark.asyncio
    async def test_create_funding_account_already_exists(self, client, mock_user, mock_funding_account):
        """Test creating funding account when one already exists"""
        from ...core.auth import get_current_entity
        app.dependency_overrides[get_current_entity] = lambda: mock_user
        
        mock_kyc_session = MagicMock()
        mock_kyc_session.status = "APPROVED"
        
        with patch('app.routers.funding_account_router.prisma') as mock_prisma:
            mock_prisma.kyc_sessions.find_first = AsyncMock(return_value=mock_kyc_session)
            mock_prisma.funding_accounts.find_first = AsyncMock(return_value=mock_funding_account)
            
            response = client.post(
                "/api/v1/account/funding/create",
                headers={"Authorization": f"Bearer {auth.create_access_token(data={'sub': str(mock_user.id), 'type': 'access'})}"}
            )
            
            assert response.status_code == status.HTTP_201_CREATED
            data = response.json()
            assert data["success"] is True
            assert data["data"] is not None
        
        app.dependency_overrides.clear()
    
    @pytest.mark.asyncio
    async def test_create_funding_account_kyc_not_completed(self, client, mock_user):
        """Test creating funding account without KYC completion"""
        from ...core.auth import get_current_entity
        app.dependency_overrides[get_current_entity] = lambda: mock_user
        
        with patch('app.routers.funding_account_router.prisma') as mock_prisma:
            mock_prisma.kyc_sessions.find_first = AsyncMock(return_value=None)
            
            response = client.post(
                "/api/v1/account/funding/create",
                headers={"Authorization": f"Bearer {auth.create_access_token(data={'sub': str(mock_user.id), 'type': 'access'})}"}
            )
            
            assert response.status_code == status.HTTP_403_FORBIDDEN
            data = response.json()
            assert "KYC verification" in data["detail"]["error"]["message"]
        
        app.dependency_overrides.clear()

