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


@pytest.fixture
def mock_kyc_session():
    """Create a mock KYC session with APPROVED status"""
    mock_session = MagicMock()
    mock_session.status = "APPROVED"
    return mock_session


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


def setup_mock_prisma_kyc(mock_prisma, kyc_session=None):
    """Helper function to set up mock KYC session"""
    mock_prisma.kyc_sessions.find_first = AsyncMock(return_value=kyc_session)


def setup_mock_prisma_funding_account(mock_prisma, funding_account=None):
    """Helper function to set up mock funding account"""
    mock_prisma.funding_accounts.find_first = AsyncMock(return_value=funding_account)


def assert_success_response(response, expected_status_code):
    """Helper function to assert successful response"""
    assert response.status_code == expected_status_code
    data = response.json()
    assert data["success"] is True
    return data


def assert_error_response(response, expected_status_code, error_message_contains=None):
    """Helper function to assert error response"""
    assert response.status_code == expected_status_code
    data = response.json()
    if error_message_contains:
        assert error_message_contains.lower() in data["detail"]["error"]["message"].lower()
    return data


class TestGetFundingAccount:
    @pytest.mark.asyncio
    async def test_get_funding_account_success(self, client, mock_user, mock_funding_account, mock_kyc_session):
        """Test successful funding account retrieval"""
        setup_dependency_override(mock_user)
        
        with patch('app.routers.funding_account_router.prisma') as mock_prisma:
            setup_mock_prisma_kyc(mock_prisma, mock_kyc_session)
            setup_mock_prisma_funding_account(mock_prisma, mock_funding_account)
            
            response = client.get(
                "/api/v1/account/funding",
                headers=get_auth_headers(mock_user)
            )
            
            data = assert_success_response(response, status.HTTP_200_OK)
            assert data["data"] is not None
            assert data["data"]["bank_name"] == "Test Bank"
            assert data["data"]["currency"] == "USD"
    
    @pytest.mark.asyncio
    async def test_get_funding_account_not_found(self, client, mock_user, mock_kyc_session):
        """Test funding account not found"""
        setup_dependency_override(mock_user)
        
        with patch('app.routers.funding_account_router.prisma') as mock_prisma:
            setup_mock_prisma_kyc(mock_prisma, mock_kyc_session)
            setup_mock_prisma_funding_account(mock_prisma, None)
            
            response = client.get(
                "/api/v1/account/funding",
                headers=get_auth_headers(mock_user)
            )
            
            data = assert_success_response(response, status.HTTP_200_OK)
            assert data["data"] is None
    
    @pytest.mark.asyncio
    async def test_get_funding_account_kyc_not_completed(self, client, mock_user):
        """Test funding account access without KYC completion"""
        setup_dependency_override(mock_user)
        
        with patch('app.routers.funding_account_router.prisma') as mock_prisma:
            setup_mock_prisma_kyc(mock_prisma, None)
            
            response = client.get(
                "/api/v1/account/funding",
                headers=get_auth_headers(mock_user)
            )
            
            assert_error_response(response, status.HTTP_403_FORBIDDEN, "KYC verification")
    
    @pytest.mark.asyncio
    async def test_get_funding_account_no_zynk_entity_id(self, client, mock_user, mock_kyc_session):
        """Test funding account access without zynk_entity_id"""
        mock_user_no_zynk = MagicMock()
        mock_user_no_zynk.id = "test-user-id-123"
        mock_user_no_zynk.zynk_entity_id = None
        setup_dependency_override(mock_user_no_zynk)
        
        with patch('app.routers.funding_account_router.prisma') as mock_prisma:
            setup_mock_prisma_kyc(mock_prisma, mock_kyc_session)
            
            response = client.get(
                "/api/v1/account/funding",
                headers=get_auth_headers(mock_user_no_zynk)
            )
            
            assert_error_response(response, status.HTTP_400_BAD_REQUEST, "profile setup")


class TestCreateFundingAccount:
    @pytest.mark.asyncio
    async def test_create_funding_account_success(self, client, mock_user, mock_funding_account, mock_kyc_session):
        """Test successful funding account creation"""
        setup_dependency_override(mock_user)
        
        zynk_response = {
            "accountInfo": {
                "bank_name": "Test Bank",
                "bank_account_number": "987654321",
                "bank_routing_number": "123456789",
                "currency": "USD"
            }
        }
        
        with patch('app.routers.funding_account_router.prisma') as mock_prisma:
            setup_mock_prisma_kyc(mock_prisma, mock_kyc_session)
            setup_mock_prisma_funding_account(mock_prisma, None)
            
            with patch('app.routers.funding_account_router.create_funding_account_from_zynk', new_callable=AsyncMock) as mock_create:
                mock_create.return_value = zynk_response
                
                with patch('app.routers.funding_account_router.save_funding_account_to_db', new_callable=AsyncMock) as mock_save:
                    mock_save.return_value = mock_funding_account
                    
                    with patch('app.routers.funding_account_router.email_service') as mock_email:
                        mock_email.send_funding_account_created_notification = AsyncMock()
                        
                        response = client.post(
                            "/api/v1/account/funding/create",
                            headers=get_auth_headers(mock_user)
                        )
                        
                        data = assert_success_response(response, status.HTTP_201_CREATED)
                        assert data["data"] is not None
    
    @pytest.mark.asyncio
    async def test_create_funding_account_already_exists(self, client, mock_user, mock_funding_account, mock_kyc_session):
        """Test creating funding account when one already exists"""
        setup_dependency_override(mock_user)
        
        with patch('app.routers.funding_account_router.prisma') as mock_prisma:
            setup_mock_prisma_kyc(mock_prisma, mock_kyc_session)
            setup_mock_prisma_funding_account(mock_prisma, mock_funding_account)
            
            response = client.post(
                "/api/v1/account/funding/create",
                headers=get_auth_headers(mock_user)
            )
            
            data = assert_success_response(response, status.HTTP_201_CREATED)
            assert data["data"] is not None
    
    @pytest.mark.asyncio
    async def test_create_funding_account_kyc_not_completed(self, client, mock_user):
        """Test creating funding account without KYC completion"""
        setup_dependency_override(mock_user)
        
        with patch('app.routers.funding_account_router.prisma') as mock_prisma:
            setup_mock_prisma_kyc(mock_prisma, None)
            
            response = client.post(
                "/api/v1/account/funding/create",
                headers=get_auth_headers(mock_user)
            )
            
            assert_error_response(response, status.HTTP_403_FORBIDDEN, "KYC verification")

