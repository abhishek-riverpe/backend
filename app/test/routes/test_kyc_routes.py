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


@pytest.fixture
def auth_headers(mock_user):
    """Fixture to create authorization headers"""
    return {"Authorization": f"Bearer {auth.create_access_token(data={'sub': str(mock_user.id), 'type': 'access'})}"}


@pytest.fixture
def setup_dependency_override(mock_user):
    """Set up dependency override for tests that need authentication"""
    from ...core.auth import get_current_entity
    app.dependency_overrides[get_current_entity] = lambda: mock_user


@pytest.fixture
def mock_prisma_context():
    """Fixture that provides a patched prisma context"""
    with patch('app.routers.kyc_router.prisma') as mock_prisma:
        yield mock_prisma


def make_get_request(client, endpoint, headers=None):
    """Helper function to make GET request"""
    return client.get(endpoint, headers=headers) if headers else client.get(endpoint)


def create_mock_kyc_session(**kwargs):
    """Helper function to create a mock KYC session with specified attributes"""
    mock_session = MagicMock()
    mock_session.status = kwargs.get("status", "NOT_STARTED")
    mock_session.routing_id = kwargs.get("routing_id", None)
    mock_session.kyc_link = kwargs.get("kyc_link", None)
    mock_session.initiated_at = kwargs.get("initiated_at", None)
    mock_session.completed_at = kwargs.get("completed_at", None)
    mock_session.rejection_reason = kwargs.get("rejection_reason", None)
    if "id" in kwargs:
        mock_session.id = kwargs["id"]
    return mock_session


def setup_mock_prisma_kyc(mock_prisma, kyc_session=None, create_return_value=None):
    """Helper function to set up mock KYC session in prisma"""
    mock_prisma.kyc_sessions.find_first = AsyncMock(return_value=kyc_session)
    if create_return_value is not None:
        mock_prisma.kyc_sessions.create = AsyncMock(return_value=create_return_value)


def assert_success_response(response, expected_status_code=status.HTTP_200_OK):
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


@pytest.fixture
def mock_user_no_zynk():
    """Fixture for user without zynk_entity_id"""
    mock_user = MagicMock()
    mock_user.id = "test-user-id-123"
    mock_user.zynk_entity_id = None
    return mock_user


@pytest.fixture
def auth_headers_no_zynk(mock_user_no_zynk):
    """Fixture for auth headers without zynk entity"""
    from ...core.auth import get_current_entity
    app.dependency_overrides[get_current_entity] = lambda: mock_user_no_zynk
    return {"Authorization": f"Bearer {auth.create_access_token(data={'sub': str(mock_user_no_zynk.id), 'type': 'access'})}"}


@pytest.fixture
def mock_kyc_session_initiated():
    """Fixture for initiated KYC session"""
    return create_mock_kyc_session(
        status="INITIATED",
        routing_id="routing-123",
        kyc_link="https://kyc.example.com/link",
        initiated_at=datetime.now(timezone.utc)
    )


@pytest.fixture
def mock_kyc_session_not_started():
    """Fixture for NOT_STARTED KYC session"""
    return create_mock_kyc_session(
        id="session-123",
        status="NOT_STARTED"
    )


def setup_mock_prisma_kyc_with_update(mock_prisma, kyc_session):
    """Helper function to set up mock KYC session with update mock"""
    setup_mock_prisma_kyc(mock_prisma, kyc_session)
    mock_prisma.kyc_sessions.update = AsyncMock(return_value=kyc_session)


@pytest.fixture
def kyc_data():
    """Fixture for KYC data response"""
    return {
        "kycLink": "https://kyc.example.com/link",
        "tosLink": "https://tos.example.com/link",
        "kycStatus": "initiated",
        "tosStatus": "pending",
        "message": "KYC link generated",
        "kycCompleted": False
    }


@pytest.fixture
def kyc_data_completed():
    """Fixture for completed KYC data response"""
    return {
        "kycCompleted": True,
        "message": "KYC already completed"
    }


@pytest.fixture
def mock_zynk_patches(kyc_data):
    """Fixture that provides patched Zynk functions"""
    with patch('app.routers.kyc_router.get_kyc_link_from_zynk', new_callable=AsyncMock) as mock_get_link, \
         patch('app.routers.kyc_router.email_service') as mock_email:
        mock_get_link.return_value = kyc_data
        mock_email.send_kyc_link_email = AsyncMock()
        yield mock_get_link, mock_email


class TestGetKycStatus:
    @pytest.mark.asyncio
    async def test_get_kyc_status_existing_session(self, client, auth_headers, mock_prisma_context, mock_kyc_session_initiated, setup_dependency_override):
        """Test getting KYC status with existing session"""
        setup_mock_prisma_kyc(mock_prisma_context, mock_kyc_session_initiated)
        
        response = make_get_request(client, "/api/v1/kyc/status", auth_headers)
        
        data = assert_success_response(response)
        assert data["data"]["status"] == "INITIATED"
        assert data["data"]["routing_id"] == "routing-123"
    
    @pytest.mark.asyncio
    async def test_get_kyc_status_no_session(self, client, auth_headers, mock_prisma_context, setup_dependency_override):
        """Test getting KYC status when no session exists"""
        mock_kyc_session = create_mock_kyc_session(status="NOT_STARTED")
        
        setup_mock_prisma_kyc(mock_prisma_context, None, create_return_value=mock_kyc_session)
        
        response = make_get_request(client, "/api/v1/kyc/status", auth_headers)
        
        data = assert_success_response(response)
        assert data["data"]["status"] == "NOT_STARTED"
    
    @pytest.mark.asyncio
    async def test_get_kyc_status_unauthorized(self, client):
        """Test getting KYC status without authentication"""
        response = make_get_request(client, "/api/v1/kyc/status")
        
        assert response.status_code == status.HTTP_401_UNAUTHORIZED


class TestGetKycLink:
    @pytest.mark.asyncio
    async def test_get_kyc_link_not_started(self, client, auth_headers, mock_prisma_context, mock_kyc_session_not_started, kyc_data, mock_zynk_patches, setup_dependency_override):
        """Test getting KYC link when status is NOT_STARTED"""
        setup_mock_prisma_kyc_with_update(mock_prisma_context, mock_kyc_session_not_started)
        
        response = make_get_request(client, "/api/v1/kyc/link", auth_headers)
        
        data = assert_success_response(response)
        assert data["data"]["kycLink"] == "https://kyc.example.com/link"
    
    @pytest.mark.asyncio
    async def test_get_kyc_link_already_initiated(self, client, auth_headers, mock_prisma_context, setup_dependency_override):
        """Test getting KYC link when already initiated"""
        mock_kyc_session = create_mock_kyc_session(
            status="INITIATED",
            kyc_link="https://kyc.example.com/existing-link"
        )
        
        setup_mock_prisma_kyc(mock_prisma_context, mock_kyc_session)
        
        response = make_get_request(client, "/api/v1/kyc/link", auth_headers)
        
        data = assert_success_response(response)
        assert data["data"]["kycLink"] == "https://kyc.example.com/existing-link"
    
    @pytest.mark.asyncio
    async def test_get_kyc_link_approved(self, client, auth_headers, mock_prisma_context, setup_dependency_override):
        """Test getting KYC link when already approved"""
        mock_kyc_session = create_mock_kyc_session(
            status="APPROVED",
            kyc_link=None
        )
        
        setup_mock_prisma_kyc(mock_prisma_context, mock_kyc_session)
        
        response = make_get_request(client, "/api/v1/kyc/link", auth_headers)
        
        data = assert_success_response(response)
        assert data["data"]["kycStatus"] == "approved"
        assert data["data"]["kycLink"] is None
    
    @pytest.mark.asyncio
    async def test_get_kyc_link_no_zynk_entity_id(self, client, mock_prisma_context, auth_headers_no_zynk):
        """Test getting KYC link without zynk_entity_id"""
        response = make_get_request(client, "/api/v1/kyc/link", auth_headers_no_zynk)
        
        assert_error_response(response, status.HTTP_400_BAD_REQUEST, "profile setup")
    
    @pytest.mark.asyncio
    async def test_get_kyc_link_kyc_already_completed(self, client, auth_headers, mock_prisma_context, mock_kyc_session_not_started, kyc_data_completed, setup_dependency_override):
        """Test getting KYC link when KYC is already completed"""
        setup_mock_prisma_kyc_with_update(mock_prisma_context, mock_kyc_session_not_started)
        
        with patch('app.routers.kyc_router.get_kyc_link_from_zynk', new_callable=AsyncMock) as mock_get_link:
            mock_get_link.return_value = kyc_data_completed
            
            response = make_get_request(client, "/api/v1/kyc/link", auth_headers)
            
            data = assert_success_response(response)
            assert data["data"]["kycStatus"] == "approved"

