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
        zynk_entity_id="zynk-123",
    )


@pytest.fixture
def mock_funding_account():
    """Create a mock funding account"""
    from types import SimpleNamespace
    return SimpleNamespace(
        id="funding-account-123",
        entity_id="test-user-id-123",
        zynk_funding_account_id="zynk-funding-123",
        bank_name="Test Bank",
        bank_account_number="123456",
        bank_routing_number="987654",
        currency="USD",
        status="ACTIVE",
        deleted_at=None,
    )


@pytest.fixture
def mock_wallet_account():
    """Create a mock wallet account"""
    from types import SimpleNamespace
    mock_wallet = SimpleNamespace(
        id="wallet-123",
        entity_id="test-user-id-123",
        chain="ethereum",
        wallet_name="Test Wallet",
    )
    wallet_account = SimpleNamespace(
        id="wallet-account-123",
        address="0x1234567890123456789012345678901234567890",
        wallet=mock_wallet,
        deleted_at=None,
    )
    return wallet_account


class TestGetTeleportDetails:
    @pytest.mark.asyncio
    async def test_get_teleport_details_success(self, client, mock_user, mock_funding_account, mock_wallet_account):
        """Test successful teleport details retrieval"""
        from ...core.auth import get_current_entity
        app.dependency_overrides[get_current_entity] = lambda: mock_user
        
        mock_wallet = MagicMock()
        mock_wallet.wallet_accounts = [mock_wallet_account]
        mock_wallet.chain = "ethereum"
        mock_wallet.wallet_name = "Test Wallet"
        
        zynk_response = {
            "success": True,
            "data": [{"teleportId": "teleport-123"}]
        }
        
        with patch('app.routers.teleport_router.prisma') as mock_prisma:
            mock_prisma.funding_accounts.find_first = AsyncMock(return_value=mock_funding_account)
            mock_prisma.wallets.find_many = AsyncMock(return_value=[mock_wallet])
            
            with patch('app.routers.teleport_router.httpx.AsyncClient') as mock_client_class:
                mock_client = MagicMock()
                mock_client_class.return_value.__aenter__.return_value = mock_client
                mock_response = MagicMock()
                mock_response.status_code = 200
                mock_response.json.return_value = zynk_response
                mock_client.get = AsyncMock(return_value=mock_response)
                
                response = client.get(
                    "/api/v1/teleport",
                    headers={"Authorization": f"Bearer {auth.create_access_token(data={'sub': str(mock_user.id), 'type': 'access'})}"}
                )
                
                assert response.status_code == status.HTTP_200_OK
                data = response.json()
                assert data["success"] is True
                assert data["data"]["teleportId"] == "teleport-123"
                assert data["data"]["fundingAccount"] is not None
                assert data["data"]["walletAccount"] is not None
        
        app.dependency_overrides.clear()
    
    @pytest.mark.asyncio
    async def test_get_teleport_details_no_funding_account(self, client, mock_user):
        """Test teleport details when no funding account exists"""
        from ...core.auth import get_current_entity
        app.dependency_overrides[get_current_entity] = lambda: mock_user
        
        with patch('app.routers.teleport_router.prisma') as mock_prisma:
            mock_prisma.funding_accounts.find_first = AsyncMock(return_value=None)
            
            response = client.get(
                "/api/v1/teleport",
                headers={"Authorization": f"Bearer {auth.create_access_token(data={'sub': str(mock_user.id), 'type': 'access'})}"}
            )
            
            assert response.status_code == status.HTTP_200_OK
            data = response.json()
            assert data["success"] is True
            assert data["data"]["fundingAccount"] is None
            assert "No funding account found" in data["message"]
        
        app.dependency_overrides.clear()


class TestCreateTeleport:
    @pytest.mark.asyncio
    async def test_create_teleport_success(self, client, mock_user, mock_funding_account, mock_wallet_account):
        """Test successful teleport creation"""
        from ...core.auth import get_current_entity
        app.dependency_overrides[get_current_entity] = lambda: mock_user
        
        zynk_response = {
            "success": True,
            "data": {
                "data": {
                    "teleportId": "teleport-456"
                },
                "message": "Teleport created successfully"
            }
        }
        
        with patch('app.routers.teleport_router.prisma') as mock_prisma:
            mock_prisma.funding_accounts.find_first = AsyncMock(return_value=mock_funding_account)
            mock_prisma.wallet_accounts.find_first = AsyncMock(return_value=mock_wallet_account)
            
            with patch('app.routers.teleport_router.httpx.AsyncClient') as mock_client_class:
                mock_client = MagicMock()
                mock_client_class.return_value.__aenter__.return_value = mock_client
                mock_response = MagicMock()
                mock_response.status_code = 200
                mock_response.json.return_value = zynk_response
                mock_client.post = AsyncMock(return_value=mock_response)
                
                response = client.post(
                    "/api/v1/teleport",
                    headers={"Authorization": f"Bearer {auth.create_access_token(data={'sub': str(mock_user.id), 'type': 'access'})}"},
                    json={
                        "walletAccountId": "wallet-account-123"
                    }
                )
                
                assert response.status_code == status.HTTP_201_CREATED
                data = response.json()
                assert data["success"] is True
                assert data["data"]["teleportId"] == "teleport-456"
        
        app.dependency_overrides.clear()
    
    @pytest.mark.asyncio
    async def test_create_teleport_no_funding_account(self, client, mock_user):
        """Test teleport creation without funding account"""
        from ...core.auth import get_current_entity
        app.dependency_overrides[get_current_entity] = lambda: mock_user
        
        with patch('app.routers.teleport_router.prisma') as mock_prisma:
            mock_prisma.funding_accounts.find_first = AsyncMock(return_value=None)
            
            response = client.post(
                "/api/v1/teleport",
                headers={"Authorization": f"Bearer {auth.create_access_token(data={'sub': str(mock_user.id), 'type': 'access'})}"},
                json={
                    "walletAccountId": "wallet-account-123"
                }
            )
            
            assert response.status_code == status.HTTP_404_NOT_FOUND
            data = response.json()
            assert "Funding account not found" in data["detail"]["message"]
        
        app.dependency_overrides.clear()
    
    @pytest.mark.asyncio
    async def test_create_teleport_no_zynk_funding_account_id(self, client, mock_user):
        """Test teleport creation without zynk_funding_account_id"""
        from ...core.auth import get_current_entity
        app.dependency_overrides[get_current_entity] = lambda: mock_user
        
        mock_funding_account_no_zynk = MagicMock()
        mock_funding_account_no_zynk.zynk_funding_account_id = None
        
        with patch('app.routers.teleport_router.prisma') as mock_prisma:
            mock_prisma.funding_accounts.find_first = AsyncMock(return_value=mock_funding_account_no_zynk)
            
            response = client.post(
                "/api/v1/teleport",
                headers={"Authorization": f"Bearer {auth.create_access_token(data={'sub': str(mock_user.id), 'type': 'access'})}"},
                json={
                    "walletAccountId": "wallet-account-123"
                }
            )
            
            assert response.status_code == status.HTTP_400_BAD_REQUEST
            data = response.json()
            assert "not properly configured" in data["detail"]["message"]
        
        app.dependency_overrides.clear()
    
    @pytest.mark.asyncio
    async def test_create_teleport_wallet_account_not_found(self, client, mock_user, mock_funding_account):
        """Test teleport creation with non-existent wallet account"""
        from ...core.auth import get_current_entity
        app.dependency_overrides[get_current_entity] = lambda: mock_user
        
        with patch('app.routers.teleport_router.prisma') as mock_prisma:
            mock_prisma.funding_accounts.find_first = AsyncMock(return_value=mock_funding_account)
            mock_prisma.wallet_accounts.find_first = AsyncMock(return_value=None)
            
            response = client.post(
                "/api/v1/teleport",
                headers={"Authorization": f"Bearer {auth.create_access_token(data={'sub': str(mock_user.id), 'type': 'access'})}"},
                json={
                    "walletAccountId": "non-existent-wallet"
                }
            )
            
            assert response.status_code == status.HTTP_404_NOT_FOUND
            data = response.json()
            assert "Wallet account not found" in data["detail"]["message"]
        
        app.dependency_overrides.clear()

