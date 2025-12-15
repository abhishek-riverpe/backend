import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from datetime import datetime, timedelta, timezone
from ...services.session_service import SessionService
from ...utils.enums import SessionStatusEnum, LoginMethodEnum


class TestSessionService:
    """Tests for SessionService"""
    
    @pytest.fixture
    def mock_prisma(self):
        """Create a mock Prisma instance"""
        return MagicMock()
    
    @pytest.fixture
    def session_service(self, mock_prisma):
        """Create SessionService instance with mocked Prisma"""
        return SessionService(mock_prisma)
    
    @pytest.fixture
    def device_info(self):
        """Sample device info"""
        return {
            "device_type": "desktop",
            "device_name": "Test Device",
            "os_name": "Windows",
            "os_version": "10",
            "browser_name": "Chrome",
            "browser_version": "91.0"
        }
    
    @pytest.fixture
    def location_info(self):
        """Sample location info"""
        return {
            "country": "United States",
            "city": "New York",
            "latitude": 40.7128,
            "longitude": -74.0060
        }
    
    @pytest.mark.asyncio
    async def test_create_session_success(self, session_service, mock_prisma, device_info, location_info):
        """Test successful session creation"""
        mock_session = MagicMock()
        mock_session.id = "session-123"
        
        # Mock transaction context manager
        mock_tx = MagicMock()
        mock_tx.login_sessions.create = AsyncMock(return_value=mock_session)
        mock_tx.login_sessions.find_many = AsyncMock(return_value=[])
        mock_tx.__aenter__ = AsyncMock(return_value=mock_tx)
        mock_tx.__aexit__ = AsyncMock(return_value=None)
        mock_prisma.tx = MagicMock(return_value=mock_tx)
        
        result = await session_service.create_session(
            entity_id="entity-123",
            session_token="token-123",
            login_method=LoginMethodEnum.EMAIL_PASSWORD,
            ip_address="192.168.1.1",
            user_agent="Mozilla/5.0",
            device_info=device_info,
            location_info=location_info
        )
        
        assert result["id"] == "session-123"
        assert "expires_at" in result
        assert "is_suspicious" in result
        mock_tx.login_sessions.create.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_create_session_minimal_info(self, session_service, mock_prisma):
        """Test session creation with minimal information"""
        mock_session = MagicMock()
        mock_session.id = "session-123"
        
        # Mock transaction context manager
        mock_tx = MagicMock()
        mock_tx.login_sessions.create = AsyncMock(return_value=mock_session)
        mock_tx.login_sessions.find_many = AsyncMock(return_value=[])
        mock_tx.__aenter__ = AsyncMock(return_value=mock_tx)
        mock_tx.__aexit__ = AsyncMock(return_value=None)
        mock_prisma.tx = MagicMock(return_value=mock_tx)
        
        result = await session_service.create_session(
            entity_id="entity-123",
            session_token="token-123"
        )
        
        assert result["id"] == "session-123"
        mock_tx.login_sessions.create.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_create_session_enforces_concurrent_limit(self, session_service, mock_prisma):
        """Test that concurrent session limit is enforced"""
        # Create existing active sessions
        existing_sessions = [MagicMock(id=f"session-{i}") for i in range(3)]
        
        mock_session = MagicMock()
        mock_session.id = "session-new"
        
        # Mock transaction context manager
        mock_tx = MagicMock()
        mock_tx.login_sessions.find_many = AsyncMock(return_value=existing_sessions)
        mock_tx.login_sessions.update_many = AsyncMock()
        mock_tx.login_sessions.create = AsyncMock(return_value=mock_session)
        mock_tx.__aenter__ = AsyncMock(return_value=mock_tx)
        mock_tx.__aexit__ = AsyncMock(return_value=None)
        mock_prisma.tx = MagicMock(return_value=mock_tx)
        
        with patch('app.services.session_service.settings') as mock_settings:
            mock_settings.max_active_sessions = 3
            
            await session_service.create_session(
                entity_id="entity-123",
                session_token="token-new"
            )
            
            # Should revoke old sessions
            mock_tx.login_sessions.update_many.assert_called()
    
    @pytest.mark.asyncio
    async def test_update_activity_success(self, session_service, mock_prisma):
        """Test successful activity update"""
        mock_session = MagicMock()
        mock_session.last_activity_at = None
        mock_session.login_at = datetime.now(timezone.utc) - timedelta(minutes=5)
        mock_prisma.login_sessions.find_unique = AsyncMock(return_value=mock_session)
        mock_prisma.login_sessions.update = AsyncMock()
        
        result = await session_service.update_activity("token-123")
        
        assert result is True
        mock_prisma.login_sessions.update.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_update_activity_session_not_found(self, session_service, mock_prisma):
        """Test activity update when session not found"""
        mock_prisma.login_sessions.find_unique = AsyncMock(return_value=None)
        
        result = await session_service.update_activity("invalid-token")
        
        assert result is None
    
    @pytest.mark.asyncio
    async def test_update_activity_expired(self, session_service, mock_prisma):
        """Test activity update when session is expired due to inactivity"""
        mock_session = MagicMock()
        mock_session.last_activity_at = None
        mock_session.login_at = datetime.now(timezone.utc) - timedelta(hours=1)
        mock_prisma.login_sessions.find_unique = AsyncMock(return_value=mock_session)
        mock_prisma.login_sessions.update = AsyncMock()
        
        with patch('app.services.session_service.settings') as mock_settings:
            mock_settings.inactivity_timeout_minutes = 15
            
            result = await session_service.update_activity("token-123")
            
            assert result is False
            # Should update status to EXPIRED
            update_call = mock_prisma.login_sessions.update.call_args
            assert update_call[1]["data"]["status"] == SessionStatusEnum.EXPIRED
    
    @pytest.mark.asyncio
    async def test_logout_session_success(self, session_service, mock_prisma):
        """Test successful session logout"""
        mock_prisma.login_sessions.update = AsyncMock()
        
        result = await session_service.logout_session("token-123")
        
        assert result is True
        mock_prisma.login_sessions.update.assert_called_once()
        update_call = mock_prisma.login_sessions.update.call_args
        assert update_call[1]["data"]["status"] == SessionStatusEnum.LOGGED_OUT
    
    @pytest.mark.asyncio
    async def test_logout_session_exception(self, session_service, mock_prisma):
        """Test logout when exception occurs"""
        mock_prisma.login_sessions.update = AsyncMock(side_effect=Exception("DB error"))
        
        result = await session_service.logout_session("token-123")
        
        assert result is False
    
    @pytest.mark.asyncio
    async def test_revoke_session_success(self, session_service, mock_prisma):
        """Test successful session revocation"""
        mock_prisma.login_sessions.update = AsyncMock()
        
        result = await session_service.revoke_session("session-123")
        
        assert result is True
        mock_prisma.login_sessions.update.assert_called_once()
        update_call = mock_prisma.login_sessions.update.call_args
        assert update_call[1]["data"]["status"] == SessionStatusEnum.REVOKED
    
    @pytest.mark.asyncio
    async def test_get_active_sessions(self, session_service, mock_prisma):
        """Test getting active sessions for entity"""
        mock_session = MagicMock()
        mock_session.id = "session-123"
        mock_session.device_type = "desktop"
        mock_session.device_name = "Test Device"
        mock_session.os_name = "Windows"
        mock_session.browser_name = "Chrome"
        mock_session.ip_address = "192.168.1.1"
        mock_session.country = "United States"
        mock_session.city = "New York"
        mock_session.login_at = datetime.now(timezone.utc)
        mock_session.last_activity_at = datetime.now(timezone.utc)
        mock_session.is_suspicious = False
        
        mock_prisma.login_sessions.find_many = AsyncMock(return_value=[mock_session])
        
        result = await session_service.get_active_sessions("entity-123")
        
        assert len(result) == 1
        assert result[0]["id"] == "session-123"
        assert result[0]["device_type"] == "desktop"
    
    @pytest.mark.asyncio
    async def test_get_session_history(self, session_service, mock_prisma):
        """Test getting session history"""
        mock_session = MagicMock()
        mock_session.id = "session-123"
        mock_session.status = SessionStatusEnum.ACTIVE
        mock_session.login_method = LoginMethodEnum.EMAIL_PASSWORD
        mock_session.device_name = "Test Device"
        mock_session.device_type = "desktop"
        mock_session.os_name = "Windows"
        mock_session.city = "New York"
        mock_session.country = "United States"
        mock_session.ip_address = "192.168.1.1"
        mock_session.login_at = datetime.now(timezone.utc)
        mock_session.logout_at = None
        mock_session.is_suspicious = False
        
        mock_prisma.login_sessions.find_many = AsyncMock(return_value=[mock_session])
        
        result = await session_service.get_session_history("entity-123", limit=50)
        
        assert len(result) == 1
        assert result[0]["id"] == "session-123"
        assert result[0]["status"] == SessionStatusEnum.ACTIVE
    
    @pytest.mark.asyncio
    async def test_cleanup_expired_sessions(self, session_service, mock_prisma):
        """Test cleanup of expired sessions"""
        mock_prisma.login_sessions.update_many = AsyncMock(return_value=10)
        
        result = await session_service.cleanup_expired_sessions()
        
        assert result == 10
        mock_prisma.login_sessions.update_many.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_revoke_all_sessions(self, session_service, mock_prisma):
        """Test revoking all sessions for entity"""
        mock_prisma.login_sessions.update_many = AsyncMock(return_value=5)
        
        result = await session_service.revoke_all_sessions("entity-123")
        
        assert result == 5
        mock_prisma.login_sessions.update_many.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_revoke_all_sessions_except_token(self, session_service, mock_prisma):
        """Test revoking all sessions except specified token"""
        mock_prisma.login_sessions.update_many = AsyncMock(return_value=4)
        
        result = await session_service.revoke_all_sessions("entity-123", except_token="token-keep")
        
        assert result == 4
        update_call = mock_prisma.login_sessions.update_many.call_args
        where_clause = update_call[1]["where"]
        assert where_clause["entity_id"] == "entity-123"
        assert "session_token" in where_clause
    
    @pytest.mark.asyncio
    async def test_check_suspicious_login_different_country(self, session_service, mock_prisma):
        """Test detection of suspicious login from different country"""
        existing_session = MagicMock()
        existing_session.country = "United States"
        existing_session.ip_address = "192.168.1.1"
        existing_session.login_at = datetime.now(timezone.utc) - timedelta(hours=1)
        
        mock_session = MagicMock()
        mock_session.id = "session-new"
        
        # Mock transaction context manager
        mock_tx = MagicMock()
        mock_tx.login_sessions.find_many = AsyncMock(return_value=[existing_session])
        mock_tx.login_sessions.create = AsyncMock(return_value=mock_session)
        mock_tx.__aenter__ = AsyncMock(return_value=mock_tx)
        mock_tx.__aexit__ = AsyncMock(return_value=None)
        mock_prisma.tx = MagicMock(return_value=mock_tx)
        
        # Mock _check_suspicious_login to use mock_prisma (not mock_tx)
        mock_prisma.login_sessions.find_many = AsyncMock(return_value=[existing_session])
        
        result = await session_service.create_session(
            entity_id="entity-123",
            session_token="token-new",
            ip_address="192.168.1.2",
            location_info={"country": "Canada"}  # Different country
        )
        
        assert result["is_suspicious"] is True
    
    @pytest.mark.asyncio
    async def test_check_suspicious_login_no_history(self, session_service, mock_prisma):
        """Test that login is not suspicious when no previous sessions"""
        mock_session = MagicMock()
        mock_session.id = "session-new"
        
        # Mock transaction context manager
        mock_tx = MagicMock()
        mock_tx.login_sessions.find_many = AsyncMock(return_value=[])
        mock_tx.login_sessions.create = AsyncMock(return_value=mock_session)
        mock_tx.__aenter__ = AsyncMock(return_value=mock_tx)
        mock_tx.__aexit__ = AsyncMock(return_value=None)
        mock_prisma.tx = MagicMock(return_value=mock_tx)
        
        result = await session_service.create_session(
            entity_id="entity-123",
            session_token="token-new"
        )
        
        assert result["is_suspicious"] is False

