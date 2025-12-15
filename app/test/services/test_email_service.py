import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from datetime import datetime
from ...services.email_service import EmailService

# Test-only IP address - RFC 5737 documentation address (192.0.2.0/24)
# Safe to use in tests as it's reserved for documentation purposes
TEST_IP_ADDRESS = "192.0.2.1"


class TestEmailService:
    """Tests for EmailService"""
    
    @pytest.fixture
    def email_service(self):
        """Create EmailService instance"""
        return EmailService()
    
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
    async def test_send_password_change_notification_no_config(self, email_service, device_info, location_info):
        """Test sending password change notification when mail config is not set"""
        result = await email_service.send_password_change_notification(
            email="test@example.com",
            user_name="Test User",
            device_info=device_info,
            location_info=location_info
        )
        assert result is True
    
    @pytest.mark.asyncio
    async def test_send_password_change_notification_with_config(self, email_service, device_info, location_info):
        """Test sending password change notification with mail config"""
        email_service.mail_config = MagicMock()
        email_service.fast_mail = MagicMock()
        email_service.fast_mail.send_message = AsyncMock()
        
        result = await email_service.send_password_change_notification(
            email="test@example.com",
            user_name="Test User",
            device_info=device_info,
            location_info=location_info,
            ip_address=TEST_IP_ADDRESS,
            timestamp=datetime.now()
        )
        
        assert result is True
        email_service.fast_mail.send_message.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_send_password_change_notification_minimal_info(self, email_service):
        """Test sending with minimal device and location info"""
        result = await email_service.send_password_change_notification(
            email="test@example.com",
            user_name="Test User",
            device_info={},
            location_info={}
        )
        assert result is True
    
    @pytest.mark.asyncio
    async def test_send_password_change_notification_exception(self, email_service, device_info, location_info):
        """Test exception handling in password change notification"""
        email_service.mail_config = MagicMock()
        email_service.fast_mail = MagicMock()
        email_service.fast_mail.send_message = AsyncMock(side_effect=Exception("Email error"))
        
        result = await email_service.send_password_change_notification(
            email="test@example.com",
            user_name="Test User",
            device_info=device_info,
            location_info=location_info
        )
        
        assert result is False
    
    @pytest.mark.asyncio
    async def test_send_failed_login_notification_no_config(self, email_service, device_info, location_info):
        """Test sending failed login notification when mail config is not set"""
        result = await email_service.send_failed_login_notification(
            email="test@example.com",
            user_name="Test User",
            failed_attempts=3,
            device_info=device_info,
            location_info=location_info
        )
        assert result is True
    
    @pytest.mark.asyncio
    async def test_send_failed_login_notification_with_config(self, email_service, device_info, location_info):
        """Test sending failed login notification with mail config"""
        email_service.mail_config = MagicMock()
        email_service.fast_mail = MagicMock()
        email_service.fast_mail.send_message = AsyncMock()
        
        result = await email_service.send_failed_login_notification(
            email="test@example.com",
            user_name="Test User",
            failed_attempts=5,
            device_info=device_info,
            location_info=location_info
        )
        
        assert result is True
        email_service.fast_mail.send_message.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_send_kyc_link_email_no_config(self, email_service):
        """Test sending KYC link email when mail config is not set"""
        result = await email_service.send_kyc_link_email(
            email="test@example.com",
            user_name="Test User",
            kyc_link="https://kyc.example.com/verify/123"
        )
        assert result is True
    
    @pytest.mark.asyncio
    async def test_send_kyc_link_email_with_config(self, email_service):
        """Test sending KYC link email with mail config"""
        email_service.mail_config = MagicMock()
        email_service.fast_mail = MagicMock()
        email_service.fast_mail.send_message = AsyncMock()
        
        result = await email_service.send_kyc_link_email(
            email="test@example.com",
            user_name="Test User",
            kyc_link="https://kyc.example.com/verify/123",
            timestamp=datetime.now()
        )
        
        assert result is True
        email_service.fast_mail.send_message.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_send_funding_account_created_notification_no_config(self, email_service):
        """Test sending funding account notification when mail config is not set"""
        result = await email_service.send_funding_account_created_notification(
            email="test@example.com",
            user_name="Test User",
            bank_name="Test Bank",
            bank_account_number="1234567890",
            bank_routing_number="987654321",
            currency="USD"
        )
        assert result is True
    
    @pytest.mark.asyncio
    async def test_send_funding_account_created_notification_with_config(self, email_service):
        """Test sending funding account notification with mail config"""
        email_service.mail_config = MagicMock()
        email_service.fast_mail = MagicMock()
        email_service.fast_mail.send_message = AsyncMock()
        
        result = await email_service.send_funding_account_created_notification(
            email="test@example.com",
            user_name="Test User",
            bank_name="Test Bank",
            bank_account_number="1234567890",
            bank_routing_number="987654321",
            currency="USD",
            timestamp=datetime.now()
        )
        
        assert result is True
        email_service.fast_mail.send_message.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_send_funding_account_created_notification_masks_account(self, email_service):
        """Test that account number is masked in email"""
        email_service.mail_config = MagicMock()
        email_service.fast_mail = MagicMock()
        email_service.fast_mail.send_message = AsyncMock()
        
        await email_service.send_funding_account_created_notification(
            email="test@example.com",
            user_name="Test User",
            bank_name="Test Bank",
            bank_account_number="1234567890",
            bank_routing_number="987654321",
            currency="USD"
        )
        
        # Check that the message body contains masked account number
        call_args = email_service.fast_mail.send_message.call_args
        message = call_args[0][0]
        assert "****7890" in message.body  # Last 4 digits should be visible

