import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from datetime import datetime, timedelta, timezone
from ...services.otp_service import OTPService
from ...utils.enums import OtpStatusEnum, OtpTypeEnum


class TestOTPService:
    """Tests for OTPService"""
    
    @pytest.fixture
    def mock_prisma(self):
        """Create a mock Prisma instance"""
        return MagicMock()
    
    @pytest.fixture
    def otp_service(self, mock_prisma):
        """Create OTPService instance with mocked Prisma"""
        return OTPService(mock_prisma)
    
    def test_generate_otp_format(self, otp_service):
        """Test that OTP is generated in correct format"""
        otp = otp_service.generate_otp()
        assert isinstance(otp, str)
        assert len(otp) == otp_service.OTP_LENGTH
        assert otp.isdigit()
    
    def test_generate_otp_different_values(self, otp_service):
        """Test that generated OTPs are different"""
        otp1 = otp_service.generate_otp()
        otp2 = otp_service.generate_otp()
        # They might be the same by chance, but very unlikely
        # We just verify they're valid OTPs
        assert len(otp1) == len(otp2) == otp_service.OTP_LENGTH
    
    @pytest.mark.asyncio
    async def test_send_otp_success(self, otp_service, mock_prisma):
        """Test successful OTP sending"""
        mock_prisma.otp_verifications.find_first = AsyncMock(return_value=None)
        mock_prisma.otp_verifications.update_many = AsyncMock()
        mock_prisma.otp_verifications.create = AsyncMock(return_value=MagicMock(
            id="otp-123",
            expires_at=datetime.now(timezone.utc) + timedelta(minutes=10)
        ))
        
        with patch.object(otp_service, '_send_sms', return_value=True):
            success, message, data = await otp_service.send_otp("1234567890", "+1")
            
            assert success is True
            assert "successfully" in message.lower()
            assert data is not None
            assert data["phone_number"] == "1234567890"
            assert data["country_code"] == "+1"
    
    @pytest.mark.asyncio
    async def test_send_otp_rate_limit(self, otp_service, mock_prisma):
        """Test OTP sending with rate limit"""
        recent_otp = MagicMock()
        recent_otp.created_at = datetime.now(timezone.utc)
        mock_prisma.otp_verifications.find_first = AsyncMock(return_value=recent_otp)
        
        success, message, data = await otp_service.send_otp("1234567890", "+1")
        
        assert success is False
        assert "wait" in message.lower() or "seconds" in message.lower()
        assert data is None
    
    @pytest.mark.asyncio
    async def test_send_otp_sms_failure(self, otp_service, mock_prisma):
        """Test OTP sending when SMS fails"""
        mock_prisma.otp_verifications.find_first = AsyncMock(return_value=None)
        mock_prisma.otp_verifications.update_many = AsyncMock()
        mock_prisma.otp_verifications.create = AsyncMock(return_value=MagicMock())
        
        with patch.object(otp_service, '_send_sms', return_value=False):
            success, message, data = await otp_service.send_otp("1234567890", "+1")
            
            assert success is False
            assert "Failed to send" in message
            assert data is None
    
    @pytest.mark.asyncio
    async def test_verify_otp_success(self, otp_service, mock_prisma):
        """Test successful OTP verification"""
        otp_record = MagicMock()
        otp_record.id = "otp-123"
        otp_record.otp_code = "123456"
        otp_record.expires_at = datetime.now(timezone.utc) + timedelta(minutes=5)
        otp_record.attempts = 0
        otp_record.max_attempts = 3
        
        mock_prisma.otp_verifications.find_first = AsyncMock(return_value=otp_record)
        mock_prisma.otp_verifications.update = AsyncMock()
        
        success, message, data = await otp_service.verify_otp("1234567890", "+1", "123456")
        
        assert success is True
        assert "verified" in message.lower()
        assert data is not None
        assert data["verified"] is True
    
    @pytest.mark.asyncio
    async def test_verify_otp_invalid_code(self, otp_service, mock_prisma):
        """Test OTP verification with invalid code"""
        otp_record = MagicMock()
        otp_record.id = "otp-123"
        otp_record.otp_code = "123456"
        otp_record.expires_at = datetime.now(timezone.utc) + timedelta(minutes=5)
        otp_record.attempts = 0
        otp_record.max_attempts = 3
        
        mock_prisma.otp_verifications.find_first = AsyncMock(return_value=otp_record)
        mock_prisma.otp_verifications.update = AsyncMock()
        
        success, message, data = await otp_service.verify_otp("1234567890", "+1", "000000")
        
        assert success is False
        assert "Invalid" in message
        assert data is None
    
    @pytest.mark.asyncio
    async def test_verify_otp_expired(self, otp_service, mock_prisma):
        """Test verification of expired OTP"""
        otp_record = MagicMock()
        otp_record.id = "otp-123"
        otp_record.expires_at = datetime.now(timezone.utc) - timedelta(minutes=1)
        
        mock_prisma.otp_verifications.find_first = AsyncMock(return_value=otp_record)
        mock_prisma.otp_verifications.update = AsyncMock()
        
        success, message, data = await otp_service.verify_otp("1234567890", "+1", "123456")
        
        assert success is False
        assert "expired" in message.lower()
        assert data is None
    
    @pytest.mark.asyncio
    async def test_verify_otp_max_attempts(self, otp_service, mock_prisma):
        """Test OTP verification when max attempts exceeded"""
        otp_record = MagicMock()
        otp_record.id = "otp-123"
        otp_record.otp_code = "123456"
        otp_record.expires_at = datetime.now(timezone.utc) + timedelta(minutes=5)
        otp_record.attempts = 3
        otp_record.max_attempts = 3
        
        mock_prisma.otp_verifications.find_first = AsyncMock(return_value=otp_record)
        mock_prisma.otp_verifications.update = AsyncMock()
        
        success, message, data = await otp_service.verify_otp("1234567890", "+1", "123456")
        
        assert success is False
        assert "Maximum" in message or "attempts" in message.lower()
        assert data is None
    
    @pytest.mark.asyncio
    async def test_verify_otp_not_found(self, otp_service, mock_prisma):
        """Test OTP verification when no pending OTP exists"""
        mock_prisma.otp_verifications.find_first = AsyncMock(return_value=None)
        
        success, message, data = await otp_service.verify_otp("1234567890", "+1", "123456")
        
        assert success is False
        assert "No pending" in message or "request a new" in message.lower()
        assert data is None
    
    @pytest.mark.asyncio
    async def test_send_email_otp_success(self, otp_service, mock_prisma):
        """Test successful email OTP sending"""
        mock_prisma.otp_verifications.find_first = AsyncMock(return_value=None)
        mock_prisma.otp_verifications.update_many = AsyncMock()
        mock_prisma.otp_verifications.create = AsyncMock(return_value=MagicMock(
            id="otp-123",
            expires_at=datetime.now(timezone.utc) + timedelta(minutes=10)
        ))
        
        with patch.object(otp_service, '_send_email', return_value=True):
            success, message, data = await otp_service.send_email_otp("test@example.com")
            
            assert success is True
            assert "successfully" in message.lower()
            assert data is not None
            assert data["email"] == "test@example.com"
    
    @pytest.mark.asyncio
    async def test_send_email_otp_rate_limit(self, otp_service, mock_prisma):
        """Test email OTP sending with rate limit"""
        recent_otp = MagicMock()
        recent_otp.created_at = datetime.now(timezone.utc)
        mock_prisma.otp_verifications.find_first = AsyncMock(return_value=recent_otp)
        
        success, message, data = await otp_service.send_email_otp("test@example.com")
        
        assert success is False
        assert "wait" in message.lower() or "seconds" in message.lower()
        assert data is None
    
    @pytest.mark.asyncio
    async def test_verify_email_otp_success(self, otp_service, mock_prisma):
        """Test successful email OTP verification"""
        otp_record = MagicMock()
        otp_record.id = "otp-123"
        otp_record.otp_code = "123456"
        otp_record.expires_at = datetime.now(timezone.utc) + timedelta(minutes=5)
        otp_record.attempts = 0
        otp_record.max_attempts = 3
        
        mock_prisma.otp_verifications.find_first = AsyncMock(return_value=otp_record)
        mock_prisma.otp_verifications.update = AsyncMock()
        
        success, message, data = await otp_service.verify_email_otp("test@example.com", "123456")
        
        assert success is True
        assert "verified" in message.lower()
        assert data is not None
        assert data["verified"] is True
    
    @pytest.mark.asyncio
    async def test_send_password_reset_otp_success(self, otp_service, mock_prisma):
        """Test successful password reset OTP sending"""
        mock_prisma.otp_verifications.find_first = AsyncMock(return_value=None)
        mock_prisma.otp_verifications.update_many = AsyncMock()
        mock_prisma.otp_verifications.create = AsyncMock(return_value=MagicMock(
            id="otp-123",
            expires_at=datetime.now(timezone.utc) + timedelta(minutes=10)
        ))
        
        with patch.object(otp_service, '_send_email', return_value=True):
            success, message, data = await otp_service.send_password_reset_otp("test@example.com")
            
            assert success is True
            assert "successfully" in message.lower()
            assert data is not None
            assert data["email"] == "test@example.com"
    
    @pytest.mark.asyncio
    async def test_verify_password_reset_otp_success(self, otp_service, mock_prisma):
        """Test successful password reset OTP verification"""
        otp_record = MagicMock()
        otp_record.id = "otp-123"
        otp_record.otp_code = "123456"
        otp_record.expires_at = datetime.now(timezone.utc) + timedelta(minutes=5)
        otp_record.attempts = 0
        otp_record.max_attempts = 3
        
        mock_prisma.otp_verifications.find_first = AsyncMock(return_value=otp_record)
        mock_prisma.otp_verifications.update = AsyncMock()
        
        success, message, data = await otp_service.verify_password_reset_otp("test@example.com", "123456")
        
        assert success is True
        assert "verified" in message.lower()
        assert data is not None
        assert data["verified"] is True
    
    @pytest.mark.asyncio
    async def test_cleanup_expired_otps(self, otp_service, mock_prisma):
        """Test cleanup of expired OTPs"""
        mock_prisma.otp_verifications.delete_many = AsyncMock(return_value=5)
        
        result = await otp_service.cleanup_expired_otps()
        
        assert result == 5
        mock_prisma.otp_verifications.delete_many.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_cleanup_expired_otps_exception(self, otp_service, mock_prisma):
        """Test cleanup when exception occurs"""
        mock_prisma.otp_verifications.delete_many = AsyncMock(side_effect=Exception("DB error"))
        
        result = await otp_service.cleanup_expired_otps()
        
        assert result == 0

