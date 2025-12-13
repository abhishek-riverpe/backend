import pytest
from unittest.mock import patch, MagicMock
from datetime import datetime, timedelta, timezone
from ...services.captcha_service import CaptchaService


class TestCaptchaService:
    """Tests for CaptchaService"""
    
    @pytest.fixture
    def captcha_service(self):
        """Create a fresh CaptchaService instance for each test"""
        return CaptchaService()
    
    def test_generate_captcha_returns_tuple(self, captcha_service):
        """Test that generate_captcha returns a tuple of 3 items"""
        result = captcha_service.generate_captcha()
        assert isinstance(result, tuple)
        assert len(result) == 3
    
    def test_generate_captcha_id_format(self, captcha_service):
        """Test that captcha ID is generated"""
        captcha_id, _, _ = captcha_service.generate_captcha()
        assert isinstance(captcha_id, str)
        assert len(captcha_id) > 0
    
    def test_generate_captcha_code_format(self, captcha_service):
        """Test that captcha code has correct format"""
        _, captcha_code, _ = captcha_service.generate_captcha()
        assert isinstance(captcha_code, str)
        assert len(captcha_code) == captcha_service.CAPTCHA_LENGTH
        # Should not contain ambiguous characters
        assert 'O' not in captcha_code.upper()
        assert 'I' not in captcha_code.upper()
        assert '0' not in captcha_code
        assert '1' not in captcha_code
    
    def test_generate_captcha_image_format(self, captcha_service):
        """Test that captcha image is base64 encoded"""
        _, _, captcha_image = captcha_service.generate_captcha()
        assert isinstance(captcha_image, str)
        assert len(captcha_image) > 0
    
    def test_generate_captcha_with_session_id(self, captcha_service):
        """Test generating captcha with session ID"""
        session_id = "session-123"
        captcha_id, _, _ = captcha_service.generate_captcha(session_id)
        assert session_id in captcha_id
    
    def test_validate_captcha_success(self, captcha_service):
        """Test successful captcha validation"""
        captcha_id, captcha_code, _ = captcha_service.generate_captcha()
        
        is_valid, message = captcha_service.validate_captcha(captcha_id, captcha_code)
        
        assert is_valid is True
        assert message == ""
    
    def test_validate_captcha_invalid_code(self, captcha_service):
        """Test validation with wrong code"""
        captcha_id, _, _ = captcha_service.generate_captcha()
        
        is_valid, message = captcha_service.validate_captcha(captcha_id, "WRONG")
        
        assert is_valid is False
        assert "Invalid CAPTCHA code" in message
    
    def test_validate_captcha_invalid_id(self, captcha_service):
        """Test validation with invalid captcha ID"""
        is_valid, message = captcha_service.validate_captcha("invalid-id", "ABC12")
        
        assert is_valid is False
        assert "Invalid or expired" in message
    
    def test_validate_captcha_expired(self, captcha_service):
        """Test validation with expired captcha"""
        captcha_id, captcha_code, _ = captcha_service.generate_captcha()
        
        # Manually expire the captcha
        captcha_service._captcha_store[captcha_id]["expires_at"] = datetime.now(timezone.utc) - timedelta(minutes=1)
        
        is_valid, message = captcha_service.validate_captcha(captcha_id, captcha_code)
        
        assert is_valid is False
        assert "expired" in message.lower()
    
    def test_validate_captcha_already_validated(self, captcha_service):
        """Test that validated captcha can be reused within time window"""
        captcha_id, captcha_code, _ = captcha_service.generate_captcha()
        
        # First validation
        is_valid1, _ = captcha_service.validate_captcha(captcha_id, captcha_code)
        assert is_valid1 is True
        
        # Second validation should also succeed (within validation window)
        is_valid2, _ = captcha_service.validate_captcha(captcha_id, captcha_code)
        assert is_valid2 is True
    
    def test_validate_captcha_strips_whitespace(self, captcha_service):
        """Test that user input is stripped of whitespace"""
        captcha_id, captcha_code, _ = captcha_service.generate_captcha()
        
        # Validate with whitespace
        is_valid, _ = captcha_service.validate_captcha(captcha_id, f" {captcha_code} ")
        
        assert is_valid is True
    
    def test_get_captcha_info_valid(self, captcha_service):
        """Test getting captcha info for valid captcha"""
        captcha_id, captcha_code, _ = captcha_service.generate_captcha()
        
        info = captcha_service.get_captcha_info(captcha_id)
        
        assert info is not None
        assert info["code"] == captcha_code
        assert "expires_at" in info
        assert "attempts" in info
    
    def test_get_captcha_info_invalid(self, captcha_service):
        """Test getting captcha info for invalid ID"""
        info = captcha_service.get_captcha_info("invalid-id")
        assert info is None
    
    def test_get_captcha_info_expired(self, captcha_service):
        """Test getting info for expired captcha"""
        captcha_id, _, _ = captcha_service.generate_captcha()
        
        # Manually expire
        captcha_service._captcha_store[captcha_id]["expires_at"] = datetime.now(timezone.utc) - timedelta(minutes=1)
        
        info = captcha_service.get_captcha_info(captcha_id)
        assert info is None
    
    def test_validate_captcha_increments_attempts(self, captcha_service):
        """Test that validation attempts are tracked"""
        captcha_id, _, _ = captcha_service.generate_captcha()
        
        # Wrong attempt
        captcha_service.validate_captcha(captcha_id, "WRONG")
        info = captcha_service.get_captcha_info(captcha_id)
        assert info["attempts"] == 1
        
        # Another wrong attempt
        captcha_service.validate_captcha(captcha_id, "WRONG2")
        info = captcha_service.get_captcha_info(captcha_id)
        assert info["attempts"] == 2


class TestCaptchaServiceCleanup:
    """Tests for CAPTCHA cleanup functionality"""
    
    @pytest.fixture
    def captcha_service(self):
        """Create a fresh CaptchaService instance"""
        return CaptchaService()
    
    def test_cleanup_expired_captchas(self, captcha_service):
        """Test that expired captchas are cleaned up"""
        # Generate a captcha
        captcha_id, _, _ = captcha_service.generate_captcha()
        
        # Manually expire it
        captcha_service._captcha_store[captcha_id]["expires_at"] = datetime.now(timezone.utc) - timedelta(minutes=1)
        
        # Force cleanup by setting last_cleanup to far in past
        captcha_service._last_cleanup = datetime.now(timezone.utc) - timedelta(seconds=captcha_service.CLEANUP_INTERVAL_SECONDS + 100)
        
        # Trigger cleanup by generating new captcha
        captcha_service.generate_captcha()
        
        # Expired captcha should be removed
        info = captcha_service.get_captcha_info(captcha_id)
        assert info is None

