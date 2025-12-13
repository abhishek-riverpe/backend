import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from fastapi.testclient import TestClient
from fastapi import status
from ...main import app
from ...core.database import prisma


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def mock_otp_service():
    """Mock OTP service"""
    with patch('app.routers.otp_router.OTPService') as mock_service:
        mock_instance = MagicMock()
        mock_service.return_value = mock_instance
        yield mock_instance


class TestSendOtp:
    @pytest.mark.asyncio
    async def test_send_otp_success(self, client, mock_otp_service):
        """Test successful OTP send"""
        mock_otp_service.send_otp = AsyncMock(return_value=(
            True,
            "OTP sent successfully",
            {"otp_id": "otp-123", "expires_in": 300}
        ))
        
        response = client.post(
            "/api/v1/otp/send",
            json={
                "phone_number": "1234567890",
                "country_code": "+1"
            }
        )
        
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["success"] is True
        assert "OTP sent" in data["message"]
        assert data["data"] is not None
        assert "otp_id" in data["data"]
    
    @pytest.mark.asyncio
    async def test_send_otp_rate_limit(self, client, mock_otp_service):
        """Test OTP send rate limit"""
        mock_otp_service.send_otp = AsyncMock(return_value=(
            False,
            "Please wait 60 seconds before requesting another OTP",
            None
        ))
        
        response = client.post(
            "/api/v1/otp/send",
            json={
                "phone_number": "1234567890",
                "country_code": "+1"
            }
        )
        
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["success"] is False
        assert data["data"] is None
        assert "rate_limit" in data["meta"]["error_type"]
    
    @pytest.mark.asyncio
    async def test_send_otp_invalid_phone(self, client, mock_otp_service):
        """Test OTP send with invalid phone number"""
        mock_otp_service.send_otp = AsyncMock(side_effect=ValueError("Invalid phone number"))
        
        response = client.post(
            "/api/v1/otp/send",
            json={
                "phone_number": "invalid",
                "country_code": "+1"
            }
        )
        
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY
    
    @pytest.mark.asyncio
    async def test_send_otp_missing_fields(self, client):
        """Test OTP send with missing fields"""
        response = client.post(
            "/api/v1/otp/send",
            json={}
        )
        
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY


class TestVerifyOtp:
    @pytest.mark.asyncio
    async def test_verify_otp_success(self, client, mock_otp_service):
        """Test successful OTP verification"""
        mock_otp_service.verify_otp = AsyncMock(return_value=(
            True,
            "OTP verified successfully",
            {"verified": True}
        ))
        
        response = client.post(
            "/api/v1/otp/verify",
            json={
                "phone_number": "1234567890",
                "country_code": "+1",
                "otp_code": "123456"
            }
        )
        
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["success"] is True
        assert "verified" in data["message"].lower()
        assert data["data"] is not None
    
    @pytest.mark.asyncio
    async def test_verify_otp_invalid(self, client, mock_otp_service):
        """Test invalid OTP verification"""
        mock_otp_service.verify_otp = AsyncMock(return_value=(
            False,
            "Invalid OTP code",
            None
        ))
        
        response = client.post(
            "/api/v1/otp/verify",
            json={
                "phone_number": "1234567890",
                "country_code": "+1",
                "otp_code": "000000"
            }
        )
        
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["success"] is False
        assert data["data"] is None
        assert "invalid_otp" in data["meta"]["error_type"]
    
    @pytest.mark.asyncio
    async def test_verify_otp_expired(self, client, mock_otp_service):
        """Test expired OTP verification"""
        mock_otp_service.verify_otp = AsyncMock(return_value=(
            False,
            "OTP has expired",
            None
        ))
        
        response = client.post(
            "/api/v1/otp/verify",
            json={
                "phone_number": "1234567890",
                "country_code": "+1",
                "otp_code": "123456"
            }
        )
        
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["success"] is False
        assert "expired_otp" in data["meta"]["error_type"]


class TestResendOtp:
    @pytest.mark.asyncio
    async def test_resend_otp_success(self, client, mock_otp_service):
        """Test successful OTP resend"""
        mock_otp_service.send_otp = AsyncMock(return_value=(
            True,
            "OTP resent successfully",
            {"otp_id": "otp-456", "expires_in": 300}
        ))
        
        response = client.post(
            "/api/v1/otp/resend",
            json={
                "phone_number": "1234567890",
                "country_code": "+1"
            }
        )
        
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["success"] is True


class TestSendEmailOtp:
    @pytest.mark.asyncio
    async def test_send_email_otp_success(self, client, mock_otp_service):
        """Test successful email OTP send"""
        mock_otp_service.send_email_otp = AsyncMock(return_value=(
            True,
            "OTP sent to email successfully",
            {"otp_id": "email-otp-123"}
        ))
        
        response = client.post(
            "/api/v1/otp/email/send",
            json={
                "email": "test@example.com"
            }
        )
        
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["success"] is True
        assert data["data"] is not None
    
    @pytest.mark.asyncio
    async def test_send_email_otp_invalid_email(self, client, mock_otp_service):
        """Test email OTP send with invalid email"""
        mock_otp_service.send_email_otp = AsyncMock(side_effect=ValueError("Invalid email format"))
        
        response = client.post(
            "/api/v1/otp/email/send",
            json={
                "email": "invalid-email"
            }
        )
        
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY


class TestVerifyEmailOtp:
    @pytest.mark.asyncio
    async def test_verify_email_otp_success(self, client, mock_otp_service):
        """Test successful email OTP verification"""
        mock_otp_service.verify_email_otp = AsyncMock(return_value=(
            True,
            "Email OTP verified successfully",
            {"verified": True}
        ))
        
        response = client.post(
            "/api/v1/otp/email/verify",
            json={
                "email": "test@example.com",
                "otp_code": "123456"
            }
        )
        
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["success"] is True
        assert data["data"] is not None
    
    @pytest.mark.asyncio
    async def test_verify_email_otp_invalid(self, client, mock_otp_service):
        """Test invalid email OTP verification"""
        mock_otp_service.verify_email_otp = AsyncMock(return_value=(
            False,
            "Invalid OTP code",
            None
        ))
        
        response = client.post(
            "/api/v1/otp/email/verify",
            json={
                "email": "test@example.com",
                "otp_code": "000000"
            }
        )
        
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["success"] is False
        assert "invalid_otp" in data["meta"]["error_type"]


class TestResendEmailOtp:
    @pytest.mark.asyncio
    async def test_resend_email_otp_success(self, client, mock_otp_service):
        """Test successful email OTP resend"""
        mock_otp_service.send_email_otp = AsyncMock(return_value=(
            True,
            "Email OTP resent successfully",
            {"otp_id": "email-otp-456"}
        ))
        
        response = client.post(
            "/api/v1/otp/email/resend",
            json={
                "email": "test@example.com"
            }
        )
        
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["success"] is True

