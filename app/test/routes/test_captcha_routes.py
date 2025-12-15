import pytest
from unittest.mock import patch
from fastapi.testclient import TestClient
from fastapi import status
from ...main import app


@pytest.fixture
def client():
    return TestClient(app)


class TestGenerateCaptcha:
    @pytest.mark.asyncio
    async def test_generate_captcha_success(self, client):
        """Test successful CAPTCHA generation"""
        with patch('app.routers.captcha_routes.captcha_service') as mock_captcha:
            mock_captcha.generate_captcha.return_value = (
                "captcha-id-123",
                "ABC12",
                "base64encodedimage"
            )
            mock_captcha.CAPTCHA_EXPIRY_MINUTES = 5
            
            response = client.post("/api/v1/captcha/generate")
            
            assert response.status_code == status.HTTP_200_OK
            data = response.json()
            assert data["success"] is True
            assert data["message"] == "CAPTCHA generated successfully"
            assert "captcha_id" in data["data"]
            assert "captcha_code" in data["data"]
            assert "captcha_image" in data["data"]
            assert data["data"]["captcha_image"].startswith("data:image/png;base64,")
            assert "expires_in_seconds" in data["data"]
    
    @pytest.mark.asyncio
    async def test_generate_captcha_failure(self, client):
        """Test CAPTCHA generation failure"""
        with patch('app.routers.captcha_routes.captcha_service') as mock_captcha:
            mock_captcha.generate_captcha.side_effect = Exception("Generation failed")
            
            response = client.post("/api/v1/captcha/generate")
            
            assert response.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR
            assert "Failed to generate CAPTCHA" in response.json()["detail"]


class TestValidateCaptcha:
    @pytest.mark.asyncio
    async def test_validate_captcha_success(self, client):
        """Test successful CAPTCHA validation"""
        with patch('app.routers.captcha_routes.captcha_service') as mock_captcha:
            mock_captcha.validate_captcha.return_value = (True, None)
            
            response = client.post(
                "/api/v1/captcha/validate",
                json={
                    "captcha_id": "captcha-id-123",
                    "captcha_code": "ABC12"
                }
            )
            
            assert response.status_code == status.HTTP_200_OK
            data = response.json()
            assert data["success"] is True
            assert data["message"] == "CAPTCHA validated successfully"
            assert data["data"]["valid"] is True
            assert data["error"] is None
    
    @pytest.mark.asyncio
    async def test_validate_captcha_invalid(self, client):
        """Test invalid CAPTCHA validation"""
        with patch('app.routers.captcha_routes.captcha_service') as mock_captcha:
            mock_captcha.validate_captcha.return_value = (False, "Invalid CAPTCHA code")
            
            response = client.post(
                "/api/v1/captcha/validate",
                json={
                    "captcha_id": "captcha-id-123",
                    "captcha_code": "WRONG"
                }
            )
            
            assert response.status_code == status.HTTP_200_OK
            data = response.json()
            assert data["success"] is False
            assert data["data"]["valid"] is False
            assert data["error"] is not None
            assert data["error"]["code"] == "INVALID_CAPTCHA"
    
    @pytest.mark.asyncio
    async def test_validate_captcha_missing_fields(self, client):
        """Test validation with missing fields"""
        response = client.post(
            "/api/v1/captcha/validate",
            json={}
        )
        
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY
    
    @pytest.mark.asyncio
    async def test_validate_captcha_failure(self, client):
        """Test CAPTCHA validation failure"""
        with patch('app.routers.captcha_routes.captcha_service') as mock_captcha:
            mock_captcha.validate_captcha.side_effect = Exception("Validation failed")
            
            response = client.post(
                "/api/v1/captcha/validate",
                json={
                    "captcha_id": "captcha-id-123",
                    "captcha_code": "ABC12"
                }
            )
            
            assert response.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR
            assert "Failed to validate CAPTCHA" in response.json()["detail"]

