import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from fastapi.testclient import TestClient
from fastapi import status
from datetime import datetime, timezone, timedelta
from ...main import app
from ...core import auth
from ...core.database import prisma

@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def mock_user():
    from types import SimpleNamespace
    return SimpleNamespace(
        id="test-user-id-123",
        email="test@example.com",
        first_name="Test",
        last_name="User",
        password="@Almamun2.O#@$",
        email_verified=True,
        login_attempts=0,
        locked_until=None,
        status="ACTIVE",
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
        zynk_entity_id="zynk-123",
        entity_type="individual",
        date_of_birth=datetime(1990, 1, 1, tzinfo=timezone.utc),
        nationality="US",
        phone_number="1234567890",
        country_code="+1",
    )


@pytest.fixture
def mock_captcha():
    with patch('app.routers.auth_routes.captcha_service') as mock:
        mock.validate_captcha.return_value = (True, None)
        yield mock


@pytest.fixture
def mock_email_service():
    with patch('app.routers.auth_routes.email_service') as mock:
        mock.send_failed_login_notification = AsyncMock()
        mock.send_password_change_notification = AsyncMock()
        yield mock


@pytest.fixture
def mock_zynk_client():
    with patch('app.routers.auth_routes._create_entity_in_zynk', new_callable=AsyncMock) as mock:
        mock.return_value = {"data": {"entityId": "zynk-entity-123"}}
        yield mock


class TestCheckCaptchaRequired: 
    @pytest.mark.asyncio
    async def test_check_captcha_required_no_user(self, client):
        """Test when user doesn't exist"""
        with patch('app.routers.auth_routes.prisma') as mock_prisma:
            mock_prisma.entities.find_unique = AsyncMock(return_value=None)
            
            response = client.post(
                "/api/v1/auth/check-captcha-required",
                json={"email": "nonexistent@example.com"}
            )
            
            assert response.status_code == status.HTTP_200_OK
            data = response.json()
            assert data["captcha_required"] is False
            assert data["login_attempts"] == 0
    
    @pytest.mark.asyncio
    async def test_check_captcha_required_below_threshold(self, client, mock_user):
        mock_user.login_attempts = 2
        
        with patch('app.routers.auth_routes.prisma') as mock_prisma:
            mock_prisma.entities.find_unique = AsyncMock(return_value=mock_user)
            
            response = client.post(
                "/api/v1/auth/check-captcha-required",
                json={"email": "test@example.com"}
            )
            
            assert response.status_code == status.HTTP_200_OK
            data = response.json()
            assert data["captcha_required"] is False
            assert data["login_attempts"] == 2
    
    @pytest.mark.asyncio
    async def test_check_captcha_required_above_threshold(self, client, mock_user):
        mock_user.login_attempts = 3
        
        with patch('app.routers.auth_routes.prisma') as mock_prisma:
            mock_prisma.entities.find_unique = AsyncMock(return_value=mock_user)
            
            response = client.post(
                "/api/v1/auth/check-captcha-required",
                json={"email": "test@example.com"}
            )
            
            assert response.status_code == status.HTTP_200_OK
            data = response.json()
            assert data["captcha_required"] is True
            assert data["login_attempts"] == 3
    
    @pytest.mark.asyncio
    async def test_check_captcha_required_missing_email(self, client):
        response = client.post(
            "/api/v1/auth/check-captcha-required",
            json={}
        )
        
        assert response.status_code == status.HTTP_400_BAD_REQUEST


class TestCheckEmail:
    
    @pytest.mark.asyncio
    async def test_check_email_available(self, client):
        with patch('app.routers.auth_routes._email_exists_in_zynk', new_callable=AsyncMock) as mock_exists:
            mock_exists.return_value = False
            
            response = client.post(
                "/api/v1/auth/check-email",
                json={"email": "herdoy77@example.com"}
            )
            
            assert response.status_code == status.HTTP_200_OK
            data = response.json()
            assert data["available"] is True
            assert "available" in data["message"].lower()
    
    @pytest.mark.asyncio
    async def test_check_email_taken(self, client):
        with patch('app.routers.auth_routes._email_exists_in_zynk', new_callable=AsyncMock) as mock_exists:
            mock_exists.return_value = True
            
            response = client.post(
                "/api/v1/auth/check-email",
                json={"email": "existing@example.com"}
            )
            
            assert response.status_code == status.HTTP_200_OK
            data = response.json()
            assert data["available"] is False
            assert "already registered" in data["message"].lower()
    
    @pytest.mark.asyncio
    async def test_check_email_invalid_format(self, client):
        response = client.post(
            "/api/v1/auth/check-email",
            json={"email": "invalid-email"}
        )
        
        assert response.status_code == status.HTTP_400_BAD_REQUEST
    
    @pytest.mark.asyncio
    async def test_check_email_missing(self, client):
        response = client.post(
            "/api/v1/auth/check-email",
            json={}
        )
        
        assert response.status_code == status.HTTP_400_BAD_REQUEST


class TestSignup:
    
    @pytest.mark.asyncio
    async def test_signup_success(self, client, mock_captcha, mock_zynk_client):
        signup_data = {
            "first_name": "John",
            "last_name": "Doe",
            "email": "newuser@example.com",
            "password": "SecurePass123!",
            "date_of_birth": "01/15/1990",
            "nationality": "US",
            "phone_number": "1234567890",
            "country_code": "+1",
            "captcha_id": "captcha-123",
            "captcha_code": "ABC12"
        }
        
        with patch('app.routers.security.settings.hibp_enabled', False):
            with patch('app.routers.auth_routes._email_exists_in_zynk', new_callable=AsyncMock) as mock_exists:
                mock_exists.return_value = False
                
                with patch('app.routers.auth_routes.prisma') as mock_prisma:
                    mock_tx_ctx = MagicMock()
                    mock_tx = MagicMock()
                    mock_tx.__aenter__ = AsyncMock(return_value=mock_tx_ctx)
                    mock_tx.__aexit__ = AsyncMock(return_value=None)
                    mock_prisma.tx = MagicMock(return_value=mock_tx)
                    
                    mock_entity = MagicMock()
                    mock_entity.id = "new-user-id"
                    mock_entity.email = "newuser@example.com"
                    mock_entity.first_name = "John"
                    mock_entity.last_name = "Doe"
                    mock_entity.email_verified = False
                    mock_entity.status = "PENDING"
                    mock_entity.zynk_entity_id = "zynk-entity-123"
                    mock_tx_ctx.entities.create = AsyncMock(return_value=mock_entity)
                    mock_tx_ctx.entities.update = AsyncMock(return_value=mock_entity)
                    
                    mock_prisma.kyc_sessions.create = AsyncMock()
                    
                    response = client.post(
                        "/api/v1/auth/signup",
                        json=signup_data
                    )
                    
                    if response.status_code != status.HTTP_201_CREATED:
                        print(f"Response status: {response.status_code}")
                        print(f"Response body: {response.json()}")
                    
                    assert response.status_code == status.HTTP_201_CREATED
                    data = response.json()
                    assert data["success"] is True
                    assert "access_token" in data["data"]
                    assert "refresh_token" in data["data"]
                    assert data["data"]["user"]["email"] == "newuser@example.com"
    
    @pytest.mark.asyncio
    async def test_signup_email_already_exists(self, client, mock_captcha):
        signup_data = {
            "first_name": "John",
            "last_name": "Doe",
            "email": "existing@example.com",
            "password": "SecurePass123!",
            "date_of_birth": "01/15/1990",
            "nationality": "US",
            "phone_number": "1234567890",
            "country_code": "+1",
            "captcha_id": "captcha-123",
            "captcha_code": "ABC12"
        }
        
        with patch('app.routers.security.settings.hibp_enabled', False):
            with patch('app.routers.auth_routes._email_exists_in_zynk', new_callable=AsyncMock) as mock_exists:
                mock_exists.return_value = True
                
                response = client.post(
                    "/api/v1/auth/signup",
                    json=signup_data
                )
                
                assert response.status_code == status.HTTP_409_CONFLICT
                assert "already registered" in response.json()["detail"].lower()
    
    @pytest.mark.asyncio
    async def test_signup_invalid_captcha(self, client):
        signup_data = {
            "first_name": "John",
            "last_name": "Doe",
            "email": "newuser@example.com",
            "password": "SecurePass123!",
            "date_of_birth": "01/15/1990",
            "nationality": "US",
            "phone_number": "1234567890",
            "country_code": "+1",
            "captcha_id": "captcha-123",
            "captcha_code": "WRONG"
        }
        
        with patch('app.routers.auth_routes.captcha_service') as mock_captcha:
            mock_captcha.validate_captcha.return_value = (False, "Invalid CAPTCHA")
            
            with patch('app.routers.auth_routes._email_exists_in_zynk', new_callable=AsyncMock) as mock_exists:
                mock_exists.return_value = False
                
                response = client.post(
                    "/api/v1/auth/signup",
                    json=signup_data
                )
                
                assert response.status_code == status.HTTP_400_BAD_REQUEST
                assert "captcha" in response.json()["detail"].lower()
    
    @pytest.mark.asyncio
    async def test_signup_weak_password(self, client, mock_captcha):
        signup_data = {
            "first_name": "John",
            "last_name": "Doe",
            "email": "newuser@example.com",
            "password": "weak",
            "date_of_birth": "01/15/1990",
            "nationality": "US",
            "phone_number": "1234567890",
            "country_code": "+1",
            "captcha_id": "captcha-123",
            "captcha_code": "ABC12"
        }
        
        with patch('app.routers.auth_routes._email_exists_in_zynk', new_callable=AsyncMock) as mock_exists:
            mock_exists.return_value = False
            
            response = client.post(
                "/api/v1/auth/signup",
                json=signup_data
            )
            
            assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY


class TestSignin:
    
    @pytest.mark.asyncio
    async def test_signin_success(self, client, mock_user):
        signin_data = {
            "email": "test@example.com",
            "password": "TestPass123!"
        }
        
        with patch('app.routers.auth_routes.prisma') as mock_prisma:
            mock_prisma.entities.find_unique = AsyncMock(return_value=mock_user)
            mock_prisma.entities.update = AsyncMock(return_value=mock_user)
            
            with patch('app.routers.auth_routes.pwd_context.verify', return_value=True):
                with patch('app.routers.auth_routes._create_session_for_user', new_callable=AsyncMock):
                    response = client.post(
                        "/api/v1/auth/signin",
                        json=signin_data
                    )
                    
                    assert response.status_code == status.HTTP_200_OK
                    data = response.json()
                    assert data["success"] is True
                    assert "access_token" in data["data"]
                    assert "refresh_token" in data["data"]
                    assert data["data"]["user"]["email"] == "test@example.com"
    
    @pytest.mark.asyncio
    async def test_signin_invalid_credentials(self, client, mock_user):
        signin_data = {
            "email": "test@example.com",
            "password": "WrongPassword123!"
        }
        
        with patch('app.routers.auth_routes.prisma') as mock_prisma:
            mock_prisma.entities.find_unique = AsyncMock(return_value=mock_user)
            mock_prisma.entities.update = AsyncMock()
            
            with patch('app.routers.auth_routes.pwd_context.verify', return_value=False):
                response = client.post(
                    "/api/v1/auth/signin",
                    json=signin_data
                )
                
                assert response.status_code == status.HTTP_401_UNAUTHORIZED
                assert "invalid" in response.json()["detail"].lower()
    
    @pytest.mark.asyncio
    async def test_signin_user_not_found(self, client):
        signin_data = {
            "email": "nonexistent@example.com",
            "password": "SomePassword123!"
        }
        
        with patch('app.routers.auth_routes.prisma') as mock_prisma:
            mock_prisma.entities.find_unique = AsyncMock(return_value=None)
            
            response = client.post(
                "/api/v1/auth/signin",
                json=signin_data
            )
            
            assert response.status_code == status.HTTP_401_UNAUTHORIZED
    
    @pytest.mark.asyncio
    async def test_signin_account_locked(self, client, mock_user):
        mock_user.locked_until = datetime.now(timezone.utc) + timedelta(minutes=15)
        
        signin_data = {
            "email": "test@example.com",
            "password": "TestPass123!"
        }
        
        with patch('app.routers.auth_routes.prisma') as mock_prisma:
            mock_prisma.entities.find_unique = AsyncMock(return_value=mock_user)
            mock_prisma.entities.update = AsyncMock()
            
            with patch('app.routers.auth_routes.pwd_context.verify', return_value=False):
                response = client.post(
                    "/api/v1/auth/signin",
                    json=signin_data
                )
                
                # Should return 423 Locked if lock_until is set
                assert response.status_code in [status.HTTP_401_UNAUTHORIZED, status.HTTP_423_LOCKED]


class TestForgotPassword:
    @pytest.mark.asyncio
    async def test_forgot_password_request_success(self, client, mock_user):
        with patch('app.routers.auth_routes.prisma') as mock_prisma:
            mock_prisma.entities.find_unique = AsyncMock(return_value=mock_user)
            
            with patch('app.routers.auth_routes.OTPService') as mock_otp_service:
                mock_instance = MagicMock()
                mock_instance.send_password_reset_otp = AsyncMock(return_value=(True, "OTP sent", {}))
                mock_otp_service.return_value = mock_instance
                
                response = client.post(
                    "/api/v1/auth/forgot-password/request",
                    json={"email": "test@example.com"}
                )
                
                assert response.status_code == status.HTTP_200_OK
                data = response.json()
                assert data["success"] is True
    
    @pytest.mark.asyncio
    async def test_forgot_password_confirm_success(self, client, mock_user):
        with patch('app.routers.security.settings.hibp_enabled', False):
            with patch('app.routers.auth_routes.OTPService') as mock_otp_service:
                mock_instance = MagicMock()
                mock_instance.verify_password_reset_otp = AsyncMock(return_value=(True, "Verified", {}))
                mock_otp_service.return_value = mock_instance
                
                with patch('app.routers.auth_routes.prisma') as mock_prisma:
                    mock_prisma.entities.update = AsyncMock()
                    
                    response = client.post(
                        "/api/v1/auth/forgot-password/confirm",
                        json={
                            "email": "test@example.com",
                            "otp_code": "123456",
                            "new_password": "NewSecurePass123!"
                        }
                    )
                    
                    assert response.status_code == status.HTTP_200_OK
                    data = response.json()
                    assert data["success"] is True
                    assert "reset successfully" in data["message"].lower()
    
    @pytest.mark.asyncio
    async def test_forgot_password_confirm_invalid_otp(self, client):
        with patch('app.routers.auth_routes.OTPService') as mock_otp_service:
            mock_instance = MagicMock()
            mock_instance.verify_password_reset_otp = AsyncMock(return_value=(False, "Invalid OTP", {}))
            mock_otp_service.return_value = mock_instance
            
            response = client.post(
                "/api/v1/auth/forgot-password/confirm",
                json={
                    "email": "test@example.com",
                    "otp_code": "000000",
                    "new_password": "NewSecurePass123!"
                }
            )
            
            assert response.status_code == status.HTTP_400_BAD_REQUEST


class TestRefreshToken:
    @pytest.mark.asyncio
    async def test_refresh_token_success(self, client, mock_user):
        refresh_token = auth.create_refresh_token(data={"sub": str(mock_user.id), "type": "refresh"})
        
        with patch('app.routers.auth_routes.prisma') as mock_prisma:
            mock_prisma.entities.find_unique = AsyncMock(return_value=mock_user)
            
            with patch('app.routers.auth_routes._create_session_for_user', new_callable=AsyncMock):
                response = client.post(
                    "/api/v1/auth/refresh",
                    json={"refresh_token": refresh_token}
                )
                
                assert response.status_code == status.HTTP_200_OK
                data = response.json()
                assert data["success"] is True
                assert "access_token" in data["data"]
                assert "refresh_token" in data["data"]
    
    @pytest.mark.asyncio
    async def test_refresh_token_from_cookie(self, client, mock_user):
        refresh_token = auth.create_refresh_token(data={"sub": str(mock_user.id), "type": "refresh"})
        
        with patch('app.routers.auth_routes.prisma') as mock_prisma:
            mock_prisma.entities.find_unique = AsyncMock(return_value=mock_user)
            
            with patch('app.routers.auth_routes._create_session_for_user', new_callable=AsyncMock):
                response = client.post(
                    "/api/v1/auth/refresh",
                    cookies={"rp_refresh": refresh_token}
                )
                
                assert response.status_code == status.HTTP_200_OK
    
    @pytest.mark.asyncio
    async def test_refresh_token_missing(self, client):
        response = client.post("/api/v1/auth/refresh")
        
        assert response.status_code == status.HTTP_401_UNAUTHORIZED


class TestLogout:
    @pytest.mark.asyncio
    async def test_logout_success(self, client, mock_user):
        access_token = auth.create_access_token(data={"sub": str(mock_user.id), "type": "access"})
        
        with patch('app.routers.auth_routes.SessionService') as mock_session_service:
            mock_instance = MagicMock()
            mock_instance.logout_session = AsyncMock()
            mock_session_service.return_value = mock_instance
            
            response = client.post(
                "/api/v1/auth/logout",
                headers={"Authorization": f"Bearer {access_token}"}
            )
            
            assert response.status_code == status.HTTP_200_OK
            data = response.json()
            assert data["success"] is True


class TestChangePassword:
    @pytest.mark.asyncio
    async def test_change_password_success(self, client, mock_user):
        access_token = auth.create_access_token(data={"sub": str(mock_user.id), "type": "access"})
        
        # Override dependency to return mock_user
        from ...core.auth import get_current_entity
        app.dependency_overrides[get_current_entity] = lambda: mock_user
        
        with patch('app.routers.security.settings.hibp_enabled', False):
            with patch('app.routers.auth_routes.pwd_context.verify', return_value=True):
                with patch('app.routers.auth_routes.prisma') as mock_prisma:
                    mock_prisma.entities.update = AsyncMock()
                    
                    with patch('app.routers.auth_routes.SessionService') as mock_session_service:
                        mock_instance = MagicMock()
                        mock_instance.revoke_all_sessions = AsyncMock()
                        mock_session_service.return_value = mock_instance
                        
                        with patch('app.routers.auth_routes.email_service') as mock_email:
                            mock_email.send_password_change_notification = AsyncMock()
                            
                            response = client.post(
                                "/api/v1/auth/change-password",
                                headers={"Authorization": f"Bearer {access_token}"},
                                json={
                                    "current_password": "TestPass123!",
                                    "new_password": "NewSecurePass123!"
                                }
                            )
                            
                            assert response.status_code == status.HTTP_200_OK
                            data = response.json()
                            assert data["success"] is True
        
        app.dependency_overrides.clear()
    
    @pytest.mark.asyncio
    async def test_change_password_wrong_current(self, client, mock_user):
        access_token = auth.create_access_token(data={"sub": str(mock_user.id), "type": "access"})
        
        app.dependency_overrides[auth.get_current_entity] = lambda: mock_user
        
        with patch('app.routers.auth_routes.pwd_context.verify', return_value=False):
            response = client.post(
                "/api/v1/auth/change-password",
                headers={"Authorization": f"Bearer {access_token}"},
                json={
                    "current_password": "WrongPassword123!",
                    "new_password": "NewSecurePass123!"
                }
            )
            
            assert response.status_code == status.HTTP_401_UNAUTHORIZED
        
        app.dependency_overrides.clear()
    
    @pytest.mark.asyncio
    async def test_change_password_same_password(self, client, mock_user):
        access_token = auth.create_access_token(data={"sub": str(mock_user.id), "type": "access"})
        
        from ...core.auth import get_current_entity
        app.dependency_overrides[get_current_entity] = lambda: mock_user
        
        with patch('app.routers.auth_routes.pwd_context.verify', return_value=True):
            response = client.post(
                "/api/v1/auth/change-password",
                headers={"Authorization": f"Bearer {access_token}"},
                json={
                    "current_password": "TestPass123!",
                    "new_password": "TestPass123!"
                }
            )
            
            assert response.status_code == status.HTTP_400_BAD_REQUEST
        
        app.dependency_overrides.clear()


class TestPing:
    @pytest.mark.asyncio
    async def test_ping_success(self, client, mock_user):
        access_token = auth.create_access_token(data={"sub": str(mock_user.id), "type": "access"})
        
        response = client.get(
            "/api/v1/auth/ping",
            headers={"Authorization": f"Bearer {access_token}"}
        )
        
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["success"] is True
        assert data["message"] == "pong"
    
    @pytest.mark.asyncio
    async def test_ping_no_token(self, client):
        response = client.get("/api/v1/auth/ping")
        
        assert response.status_code == status.HTTP_401_UNAUTHORIZED


class TestLogoutAll:                    
    @pytest.mark.asyncio
    async def test_logout_all_success(self, client, mock_user):
        access_token = auth.create_access_token(data={"sub": str(mock_user.id), "type": "access"})
        
        from ...core.auth import get_current_entity
        app.dependency_overrides[get_current_entity] = lambda: mock_user
        
        with patch('app.routers.auth_routes.SessionService') as mock_session_service:
            mock_instance = MagicMock()
            mock_instance.revoke_all_sessions = AsyncMock(return_value=3)
            mock_session_service.return_value = mock_instance
            
            response = client.post(
                "/api/v1/auth/logout-all",
                headers={"Authorization": f"Bearer {access_token}"}
            )
            
            assert response.status_code == status.HTTP_200_OK
            data = response.json()
            assert data["success"] is True
            assert "revoked" in data["data"]
        
        app.dependency_overrides.clear()

