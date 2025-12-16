import pytest
from ...utils.enums import (
    UserStatusEnum,
    EntityTypeEnum,
    KycStatusEnum,
    WebhookEventCategory,
    WebhookDeliveryStatusEnum,
    OtpTypeEnum,
    OtpStatusEnum,
    SessionStatusEnum,
    LoginMethodEnum,
    AccountStatusEnum
)


class TestUserStatusEnum:
    """Tests for UserStatusEnum"""

    def test_user_status_enum_values(self):
        """Test UserStatusEnum has correct values"""
        assert UserStatusEnum.REGISTERED == "REGISTERED"
        assert UserStatusEnum.PENDING == "PENDING"
        assert UserStatusEnum.ACTIVE == "ACTIVE"
        assert UserStatusEnum.SUSPENDED == "SUSPENDED"
        assert UserStatusEnum.CLOSED == "CLOSED"

    def test_user_status_enum_string_inheritance(self):
        """Test UserStatusEnum values are strings"""
        assert isinstance(UserStatusEnum.PENDING, str)


class TestEntityTypeEnum:
    """Tests for EntityTypeEnum"""
    
    def test_entity_type_enum_values(self):
        """Test EntityTypeEnum has correct values"""
        assert EntityTypeEnum.INDIVIDUAL == "INDIVIDUAL"
        assert EntityTypeEnum.BUSINESS == "BUSINESS"


class TestKycStatusEnum:
    """Tests for KycStatusEnum"""
    
    def test_kyc_status_enum_values(self):
        """Test KycStatusEnum has correct values"""
        assert KycStatusEnum.NOT_STARTED == "NOT_STARTED"
        assert KycStatusEnum.INITIATED == "INITIATED"
        assert KycStatusEnum.REVIEWING == "REVIEWING"
        assert KycStatusEnum.ADDITIONAL_INFO_REQUIRED == "ADDITIONAL_INFO_REQUIRED"
        assert KycStatusEnum.REJECTED == "REJECTED"
        assert KycStatusEnum.APPROVED == "APPROVED"


class TestWebhookEventCategory:
    """Tests for WebhookEventCategory"""
    
    def test_webhook_event_category_values(self):
        """Test WebhookEventCategory has correct values"""
        assert WebhookEventCategory.KYC == "KYC"
        assert WebhookEventCategory.TRANSFER == "TRANSFER"
        assert WebhookEventCategory.WEBHOOK == "WEBHOOK"


class TestWebhookDeliveryStatusEnum:
    """Tests for WebhookDeliveryStatusEnum"""
    
    def test_webhook_delivery_status_enum_values(self):
        """Test WebhookDeliveryStatusEnum has correct values"""
        assert WebhookDeliveryStatusEnum.PENDING == "PENDING"
        assert WebhookDeliveryStatusEnum.SUCCESS == "SUCCESS"
        assert WebhookDeliveryStatusEnum.FAILED == "FAILED"
        assert WebhookDeliveryStatusEnum.RETRYING == "RETRYING"


class TestOtpTypeEnum:
    """Tests for OtpTypeEnum"""
    
    def test_otp_type_enum_values(self):
        """Test OtpTypeEnum has correct values"""
        assert OtpTypeEnum.PHONE_VERIFICATION == "PHONE_VERIFICATION"
        assert OtpTypeEnum.EMAIL_VERIFICATION == "EMAIL_VERIFICATION"
        assert OtpTypeEnum.PASSWORD_RESET == "PASSWORD_RESET"


class TestOtpStatusEnum:
    """Tests for OtpStatusEnum"""
    
    def test_otp_status_enum_values(self):
        """Test OtpStatusEnum has correct values"""
        assert OtpStatusEnum.PENDING == "PENDING"
        assert OtpStatusEnum.VERIFIED == "VERIFIED"
        assert OtpStatusEnum.EXPIRED == "EXPIRED"
        assert OtpStatusEnum.FAILED == "FAILED"


class TestSessionStatusEnum:
    """Tests for SessionStatusEnum"""

    def test_session_status_enum_values(self):
        """Test SessionStatusEnum has correct values"""
        assert SessionStatusEnum.ACTIVE == "ACTIVE"
        assert SessionStatusEnum.EXPIRED == "EXPIRED"
        assert SessionStatusEnum.LOGGED_OUT == "LOGGED_OUT"
        assert SessionStatusEnum.REVOKED == "REVOKED"


class TestLoginMethodEnum:
    """Tests for LoginMethodEnum"""

    def test_login_method_enum_values(self):
        """Test LoginMethodEnum has correct values"""
        assert LoginMethodEnum.EMAIL_PASSWORD == "EMAIL_PASSWORD"
        assert LoginMethodEnum.GOOGLE_OAUTH == "GOOGLE_OAUTH"
        assert LoginMethodEnum.PHONE_OTP == "PHONE_OTP"
        assert LoginMethodEnum.APPLE_ID == "APPLE_ID"


class TestAccountStatusEnum:
    """Tests for AccountStatusEnum"""

    def test_account_status_enum_values(self):
        """Test AccountStatusEnum has correct values"""
        assert AccountStatusEnum.INACTIVE == "INACTIVE"
        assert AccountStatusEnum.ACTIVE == "ACTIVE"

