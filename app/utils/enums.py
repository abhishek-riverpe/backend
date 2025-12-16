from enum import Enum

class UserStatusEnum(str, Enum):
    REGISTERED = "REGISTERED"
    PENDING = "PENDING"
    ACTIVE = "ACTIVE"
    SUSPENDED = "SUSPENDED"
    CLOSED = "CLOSED"

class EntityTypeEnum(str, Enum):
    INDIVIDUAL = "INDIVIDUAL"
    BUSINESS = "BUSINESS"

class KycStatusEnum(str, Enum):
    NOT_STARTED = "NOT_STARTED"
    INITIATED = "INITIATED"
    REVIEWING = "REVIEWING"
    ADDITIONAL_INFO_REQUIRED = "ADDITIONAL_INFO_REQUIRED"
    REJECTED = "REJECTED"
    APPROVED = "APPROVED"

class WebhookEventCategory(str, Enum):
    KYC = "KYC"
    TRANSFER = "TRANSFER"
    WEBHOOK = "WEBHOOK"

class WebhookDeliveryStatusEnum(str, Enum):
    PENDING = "PENDING"
    SUCCESS = "SUCCESS"
    FAILED = "FAILED"
    RETRYING = "RETRYING"

class OtpTypeEnum(str, Enum):
    PHONE_VERIFICATION = "PHONE_VERIFICATION"
    EMAIL_VERIFICATION = "EMAIL_VERIFICATION"
    PASSWORD_RESET = "PASSWORD_RESET"

class OtpStatusEnum(str, Enum):
    PENDING = "PENDING"
    VERIFIED = "VERIFIED"
    EXPIRED = "EXPIRED"
    FAILED = "FAILED"

class SessionStatusEnum(str, Enum):
    ACTIVE = "ACTIVE"
    EXPIRED = "EXPIRED"
    LOGGED_OUT = "LOGGED_OUT"
    REVOKED = "REVOKED"


class LoginMethodEnum(str, Enum):
    EMAIL_PASSWORD = "EMAIL_PASSWORD"
    GOOGLE_OAUTH = "GOOGLE_OAUTH"
    PHONE_OTP = "PHONE_OTP"
    APPLE_ID = "APPLE_ID"


class AccountStatusEnum(str, Enum):
    INACTIVE = "INACTIVE"
    ACTIVE = "ACTIVE"