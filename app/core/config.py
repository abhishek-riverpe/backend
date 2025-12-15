import secrets
from pydantic_settings import BaseSettings, SettingsConfigDict  # type: ignore

class Settings(BaseSettings):
    database_url: str
    jwt_secret: str
    session_secret: str 
    google_client_id: str | None = None
    google_client_secret: str | None = None
    frontend_url: str = "http://localhost:5173"
    backend_url: str | None = None

    # Zynk API settings - MUST be set via environment variables
    zynk_base_url: str | None = None
    zynk_api_key: str | None = None
    zynk_timeout_s: int = 30
    zynk_default_routing_id: str | None = None
    zynk_webhook_secret: str | None = None 

    # AWS S3 settings
    aws_access_key_id: str | None = None
    aws_secret_access_key: str | None = None
    aws_region: str | None = None
    aws_s3_bucket_name: str | None = None
    aws_s3_bucket_owner: str | None = None

    # Max request size in megabytes (used by custom middleware)
    max_request_size_mb: int = 10

 
    jwt_algorithm: str = "HS256"
    jwt_allowed_algorithms: list[str] = ["HS256"] 
    access_token_expire_minutes: int = 15

    # SMS/OTP settings
    sms_provider: str = "mock"  
    twilio_account_sid: str | None = None
    twilio_auth_token: str | None = None
    twilio_phone_number: str | None = None

    # Email/SMTP settings
    mail_username: str | None = None
    mail_password: str | None = None
    mail_from: str | None = None
    mail_from_name: str = "RiverPe"
    mail_port: int = 587
    mail_server: str = "smtp.gmail.com"
    mail_starttls: bool = True
    mail_ssl_tls: bool = False
    use_credentials: bool = True
    validate_certs: bool = True

    # Password breach check (Have I Been Pwned)
    hibp_enabled: bool = True
    hibp_timeout_s: int = 5


    inactivity_timeout_minutes: int = 15

    # Concurrent session controls
    max_active_sessions: int = 3  

    # Test-only password constants (for unit tests)
    # These are safe to commit as they are only used in test environments
    test_password: str = "TestPass123!"
    test_password_hashed: str = "@Almamun2.O#@$"  # Mock hashed password for test user
    test_password_secure: str = "SecurePass123!"
    test_password_new: str = "NewSecurePass123!"
    test_password_wrong: str = "WrongPassword123!"
    test_password_weak: str = "weak"

    # Test-only IP addresses (RFC 5737 documentation addresses)
    # These are safe to commit as they are reserved for documentation/testing
    test_ip_address_1: str = "192.0.2.1"
    test_ip_address_2: str = "192.0.2.2"
    test_ip_public: str = "192.0.2.10"  # Public IP for testing (RFC 5737)
    test_ip_localhost: str = "127.0.0.1"  # Localhost (safe exception)
    test_ip_localhost_v6: str = "::1"  # IPv6 localhost (safe exception)
    test_ip_private_192: str = "192.168.1.1"  # Private network (RFC 1918)
    test_ip_private_10: str = "10.0.0.1"  # Private network (RFC 1918)

    # Test-only device and location info
    test_device_type: str = "desktop"
    test_device_name: str = "Test Device"
    test_os_name: str = "Windows"
    test_os_version: str = "10"
    test_browser_name: str = "Chrome"
    test_browser_version: str = "91.0"
    test_user_agent: str = "Mozilla/5.0"
    test_country: str = "United States"
    test_city: str = "New York"
    test_latitude: float = 40.7128
    test_longitude: float = -74.0060
    test_country_alt: str = "Canada"

    # Test-only entity IDs
    test_entity_id: str = "entity-123"
    test_session_id: str = "session-123"
    test_token: str = "token-123"

    # Pydantic v2 settings config
    model_config = SettingsConfigDict(
        env_file=".env",
        env_prefix="",
        case_sensitive=False,
        extra="ignore",       
    )

settings = Settings()


if settings.session_secret is None or settings.session_secret == "":
    import warnings
    warnings.warn(
        "SESSION_SECRET not set in environment. Generating a random secret for this session. "
        "This is not suitable for production! Please set SESSION_SECRET in your .env file.",
        UserWarning
    )

    settings.session_secret = secrets.token_urlsafe(32)

