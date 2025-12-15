import secrets
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    database_url: str
    jwt_secret: str
    session_secret: str 
    google_client_id: str | None = None
    google_client_secret: str | None = None
    frontend_url: str = "http://localhost:5173"
    backend_url: str | None = None

    zynk_base_url: str | None = None
    zynk_api_key: str | None = None
    zynk_timeout_s: int = 30
    zynk_default_routing_id: str | None = None
    zynk_webhook_secret: str | None = None 

    aws_access_key_id: str | None = None
    aws_secret_access_key: str | None = None
    aws_region: str | None = None
    aws_s3_bucket_name: str | None = None
    aws_s3_bucket_owner: str | None = None

    max_request_size_mb: int = 10

 
    jwt_algorithm: str = "HS256"
    jwt_allowed_algorithms: list[str] = ["HS256"] 
    access_token_expire_minutes: int = 15

    sms_provider: str = "mock"  
    twilio_account_sid: str | None = None
    twilio_auth_token: str | None = None
    twilio_phone_number: str | None = None

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

    hibp_enabled: bool = True
    hibp_timeout_s: int = 5


    inactivity_timeout_minutes: int = 15

    max_active_sessions: int = 3  

    test_password: str = Field(default="TestPass123!")
    test_password_hashed: str = Field(default="@Almamun2.O#@$")
    test_password_secure: str = Field(default="SecurePass123!")
    test_password_new: str = Field(default="NewSecurePass123!")
    test_password_wrong: str = Field(default="WrongPassword123!")
    test_password_weak: str = Field(default="weak")

    test_ip_address_1: str = Field(default="192.0.2.1")
    test_ip_address_2: str = Field(default="192.0.2.2")
    test_ip_public: str = Field(default="192.0.2.10")
    test_ip_localhost: str = Field(default="127.0.0.1")
    test_ip_localhost_v6: str = Field(default="::1")
    test_ip_private_192: str = Field(default="192.0.2.3")
    test_ip_private_10: str = Field(default="10.0.0.1")

    test_device_type: str = Field(default="desktop")
    test_device_name: str = Field(default="Test Device")
    test_os_name: str = Field(default="Windows")
    test_os_version: str = Field(default="10")
    test_browser_name: str = Field(default="Chrome")
    test_browser_version: str = Field(default="91.0")
    test_user_agent: str = Field(default="Mozilla/5.0")
    test_country: str = Field(default="United States")
    test_city: str = Field(default="New York")
    test_latitude: float = Field(default=40.7128)
    test_longitude: float = Field(default=-74.0060)
    test_country_alt: str = Field(default="Canada")

    test_entity_id: str = Field(default="entity-123")
    test_session_id: str = Field(default="session-123")
    test_token: str = Field(default="token-123")

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

