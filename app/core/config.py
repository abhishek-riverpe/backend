import secrets
from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    database_url: str
    jwt_secret: str
    session_secret: str
    google_client_id: str | None = None
    google_client_secret: str | None = None
    frontend_url: str = "http://localhost:5173"
    backend_url: str | None = None

    # Auth0 Configuration
    auth0_domain: str | None = None  # e.g., "your-tenant.auth0.com"
    auth0_audience: str | None = None  # Your Auth0 API identifier
    auth0_algorithms: list[str] = ["RS256"]

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

    test_password: str | None = None
    test_password_hashed: str | None = None
    test_password_secure: str | None = None
    test_password_new: str | None = None
    test_password_wrong: str | None = None
    test_password_weak: str | None = None

    test_ip_address_1: str | None = None
    test_ip_address_2: str | None = None
    test_ip_public: str | None = None
    test_ip_localhost: str | None = None
    test_ip_localhost_v6: str | None = None
    test_ip_private_192: str | None = None
    test_ip_private_10: str | None = None

    test_device_type: str | None = None
    test_device_name: str | None = None
    test_os_name: str | None = None
    test_os_version: str | None = None
    test_browser_name: str | None = None
    test_browser_version: str | None = None
    test_user_agent: str | None = None
    test_country: str | None = None
    test_city: str | None = None
    test_latitude: float | None = None
    test_longitude: float | None = None
    test_country_alt: str | None = None

    test_entity_id: str | None = None
    test_session_id: str | None = None
    test_token: str | None = None

    model_config = SettingsConfigDict(
        env_file=[".env", ".env.test"],
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

