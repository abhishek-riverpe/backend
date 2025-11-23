# app/core/config.py
import secrets
from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    database_url: str
    jwt_secret: str
    session_secret: str  # Separate secret for session cookies (must be different from jwt_secret)
    google_client_id: str | None = None
    google_client_secret: str | None = None
    frontend_url: str = "http://localhost:5173"
    backend_url: str | None = None

    # Zynk API settings - MUST be set via environment variables
    zynk_base_url: str | None = None
    zynk_api_key: str | None = None
    zynk_timeout_s: int = 30
    zynk_default_routing_id: str | None = None
    zynk_webhook_secret: str | None = None  # Secret for verifying webhook signatures

    # AWS S3 settings
    aws_access_key_id: str | None = None
    aws_secret_access_key: str | None = None
    aws_region: str | None = None
    aws_s3_bucket_name: str | None = None

    # Max request size in megabytes (used by custom middleware)
    max_request_size_mb: int = 10

    # Add these to match your .env so they are NOT "extra"
    jwt_algorithm: str = "HS256"
    # JWT algorithm whitelist - only these algorithms are allowed
    # Prevents algorithm confusion attacks (e.g., RS256 -> HS256 swap)
    jwt_allowed_algorithms: list[str] = ["HS256"]  # Only symmetric algorithms for now
    access_token_expire_minutes: int = 15

    # SMS/OTP settings
    sms_provider: str = "mock"  # 'twilio' or 'mock'
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

    # Session inactivity timeout (minutes)
    inactivity_timeout_minutes: int = 60

    # Concurrent session controls
    max_active_sessions: int = 3  # 0 or negative disables limiting

    # Pydantic v2 settings config
    model_config = SettingsConfigDict(
        env_file=".env",
        env_prefix="",        # map jwt_secret <-> JWT_SECRET etc.
        case_sensitive=False,
        extra="ignore",       # ignore any future unknown env vars
    )

settings = Settings()

# Generate a random session_secret if not provided (for development only)
if settings.session_secret is None or settings.session_secret == "":
    import warnings
    warnings.warn(
        "SESSION_SECRET not set in environment. Generating a random secret for this session. "
        "This is not suitable for production! Please set SESSION_SECRET in your .env file.",
        UserWarning
    )
    # Generate a random 32-byte hex string (same length as typical secrets)
    settings.session_secret = secrets.token_urlsafe(32)

