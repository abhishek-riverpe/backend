# app/config.py
from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    database_url: str
    jwt_secret: str
    google_client_id: str | None = None
    google_client_secret: str | None = None
    frontend_url: str = "http://localhost:5173"
    backend_url: str | None = None

    # Zynk API settings
    zynk_base_url: str | None = "https://qaapi.zynklabs.xyz"
    zynk_api_key: str | None = "2dfdbe8cbdbe7231375c93808d55cc32"
    zynk_timeout_s: int = 30

    # Max request size in megabytes (used by custom middleware)
    max_request_size_mb: int = 10

    # Add these to match your .env so they are NOT "extra"
    jwt_algorithm: str = "HS256"
    access_token_expire_minutes: int = 60

    # Pydantic v2 settings config
    model_config = SettingsConfigDict(
        env_file=".env",
        env_prefix="",        # map jwt_secret <-> JWT_SECRET etc.
        case_sensitive=False,
        extra="ignore",       # ignore any future unknown env vars
    )

settings = Settings()
