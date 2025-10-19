from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    database_url: str
    jwt_secret: str
    google_client_id: str | None = None
    google_client_secret: str | None = None
    frontend_url: str = "http://localhost:5173"
    backend_url: str | None = None
    # Max request size in megabytes (used by custom middleware)
    max_request_size_mb: int = 10

    class Config:
        env_file = ".env"

settings = Settings()
