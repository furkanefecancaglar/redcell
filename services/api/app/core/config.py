"""Application configuration via pydantic-settings, env-driven."""
from typing import Optional

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    PROJECT_NAME: str = "RedCell API"
    API_V1_STR: str = "/api/v1"
    VERSION: str = "1.0.0"
    DEBUG: bool = False

    # Database. Defaults to SQLite for dev/tests; set DATABASE_URL for Postgres.
    DATABASE_URL: str = "sqlite+aiosqlite:///./redcell.db"
    DB_ECHO: bool = False

    # Redis (rate limit, job queue, cache)
    REDIS_URL: str = "redis://localhost:6379/0"
    REDIS_KEY_PREFIX: str = "redcell"

    # Security
    SECRET_KEY: str = "dev-only-change-me"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24 * 7  # 7 days
    API_KEY_PREFIX: str = "rk_live_"

    # Rate limiting (per key/IP, fixed window)
    RATE_LIMIT_ENABLED: bool = True
    RATE_LIMIT_REQUESTS: int = 100
    RATE_LIMIT_WINDOW_SECONDS: int = 60

    # Limits
    MAX_INPUT_CHARS: int = 20000
    MAX_AGENT_PROMPT_CHARS: int = 50000

    # Cloudflare settings (for edge services proxy)
    CLOUDFLARE_WORKER_URL: str = "https://redcell.redcellv1.workers.dev"
    CLOUDFLARE_WORKER_API_KEY: Optional[str] = None

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")


settings = Settings()
