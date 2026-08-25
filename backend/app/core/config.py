import os
from functools import lru_cache
from pathlib import Path

from app.core.paths import DATA_ROOT
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


# Beside the executable in a frozen build; the repository root from source.
REPOSITORY_ROOT = DATA_ROOT
CONFIG_FILE = Path(
    os.environ.get("CYBERIP_CONFIG_FILE", REPOSITORY_ROOT / ".env")
)


class Settings(BaseSettings):
    """Runtime configuration loaded from environment variables and `.env`."""

    model_config = SettingsConfigDict(
        env_file=CONFIG_FILE,
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    env: str = "development"
    virustotal_api_key: str | None = None
    abuseipdb_api_key: str | None = None
    threatfox_api_key: str | None = None
    urlhaus_api_key: str | None = None
    ai_api_key: str | None = None
    db_path: str = "./data/cyberip.db"
    http_timeout: float = Field(default=10.0, gt=0, le=120)
    dns_timeout: float = Field(default=3.0, gt=0, le=30)
    cache_ttl: int = Field(default=3600, ge=0, le=86_400)
    analysis_timeout: float = Field(default=15.0, gt=0, le=120)
    rate_limit_requests: int = Field(default=60, ge=1, le=10_000)
    rate_limit_window: int = Field(default=60, ge=1, le=3600)
    cors_origins: list[str] = Field(
        default_factory=lambda: [
            "http://localhost:8000",
            "http://127.0.0.1:8000",
        ]
    )


@lru_cache
def get_settings() -> Settings:
    """Return the process-wide validated settings object."""

    return Settings()
