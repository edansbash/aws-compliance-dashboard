from pydantic_settings import BaseSettings
from typing import List, Optional


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    # Database
    database_url: str = "postgresql+asyncpg://postgres:postgres@db:5432/compliance"

    # Redis
    redis_url: str = "redis://redis:6379/0"
    cache_ttl_seconds: int = 60  # Default cache TTL

    # AWS
    aws_access_key_id: str = ""
    aws_secret_access_key: str = ""
    aws_session_token: str = ""
    aws_default_region: str = "us-east-1"

    # Default scan regions (US regions)
    default_scan_regions: List[str] = [
        "us-east-1",
        "us-east-2",
        "us-west-1",
        "us-west-2",
    ]

    # Slack notifications (can be overridden via database config)
    slack_webhook_url: Optional[str] = None
    slack_notifications_enabled: bool = False
    slack_min_severity: str = "CRITICAL"  # CRITICAL, HIGH, MEDIUM, LOW, INFO

    # App settings
    app_version: str = "1.0.0"

    class Config:
        env_file = ".env"
        extra = "allow"


settings = Settings()
