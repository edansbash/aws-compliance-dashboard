"""Notification configuration model for Slack integration.

Note: Connection credentials (webhook URLs, API tokens) are configured via
environment variables. This table only stores UI-configurable preferences
like minimum severity and notification triggers.
"""
import uuid
from datetime import datetime
from sqlalchemy import String, Boolean, DateTime
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.dialects.postgresql import UUID

from app.database import Base


class NotificationConfig(Base):
    """Notification configuration for Slack integration.

    Stores UI-configurable settings only. The actual webhook URL
    is configured via SLACK_WEBHOOK_URL environment variable.
    """

    __tablename__ = "notification_configs"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    # Use a key to identify config type (e.g., "slack")
    config_key: Mapped[str] = mapped_column(String(50), unique=True, nullable=False)

    # UI-configurable settings
    is_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    min_severity: Mapped[str] = mapped_column(String(20), default="CRITICAL")

    # Notification triggers
    notify_on_new_findings: Mapped[bool] = mapped_column(Boolean, default=True)
    notify_on_regression: Mapped[bool] = mapped_column(Boolean, default=True)
    notify_on_scan_complete: Mapped[bool] = mapped_column(Boolean, default=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False
    )
