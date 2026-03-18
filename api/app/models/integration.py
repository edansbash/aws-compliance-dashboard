"""
Integration settings model for managing integration state and configuration.

Design principles:
- Credentials (API tokens, URLs) -> Always from env vars (never in DB)
- is_enabled -> UI toggle, stored in DB
- Behavioral settings (min_severity, notify flags) -> UI configurable, stored in DB as JSON
"""

import uuid
from datetime import datetime
from typing import Any, Dict
from sqlalchemy import String, DateTime, Boolean
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.dialects.postgresql import UUID, JSONB

from app.database import Base


class IntegrationSetting(Base):
    """
    Unified integration settings table.

    Stores enabled/disabled state and behavioral settings for each integration.
    Credentials are always read from environment variables.

    Integration types:
    - slack: Slack notifications
    - jira: JIRA ticket creation
    - iac: IaC/GitHub Code Scanning sync

    Settings schema by integration type:
    - slack: {min_severity, notify_on_new_findings, notify_on_regression, notify_on_scan_complete}
    - jira: {min_severity, notify_on_new_findings, notify_on_regression}
    - iac: {}
    """
    __tablename__ = "integration_settings"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    integration_type: Mapped[str] = mapped_column(
        String(50), nullable=False, unique=True
    )  # slack, jira, iac
    is_enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    settings: Mapped[Dict[str, Any]] = mapped_column(
        JSONB, nullable=False, default=dict
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False
    )

    def get_setting(self, key: str, default: Any = None) -> Any:
        """Get a setting value with optional default."""
        return self.settings.get(key, default) if self.settings else default

    def set_setting(self, key: str, value: Any) -> None:
        """Set a setting value."""
        if self.settings is None:
            self.settings = {}
        self.settings[key] = value
