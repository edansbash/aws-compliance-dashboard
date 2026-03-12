"""JIRA configuration model for ticket creation integration."""
import uuid
from datetime import datetime
from sqlalchemy import String, Boolean, DateTime, Text
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.dialects.postgresql import UUID

from app.database import Base


class JiraConfig(Base):
    """Configuration for JIRA ticket creation integration."""

    __tablename__ = "jira_configs"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    # Use a key to identify config type (e.g., "jira")
    config_key: Mapped[str] = mapped_column(String(50), unique=True, nullable=False)

    # JIRA connection settings
    base_url: Mapped[str] = mapped_column(Text, nullable=True)  # e.g., https://company.atlassian.net
    email: Mapped[str] = mapped_column(Text, nullable=True)  # JIRA account email
    api_token: Mapped[str] = mapped_column(Text, nullable=True)  # JIRA API token

    # Project settings
    project_key: Mapped[str] = mapped_column(String(50), nullable=True)  # e.g., "SEC"
    issue_type: Mapped[str] = mapped_column(String(100), default="Security Issue")

    # Feature toggles
    is_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    min_severity: Mapped[str] = mapped_column(String(20), default="CRITICAL")

    # Notification triggers
    notify_on_new_findings: Mapped[bool] = mapped_column(Boolean, default=True)
    notify_on_regression: Mapped[bool] = mapped_column(Boolean, default=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False
    )
