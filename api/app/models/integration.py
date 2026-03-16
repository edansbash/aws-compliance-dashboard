"""
Integration settings model for managing enabled/disabled state of integrations.
"""

import uuid
from datetime import datetime
from sqlalchemy import String, DateTime, Boolean
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.dialects.postgresql import UUID

from app.database import Base


class IntegrationSetting(Base):
    """
    Stores enabled/disabled state for each integration.

    Integration types:
    - slack: Slack notifications
    - jira: JIRA ticket creation
    - iac: IaC/GitHub Code Scanning sync
    """
    __tablename__ = "integration_settings"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    integration_type: Mapped[str] = mapped_column(
        String(50), nullable=False, unique=True
    )  # slack, jira, iac
    is_enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False
    )
