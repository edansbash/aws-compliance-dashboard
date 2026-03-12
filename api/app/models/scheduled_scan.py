"""
Scheduled scan model for recurring compliance scans.
"""
import uuid
from datetime import datetime
from enum import Enum as PyEnum
from sqlalchemy import String, DateTime, Boolean, Text
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.dialects.postgresql import UUID, JSONB

from app.database import Base


class ScheduleType(str, PyEnum):
    """Schedule type for recurring scans."""
    CRON = "cron"
    INTERVAL = "interval"


class ScheduledScan(Base):
    """Scheduled scan configuration for recurring compliance scans."""

    __tablename__ = "scheduled_scans"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Scan configuration (same as manual scans)
    account_ids: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    regions: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    rule_ids: Mapped[list | None] = mapped_column(JSONB, nullable=True)

    # Schedule configuration
    schedule_type: Mapped[str] = mapped_column(
        String(20), nullable=False, default="cron"
    )
    # For cron: "0 2 * * *" (daily at 2 AM)
    # For interval: minutes as integer stored as string, e.g., "360" for 6 hours
    schedule_expression: Mapped[str] = mapped_column(String(100), nullable=False)

    # Timezone for cron schedules (default UTC)
    timezone: Mapped[str] = mapped_column(String(50), nullable=False, default="UTC")

    # State
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    last_run_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    next_run_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    last_scan_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), nullable=True
    )

    # Audit fields
    created_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False
    )
