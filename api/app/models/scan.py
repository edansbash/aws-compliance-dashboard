import uuid
from datetime import datetime
from enum import Enum as PyEnum
from sqlalchemy import String, DateTime, Integer, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.dialects.postgresql import UUID, JSONB

from app.database import Base


class ScanStatus(str, PyEnum):
    """Scan status values (for reference only, DB stores as string)."""
    QUEUED = "QUEUED"      # Job is in Redis queue waiting for worker
    PENDING = "PENDING"    # Legacy status (kept for backward compatibility)
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


class Scan(Base):
    """Scan execution record."""

    __tablename__ = "scans"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    status: Mapped[str] = mapped_column(
        String(20), default="PENDING", nullable=False
    )
    regions: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    account_ids: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    rule_ids: Mapped[list | None] = mapped_column(JSONB, nullable=True)
    resource_types: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    started_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    total_resources: Mapped[int] = mapped_column(Integer, default=0)
    total_findings: Mapped[int] = mapped_column(Integer, default=0)
    error_message: Mapped[str | None] = mapped_column(String(1000), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, nullable=False
    )

    # Relationships
    findings = relationship("Finding", back_populates="scan", cascade="all, delete-orphan")
