import uuid
from datetime import datetime
from enum import Enum as PyEnum
from sqlalchemy import String, DateTime, Text, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.dialects.postgresql import UUID, JSONB

from app.database import Base


class FindingStatus(str, PyEnum):
    PASS = "PASS"
    FAIL = "FAIL"
    ERROR = "ERROR"
    EXCEPTION = "EXCEPTION"


class WorkflowStatus(str, PyEnum):
    OPEN = "OPEN"
    ACKNOWLEDGED = "ACKNOWLEDGED"
    PLANNED = "PLANNED"
    IN_PROGRESS = "IN_PROGRESS"
    RESOLVED = "RESOLVED"


class Finding(Base):
    """Individual compliance finding."""

    __tablename__ = "findings"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    scan_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False
    )
    rule_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("rules.id"), nullable=False
    )
    resource_id: Mapped[str] = mapped_column(String(500), nullable=False)
    resource_name: Mapped[str] = mapped_column(String(255), nullable=False)
    resource_type: Mapped[str] = mapped_column(String(100), nullable=False)
    account_id: Mapped[str] = mapped_column(String(12), nullable=False)
    region: Mapped[str] = mapped_column(String(50), nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False)
    workflow_status: Mapped[str] = mapped_column(String(20), default="OPEN", nullable=False)
    workflow_updated_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    workflow_updated_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    workflow_notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    details: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, nullable=False
    )
    last_scanned_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    jira_ticket_key: Mapped[str | None] = mapped_column(String(50), nullable=True, index=True)

    # Relationships
    scan = relationship("Scan", back_populates="findings")
    rule = relationship("Rule")
