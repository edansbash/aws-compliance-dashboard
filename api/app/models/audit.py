import uuid
from datetime import datetime
from enum import Enum as PyEnum
from sqlalchemy import String, DateTime, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.dialects.postgresql import UUID, JSONB

from app.database import Base


class AuditAction(str, PyEnum):
    """Audit action values (for reference only, DB stores as string)."""
    SCAN_STARTED = "SCAN_STARTED"
    SCAN_COMPLETED = "SCAN_COMPLETED"
    FINDING_ACKNOWLEDGED = "FINDING_ACKNOWLEDGED"
    FINDING_RESOLVED = "FINDING_RESOLVED"
    EXCEPTION_CREATED = "EXCEPTION_CREATED"
    EXCEPTION_DELETED = "EXCEPTION_DELETED"
    REMEDIATION_STARTED = "REMEDIATION_STARTED"
    REMEDIATION_COMPLETED = "REMEDIATION_COMPLETED"
    REMEDIATION_FAILED = "REMEDIATION_FAILED"
    ACCOUNT_ADDED = "ACCOUNT_ADDED"
    ACCOUNT_REMOVED = "ACCOUNT_REMOVED"


class AuditLog(Base):
    """Comprehensive audit trail for all resource modifications."""

    __tablename__ = "audit_logs"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    action: Mapped[str] = mapped_column(
        String(50), nullable=False
    )
    resource_id: Mapped[str | None] = mapped_column(String(500), nullable=True)
    resource_type: Mapped[str | None] = mapped_column(String(100), nullable=True)
    account_id: Mapped[str | None] = mapped_column(String(12), nullable=True)
    region: Mapped[str | None] = mapped_column(String(50), nullable=True)
    rule_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("rules.id", ondelete="SET NULL"), nullable=True
    )
    performed_by: Mapped[str] = mapped_column(String(255), nullable=False)
    job_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("remediation_jobs.id", ondelete="SET NULL"), nullable=True
    )
    before_state: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    after_state: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    details: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, nullable=False
    )

    # Relationships
    rule = relationship("Rule")
    job = relationship("RemediationJob")
