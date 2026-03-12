import uuid
from datetime import datetime
from enum import Enum as PyEnum
from sqlalchemy import String, DateTime, Text, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.dialects.postgresql import UUID

from app.database import Base


class ExceptionScope(str, PyEnum):
    """Exception scope values (for reference only, DB stores as string)."""
    RESOURCE = "RESOURCE"
    RULE = "RULE"
    ACCOUNT = "ACCOUNT"


class Exception(Base):
    """Exception record for ignored findings."""

    __tablename__ = "compliance_exceptions"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    rule_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("rules.id"), nullable=False
    )
    resource_id: Mapped[str | None] = mapped_column(String(500), nullable=True)
    account_id: Mapped[str | None] = mapped_column(String(12), nullable=True)
    scope: Mapped[str] = mapped_column(
        String(20), nullable=False
    )
    justification: Mapped[str] = mapped_column(Text, nullable=False)
    created_by: Mapped[str] = mapped_column(String(255), nullable=False)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, nullable=False
    )

    # Relationships
    rule = relationship("Rule")
