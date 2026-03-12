import uuid
from datetime import datetime
from sqlalchemy import String, Boolean, DateTime, Text, Table, ForeignKey, Column
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.dialects.postgresql import UUID

from app.database import Base


# Association table for many-to-many relationship between CompliancePack and Rule
compliance_pack_rules = Table(
    "compliance_pack_rules",
    Base.metadata,
    Column("compliance_pack_id", UUID(as_uuid=True), ForeignKey("compliance_packs.id", ondelete="CASCADE"), primary_key=True),
    Column("rule_id", UUID(as_uuid=True), ForeignKey("rules.id", ondelete="CASCADE"), primary_key=True),
)


class CompliancePack(Base):
    """Compliance pack - a collection of rules that can be enabled/disabled together."""

    __tablename__ = "compliance_packs"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=True)
    is_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False
    )

    # Many-to-many relationship with rules
    rules = relationship("Rule", secondary=compliance_pack_rules, backref="compliance_packs")
