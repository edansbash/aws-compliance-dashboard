"""
IaC (Infrastructure as Code) models for Terraform compliance scanning.

These models track pre-deployment misconfigurations from Trivy via GitHub Code Scanning.
NOTE: IaC findings are completely separate from runtime findings and do NOT count
toward the main compliance score.
"""

import uuid
from datetime import datetime
from sqlalchemy import String, DateTime, Integer, Text, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.dialects.postgresql import UUID

from app.database import Base


class IaCSync(Base):
    """
    Sync record - tracks when findings were pulled from GitHub Code Scanning API.

    Each sync fetches all current alerts and updates iac_findings.
    """
    __tablename__ = "iac_syncs"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    status: Mapped[str] = mapped_column(
        String(20), default="RUNNING", nullable=False
    )  # RUNNING, COMPLETED, FAILED
    commit_sha: Mapped[str | None] = mapped_column(String(40), nullable=True)
    branch: Mapped[str | None] = mapped_column(String(100), nullable=True)
    started_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    total_alerts: Mapped[int] = mapped_column(Integer, default=0)
    open_alerts: Mapped[int] = mapped_column(Integer, default=0)
    new_alerts: Mapped[int] = mapped_column(Integer, default=0)
    fixed_alerts: Mapped[int] = mapped_column(Integer, default=0)
    error_message: Mapped[str | None] = mapped_column(String(1000), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, nullable=False
    )

    # Relationships
    findings = relationship("IaCFinding", back_populates="sync")


class IaCFinding(Base):
    """
    Pre-deployment misconfiguration from Trivy via GitHub Code Scanning.

    NOTE: These are NOT runtime findings. They represent issues in
    Terraform code that may or may not be deployed to AWS yet.
    They do NOT count toward the main compliance score.
    """
    __tablename__ = "iac_findings"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    sync_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("iac_syncs.id", ondelete="SET NULL"), nullable=True
    )

    # GitHub Alert (source of truth - unique identifier)
    github_alert_number: Mapped[int] = mapped_column(
        Integer, nullable=False, unique=True
    )
    github_alert_url: Mapped[str] = mapped_column(String(500), nullable=False)
    github_alert_state: Mapped[str] = mapped_column(
        String(20), nullable=False
    )  # open, dismissed, fixed

    # Trivy Rule
    trivy_rule_id: Mapped[str] = mapped_column(String(100), nullable=False)
    trivy_rule_description: Mapped[str | None] = mapped_column(Text, nullable=True)
    trivy_rule_name: Mapped[str | None] = mapped_column(String(100), nullable=True)  # e.g., "Misconfiguration"
    trivy_help_uri: Mapped[str | None] = mapped_column(String(500), nullable=True)  # Link to Aqua docs
    severity: Mapped[str] = mapped_column(
        String(20), nullable=False
    )  # CRITICAL, HIGH, MEDIUM, LOW

    # Scanner info
    tool_name: Mapped[str | None] = mapped_column(String(50), nullable=True)  # e.g., "Trivy"

    # Code Location
    file_path: Mapped[str] = mapped_column(String(500), nullable=False)
    start_line: Mapped[int | None] = mapped_column(Integer, nullable=True)
    end_line: Mapped[int | None] = mapped_column(Integer, nullable=True)

    # Details
    message: Mapped[str | None] = mapped_column(Text, nullable=True)
    resource_type: Mapped[str | None] = mapped_column(String(100), nullable=True)

    # Tracking
    commit_sha: Mapped[str | None] = mapped_column(String(40), nullable=True)
    first_detected_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, nullable=False
    )
    last_seen_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, nullable=False
    )
    fixed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)  # When GitHub marked it fixed
    dismissed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    dismissed_reason: Mapped[str | None] = mapped_column(String(100), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, nullable=False
    )

    # Relationships
    sync = relationship("IaCSync", back_populates="findings")
