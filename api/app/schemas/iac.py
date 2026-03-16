"""
Pydantic schemas for IaC (Infrastructure as Code) API.
"""

from datetime import datetime
from uuid import UUID
from typing import Optional, List
from pydantic import BaseModel


# === Configuration ===

class IaCConfigResponse(BaseModel):
    """IaC configuration status."""

    configured: bool
    owner: Optional[str] = None
    repo: Optional[str] = None
    branch: Optional[str] = None
    last_sync: Optional["IaCSyncResponse"] = None


# === Syncs ===

class IaCSyncResponse(BaseModel):
    """IaC sync record."""

    id: UUID
    status: str
    branch: Optional[str]
    commit_sha: Optional[str]
    started_at: Optional[datetime]
    completed_at: Optional[datetime]
    total_alerts: int
    open_alerts: int
    new_alerts: int
    fixed_alerts: int
    error_message: Optional[str]
    created_at: datetime

    class Config:
        from_attributes = True


class IaCSyncListResponse(BaseModel):
    """Paginated list of IaC syncs."""

    items: List[IaCSyncResponse]
    total: int
    page: int
    per_page: int
    pages: int


class IaCSyncTriggerResponse(BaseModel):
    """Response when triggering a sync."""

    id: UUID
    status: str
    started_at: datetime
    message: str


# === Findings ===

class IaCFindingResponse(BaseModel):
    """IaC finding."""

    id: UUID
    github_alert_number: int
    github_alert_url: str
    github_alert_state: str
    trivy_rule_id: str
    trivy_rule_description: Optional[str]
    trivy_rule_name: Optional[str]  # e.g., "Misconfiguration"
    trivy_help_uri: Optional[str]  # Link to Aqua vulnerability database
    severity: str
    tool_name: Optional[str]  # e.g., "Trivy"
    file_path: str
    start_line: Optional[int]
    end_line: Optional[int]
    message: Optional[str]
    resource_type: Optional[str]
    commit_sha: Optional[str]
    first_detected_at: datetime
    last_seen_at: datetime
    fixed_at: Optional[datetime]  # When GitHub marked it fixed
    dismissed_at: Optional[datetime]
    dismissed_reason: Optional[str]
    created_at: datetime
    github_file_link: Optional[str] = None

    class Config:
        from_attributes = True


class IaCFindingListResponse(BaseModel):
    """Paginated list of IaC findings."""

    items: List[IaCFindingResponse]
    total: int
    page: int
    per_page: int
    pages: int


# === Summary ===

class SeverityCounts(BaseModel):
    """Counts by severity."""

    CRITICAL: int = 0
    HIGH: int = 0
    MEDIUM: int = 0
    LOW: int = 0


class StateCounts(BaseModel):
    """Counts by state."""

    open: int = 0
    fixed: int = 0
    dismissed: int = 0


class IaCSummaryResponse(BaseModel):
    """IaC dashboard summary."""

    configured: bool
    owner: Optional[str] = None
    repo: Optional[str] = None
    total_findings: int
    by_severity: SeverityCounts
    by_state: StateCounts
    last_sync_at: Optional[datetime]


# Resolve forward reference
IaCConfigResponse.model_rebuild()
