from datetime import datetime
from uuid import UUID
from typing import Optional, List, Any, Dict
from pydantic import BaseModel

from app.models.remediation import RemediationStatus


class RemediationPreviewRequest(BaseModel):
    finding_ids: List[UUID]


class PreviewItem(BaseModel):
    finding_id: str
    resource_id: str
    resource_name: str
    rule_name: str
    planned_action: Optional[str] = None
    preview: Optional[Dict[str, Any]] = None
    can_remediate: bool
    reason: Optional[str] = None


class RemediationPreviewResponse(BaseModel):
    findings: List[Any]  # PreviewItem
    total: int
    remediable: int


class RemediationCreateRequest(BaseModel):
    finding_ids: List[UUID]
    confirmed_by: str


class FindingInfo(BaseModel):
    """Minimal finding info for display in remediation job list."""
    resource_id: str
    resource_name: str
    account_id: str
    region: str
    rule: Optional[Dict[str, Any]] = None

    class Config:
        from_attributes = True


class RemediationJobResponse(BaseModel):
    id: UUID
    status: RemediationStatus
    finding_id: UUID
    batch_id: Optional[UUID]
    confirmed_by: str
    started_at: Optional[datetime]
    completed_at: Optional[datetime]
    error_message: Optional[str]
    created_at: datetime
    # Include finding data for display
    finding: Optional[FindingInfo] = None

    class Config:
        from_attributes = True


class RemediationBatchResponse(BaseModel):
    batch_id: UUID
    job_ids: List[UUID]
    total_jobs: int


class RemediationListResponse(BaseModel):
    items: List[RemediationJobResponse]
    total: int
    page: int
    per_page: int
    pages: int
