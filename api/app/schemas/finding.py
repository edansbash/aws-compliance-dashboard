from datetime import datetime
from uuid import UUID
from typing import Optional, List, Any, Dict
from pydantic import BaseModel


class RuleSummary(BaseModel):
    id: str
    rule_id: str
    name: str
    severity: str


class FindingItem(BaseModel):
    id: str
    scan_id: str
    resource_id: str
    resource_name: str
    resource_type: str
    account_id: str
    region: str
    status: str
    workflow_status: str
    workflow_notes: Optional[str]
    rule: Optional[RuleSummary]
    details: Dict[str, Any]
    created_at: str
    last_scanned_at: Optional[str] = None
    jira_ticket_key: Optional[str] = None


class FindingListResponse(BaseModel):
    items: List[FindingItem]
    total: int
    page: int
    per_page: int
    pages: int


class WorkflowUpdate(BaseModel):
    workflow_status: str
    notes: Optional[str] = None
    updated_by: Optional[str] = None


class WorkflowUpdateResponse(BaseModel):
    id: UUID
    workflow_status: str
    workflow_updated_by: Optional[str]
    workflow_updated_at: Optional[datetime]
    workflow_notes: Optional[str]


class RescanResponse(BaseModel):
    finding_id: UUID
    previous_status: str
    new_status: str
    resource_id: str
    message: str
    scanned_at: datetime
