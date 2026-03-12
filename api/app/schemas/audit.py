from datetime import datetime
from uuid import UUID
from typing import Optional, List, Any, Dict
from pydantic import BaseModel

from app.models.audit import AuditAction


class AuditLogItem(BaseModel):
    id: str
    action: str
    resource_id: Optional[str]
    resource_type: Optional[str]
    account_id: Optional[str]
    region: Optional[str]
    rule: Optional[Dict[str, Any]]
    performed_by: str
    job_id: Optional[str]
    before_state: Optional[Dict[str, Any]]
    after_state: Optional[Dict[str, Any]]
    details: Optional[Dict[str, Any]]
    created_at: str


class AuditLogResponse(BaseModel):
    id: UUID
    action: AuditAction
    resource_id: Optional[str]
    resource_type: Optional[str]
    account_id: Optional[str]
    region: Optional[str]
    performed_by: str
    before_state: Optional[Dict[str, Any]]
    after_state: Optional[Dict[str, Any]]
    details: Optional[Dict[str, Any]]
    created_at: datetime

    class Config:
        from_attributes = True


class AuditLogListResponse(BaseModel):
    items: List[Any]  # AuditLogItem
    total: int
    page: int
    per_page: int
    pages: int
