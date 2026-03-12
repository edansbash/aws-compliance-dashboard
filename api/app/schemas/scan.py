from datetime import datetime
from uuid import UUID
from typing import Optional, List
from pydantic import BaseModel

from app.models.scan import ScanStatus


class ScanCreate(BaseModel):
    account_ids: Optional[List[str]] = None
    regions: Optional[List[str]] = None
    rule_ids: Optional[List[str]] = None


class ScanResponse(BaseModel):
    id: UUID
    status: ScanStatus
    regions: List[str]
    account_ids: List[str]
    rule_ids: Optional[List[str]]
    resource_types: List[str]
    started_at: Optional[datetime]
    completed_at: Optional[datetime]
    total_resources: int
    total_findings: int
    error_message: Optional[str]
    created_at: datetime

    class Config:
        from_attributes = True


class ScanDetailResponse(ScanResponse):
    pass


class ScanListResponse(BaseModel):
    items: List[ScanResponse]
    total: int
    page: int
    per_page: int
    pages: int
