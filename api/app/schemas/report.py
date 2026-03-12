from datetime import datetime
from uuid import UUID
from typing import Optional, List
from pydantic import BaseModel

from app.models.report import ReportType, ReportFormat, ReportStatus


class ReportFilters(BaseModel):
    """Filters for report generation."""
    account_ids: Optional[List[str]] = None
    regions: Optional[List[str]] = None
    severities: Optional[List[str]] = None
    statuses: Optional[List[str]] = None
    rule_ids: Optional[List[str]] = None


class ReportCreate(BaseModel):
    """Request to generate a new report."""
    report_type: ReportType
    scan_id: Optional[UUID] = None
    filters: Optional[ReportFilters] = None


class ReportResponse(BaseModel):
    """Report metadata response."""
    id: UUID
    report_type: ReportType
    format: ReportFormat
    status: ReportStatus
    scan_id: Optional[UUID]
    filters: Optional[dict]
    file_size: Optional[int]
    error_message: Optional[str]
    created_at: datetime
    completed_at: Optional[datetime]

    class Config:
        from_attributes = True


class ReportListResponse(BaseModel):
    """Paginated list of reports."""
    items: List[ReportResponse]
    total: int
    page: int
    per_page: int
    pages: int
