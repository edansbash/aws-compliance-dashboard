"""
Pydantic schemas for scheduled scan API endpoints.
"""
from datetime import datetime
from uuid import UUID
from typing import Optional, List
from pydantic import BaseModel, Field, field_validator

from app.models.scheduled_scan import ScheduleType


class ScheduledScanCreate(BaseModel):
    """Schema for creating a new scheduled scan."""
    name: str = Field(..., min_length=1, max_length=255)
    description: Optional[str] = None
    account_ids: Optional[List[str]] = None
    regions: Optional[List[str]] = None
    rule_ids: Optional[List[str]] = None
    schedule_type: ScheduleType = ScheduleType.CRON
    schedule_expression: str = Field(
        ...,
        description="Cron expression (e.g., '0 2 * * *') or interval in minutes (e.g., '360')"
    )
    timezone: str = Field(default="UTC", description="Timezone for cron schedules")
    enabled: bool = True
    created_by: Optional[str] = None

    @field_validator("schedule_expression")
    @classmethod
    def validate_schedule_expression(cls, v: str, info) -> str:
        """Validate schedule expression based on type."""
        # Basic validation - more detailed validation in scheduler service
        if not v or not v.strip():
            raise ValueError("Schedule expression cannot be empty")
        return v.strip()


class ScheduledScanUpdate(BaseModel):
    """Schema for updating a scheduled scan."""
    name: Optional[str] = Field(None, min_length=1, max_length=255)
    description: Optional[str] = None
    account_ids: Optional[List[str]] = None
    regions: Optional[List[str]] = None
    rule_ids: Optional[List[str]] = None
    schedule_type: Optional[ScheduleType] = None
    schedule_expression: Optional[str] = None
    timezone: Optional[str] = None
    enabled: Optional[bool] = None


class ScheduledScanResponse(BaseModel):
    """Schema for scheduled scan response."""
    id: UUID
    name: str
    description: Optional[str]
    account_ids: List[str]
    regions: List[str]
    rule_ids: Optional[List[str]]
    schedule_type: str
    schedule_expression: str
    timezone: str
    enabled: bool
    last_run_at: Optional[datetime]
    next_run_at: Optional[datetime]
    last_scan_id: Optional[UUID]
    created_by: Optional[str]
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class ScheduledScanListResponse(BaseModel):
    """Schema for paginated list of scheduled scans."""
    items: List[ScheduledScanResponse]
    total: int
    page: int
    per_page: int
    pages: int


class ScheduledScanRunResponse(BaseModel):
    """Schema for manual trigger of a scheduled scan."""
    schedule_id: UUID
    scan_id: UUID
    message: str
