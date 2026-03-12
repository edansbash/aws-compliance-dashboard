from datetime import datetime
from uuid import UUID
from typing import Optional, List, Any
from pydantic import BaseModel


class ExceptionCreate(BaseModel):
    rule_id: UUID
    resource_id: Optional[str] = None
    account_id: Optional[str] = None
    scope: str
    justification: str
    created_by: str
    expires_at: Optional[datetime] = None


class ExceptionBulkCreate(BaseModel):
    finding_ids: List[UUID]
    justification: str
    created_by: str
    expires_at: Optional[datetime] = None


class ExceptionUpdate(BaseModel):
    justification: Optional[str] = None
    expires_at: Optional[datetime] = None


class ExceptionBulkUpdate(BaseModel):
    exception_ids: List[UUID]
    justification: Optional[str] = None
    expires_at: Optional[datetime] = None


class BulkUpdateResponse(BaseModel):
    updated: int
    exception_ids: List[str]


class RuleSummary(BaseModel):
    id: UUID
    rule_id: str
    name: str
    severity: str

    class Config:
        from_attributes = True


class ExceptionResponse(BaseModel):
    id: UUID
    rule_id: UUID
    resource_id: Optional[str]
    account_id: Optional[str]
    scope: str
    justification: str
    created_by: str
    expires_at: Optional[datetime]
    created_at: datetime
    rule: Optional[RuleSummary] = None

    class Config:
        from_attributes = True


class ExceptionListResponse(BaseModel):
    items: List[ExceptionResponse]
    total: int
    page: int
    per_page: int
    pages: int


class BulkExceptionItem(BaseModel):
    id: Optional[str] = None
    finding_id: str


class BulkExceptionResponse(BaseModel):
    created: int
    exceptions: List[Any]
