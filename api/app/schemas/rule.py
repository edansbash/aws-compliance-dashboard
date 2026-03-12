from datetime import datetime
from uuid import UUID
from typing import Optional, List, Any
from pydantic import BaseModel

from app.models.rule import Severity


class RuleResponse(BaseModel):
    id: UUID
    rule_id: str
    name: str
    description: str
    resource_type: str
    severity: Severity
    is_enabled: bool
    has_remediation: bool
    remediation_tested: bool
    created_at: datetime

    class Config:
        from_attributes = True


class RuleWithCount(BaseModel):
    id: UUID
    rule_id: str
    name: str
    description: str
    resource_type: str
    severity: Severity
    is_enabled: bool
    has_remediation: bool
    remediation_tested: bool
    created_at: datetime
    finding_count: int


class RuleListResponse(BaseModel):
    items: List[Any]  # RuleWithCount
    total: int
    page: int
    per_page: int
    pages: int


class RuleUpdate(BaseModel):
    is_enabled: Optional[bool] = None
