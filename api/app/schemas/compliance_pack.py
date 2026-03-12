from datetime import datetime
from uuid import UUID
from typing import Optional, List
from pydantic import BaseModel

from app.schemas.rule import RuleResponse, RuleWithCount


class CompliancePackCreate(BaseModel):
    name: str
    description: Optional[str] = None
    rule_ids: Optional[List[UUID]] = None


class CompliancePackUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    is_enabled: Optional[bool] = None


class CompliancePackRuleUpdate(BaseModel):
    rule_ids: List[UUID]


class CompliancePackResponse(BaseModel):
    id: UUID
    name: str
    description: Optional[str]
    is_enabled: bool
    created_at: datetime
    updated_at: datetime
    rule_count: int = 0

    class Config:
        from_attributes = True


class CompliancePackDetailResponse(BaseModel):
    id: UUID
    name: str
    description: Optional[str]
    is_enabled: bool
    created_at: datetime
    updated_at: datetime
    rules: List[RuleWithCount]
    compliance_score: float = 100.0  # Percentage of passing rules
    passing_rules: int = 0
    failing_rules: int = 0
    # Resource-based metrics
    total_resources: int = 0
    failing_resources: int = 0
    resource_compliance_score: float = 100.0  # Percentage of passing resources

    class Config:
        from_attributes = True


class CompliancePackListResponse(BaseModel):
    items: List[CompliancePackResponse]
    total: int
    page: int
    per_page: int
    pages: int
