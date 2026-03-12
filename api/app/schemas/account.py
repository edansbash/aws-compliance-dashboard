from datetime import datetime
from uuid import UUID
from typing import Optional, List
from pydantic import BaseModel, Field


class AccountCreate(BaseModel):
    account_id: str = Field(..., min_length=12, max_length=12)
    name: str = Field(..., min_length=1, max_length=255)
    role_arn: Optional[str] = None
    external_id: Optional[str] = None
    is_active: bool = True


class AccountUpdate(BaseModel):
    name: Optional[str] = None
    role_arn: Optional[str] = None
    external_id: Optional[str] = None
    is_active: Optional[bool] = None


class AccountResponse(BaseModel):
    id: UUID
    account_id: str
    name: str
    role_arn: Optional[str]
    external_id: Optional[str]
    is_active: bool
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class AccountListResponse(BaseModel):
    items: List[AccountResponse]
    total: int
    page: int
    per_page: int
    pages: int


class AccountTestResponse(BaseModel):
    success: bool
    message: str
    account_id: Optional[str]
