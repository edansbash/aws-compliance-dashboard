"""
Integration settings API router.

Provides endpoints for managing integration enabled/disabled state.
"""

from typing import List
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from pydantic import BaseModel

from app.database import get_db
from app.models.integration import IntegrationSetting

router = APIRouter()


class IntegrationStatus(BaseModel):
    """Integration status response."""
    integration_type: str
    is_enabled: bool

    class Config:
        from_attributes = True


class IntegrationStatusList(BaseModel):
    """List of integration statuses."""
    integrations: List[IntegrationStatus]


class IntegrationUpdate(BaseModel):
    """Request to update integration status."""
    is_enabled: bool


@router.get("", response_model=IntegrationStatusList)
async def get_all_integrations(db: AsyncSession = Depends(get_db)):
    """Get enabled/disabled status for all integrations."""
    result = await db.execute(select(IntegrationSetting))
    settings = result.scalars().all()

    return IntegrationStatusList(
        integrations=[
            IntegrationStatus(
                integration_type=s.integration_type,
                is_enabled=s.is_enabled
            )
            for s in settings
        ]
    )


@router.get("/{integration_type}", response_model=IntegrationStatus)
async def get_integration(
    integration_type: str,
    db: AsyncSession = Depends(get_db)
):
    """Get enabled/disabled status for a specific integration."""
    result = await db.execute(
        select(IntegrationSetting).where(
            IntegrationSetting.integration_type == integration_type
        )
    )
    setting = result.scalar_one_or_none()

    if not setting:
        raise HTTPException(status_code=404, detail=f"Integration '{integration_type}' not found")

    return IntegrationStatus(
        integration_type=setting.integration_type,
        is_enabled=setting.is_enabled
    )


@router.put("/{integration_type}", response_model=IntegrationStatus)
async def update_integration(
    integration_type: str,
    update: IntegrationUpdate,
    db: AsyncSession = Depends(get_db)
):
    """Enable or disable an integration."""
    result = await db.execute(
        select(IntegrationSetting).where(
            IntegrationSetting.integration_type == integration_type
        )
    )
    setting = result.scalar_one_or_none()

    if not setting:
        raise HTTPException(status_code=404, detail=f"Integration '{integration_type}' not found")

    setting.is_enabled = update.is_enabled
    await db.commit()
    await db.refresh(setting)

    return IntegrationStatus(
        integration_type=setting.integration_type,
        is_enabled=setting.is_enabled
    )
