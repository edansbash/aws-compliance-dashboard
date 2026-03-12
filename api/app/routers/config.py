from typing import List
from fastapi import APIRouter
from pydantic import BaseModel

from app.config import settings

router = APIRouter()


class RegionsResponse(BaseModel):
    regions: List[str]


class RegionsUpdate(BaseModel):
    regions: List[str]


@router.get("/regions", response_model=RegionsResponse)
async def get_regions():
    """Get configured scan regions."""
    return RegionsResponse(regions=settings.default_scan_regions)


@router.put("/regions", response_model=RegionsResponse)
async def update_regions(update: RegionsUpdate):
    """Update default scan regions."""
    # Note: In production, this should persist to database
    settings.default_scan_regions = update.regions
    return RegionsResponse(regions=settings.default_scan_regions)
