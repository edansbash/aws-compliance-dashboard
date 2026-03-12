"""
API router for managing scheduled scans.

Provides CRUD operations for scheduled scans and manual triggering.
"""
from uuid import UUID
from typing import Optional
from math import ceil

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.scheduled_scan import ScheduledScan
from app.schemas.scheduled_scan import (
    ScheduledScanCreate,
    ScheduledScanUpdate,
    ScheduledScanResponse,
    ScheduledScanListResponse,
    ScheduledScanRunResponse,
)
from app.services.scheduler import (
    add_schedule,
    update_schedule,
    remove_schedule,
    trigger_schedule_now,
    get_scheduler_status,
    validate_cron_expression,
    validate_interval_expression,
)
from app.config import settings

router = APIRouter()


@router.get("", response_model=ScheduledScanListResponse)
async def list_scheduled_scans(
    page: int = Query(1, ge=1),
    per_page: int = Query(20, ge=1, le=100),
    enabled: Optional[bool] = None,
    db: AsyncSession = Depends(get_db),
):
    """
    List all scheduled scans with pagination.

    Args:
        page: Page number (1-indexed)
        per_page: Items per page (max 100)
        enabled: Filter by enabled status
    """
    # Build query
    query = select(ScheduledScan)
    count_query = select(func.count(ScheduledScan.id))

    if enabled is not None:
        query = query.where(ScheduledScan.enabled == enabled)
        count_query = count_query.where(ScheduledScan.enabled == enabled)

    # Get total count
    total_result = await db.execute(count_query)
    total = total_result.scalar() or 0

    # Apply pagination and ordering
    query = query.order_by(ScheduledScan.created_at.desc())
    query = query.offset((page - 1) * per_page).limit(per_page)

    result = await db.execute(query)
    schedules = result.scalars().all()

    return ScheduledScanListResponse(
        items=[ScheduledScanResponse.model_validate(s) for s in schedules],
        total=total,
        page=page,
        per_page=per_page,
        pages=ceil(total / per_page) if total > 0 else 1,
    )


@router.post("", response_model=ScheduledScanResponse, status_code=201)
async def create_scheduled_scan(
    data: ScheduledScanCreate,
    db: AsyncSession = Depends(get_db),
):
    """
    Create a new scheduled scan.

    Schedule types:
    - cron: Standard cron expression (e.g., "0 2 * * *" for daily at 2 AM)
    - interval: Minutes between runs (e.g., "360" for every 6 hours)
    """
    # Validate schedule expression
    if data.schedule_type == "cron":
        if not validate_cron_expression(data.schedule_expression):
            raise HTTPException(
                status_code=400,
                detail=f"Invalid cron expression: {data.schedule_expression}. "
                       "Expected 5 or 6 space-separated fields "
                       "(minute hour day month day_of_week [second])."
            )
    else:
        if not validate_interval_expression(data.schedule_expression):
            raise HTTPException(
                status_code=400,
                detail=f"Invalid interval expression: {data.schedule_expression}. "
                       "Expected minutes as integer or with suffix (e.g., '360', '6h', '1d')."
            )

    # Use default regions if not specified
    regions = data.regions or settings.default_scan_regions

    # Create schedule
    schedule = ScheduledScan(
        name=data.name,
        description=data.description,
        account_ids=data.account_ids or [],
        regions=regions,
        rule_ids=data.rule_ids,
        schedule_type=data.schedule_type.value,
        schedule_expression=data.schedule_expression,
        timezone=data.timezone,
        enabled=data.enabled,
        created_by=data.created_by,
    )

    db.add(schedule)
    await db.commit()
    await db.refresh(schedule)

    # Add to running scheduler
    await add_schedule(schedule)

    return ScheduledScanResponse.model_validate(schedule)


@router.get("/status")
async def get_scheduler_info():
    """
    Get scheduler status and list of active jobs.

    Returns scheduler running state and details of all scheduled jobs.
    """
    return get_scheduler_status()


@router.get("/{schedule_id}", response_model=ScheduledScanResponse)
async def get_scheduled_scan(
    schedule_id: UUID,
    db: AsyncSession = Depends(get_db),
):
    """Get a specific scheduled scan by ID."""
    result = await db.execute(
        select(ScheduledScan).where(ScheduledScan.id == schedule_id)
    )
    schedule = result.scalar_one_or_none()

    if not schedule:
        raise HTTPException(status_code=404, detail="Scheduled scan not found")

    return ScheduledScanResponse.model_validate(schedule)


@router.put("/{schedule_id}", response_model=ScheduledScanResponse)
async def update_scheduled_scan(
    schedule_id: UUID,
    data: ScheduledScanUpdate,
    db: AsyncSession = Depends(get_db),
):
    """
    Update an existing scheduled scan.

    Only provided fields will be updated.
    """
    result = await db.execute(
        select(ScheduledScan).where(ScheduledScan.id == schedule_id)
    )
    schedule = result.scalar_one_or_none()

    if not schedule:
        raise HTTPException(status_code=404, detail="Scheduled scan not found")

    # Validate schedule expression if being updated
    update_data = data.model_dump(exclude_unset=True)

    schedule_type = update_data.get("schedule_type", schedule.schedule_type)
    schedule_expression = update_data.get("schedule_expression", schedule.schedule_expression)

    if "schedule_expression" in update_data or "schedule_type" in update_data:
        if schedule_type == "cron":
            if not validate_cron_expression(schedule_expression):
                raise HTTPException(
                    status_code=400,
                    detail=f"Invalid cron expression: {schedule_expression}"
                )
        else:
            if not validate_interval_expression(schedule_expression):
                raise HTTPException(
                    status_code=400,
                    detail=f"Invalid interval expression: {schedule_expression}"
                )

    # Apply updates
    for field, value in update_data.items():
        if field == "schedule_type" and value:
            value = value.value if hasattr(value, "value") else value
        setattr(schedule, field, value)

    await db.commit()
    await db.refresh(schedule)

    # Update in running scheduler
    await update_schedule(schedule)

    return ScheduledScanResponse.model_validate(schedule)


@router.delete("/{schedule_id}", status_code=204)
async def delete_scheduled_scan(
    schedule_id: UUID,
    db: AsyncSession = Depends(get_db),
):
    """Delete a scheduled scan."""
    result = await db.execute(
        select(ScheduledScan).where(ScheduledScan.id == schedule_id)
    )
    schedule = result.scalar_one_or_none()

    if not schedule:
        raise HTTPException(status_code=404, detail="Scheduled scan not found")

    # Remove from scheduler first
    await remove_schedule(schedule_id)

    # Delete from database
    await db.delete(schedule)
    await db.commit()


@router.post("/{schedule_id}/run", response_model=ScheduledScanRunResponse)
async def run_scheduled_scan_now(
    schedule_id: UUID,
    db: AsyncSession = Depends(get_db),
):
    """
    Manually trigger a scheduled scan immediately.

    This creates a new scan based on the schedule configuration,
    regardless of the schedule's next run time.
    """
    try:
        scan_id = await trigger_schedule_now(schedule_id, db)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))

    return ScheduledScanRunResponse(
        schedule_id=schedule_id,
        scan_id=scan_id,
        message="Scheduled scan triggered successfully",
    )


@router.post("/{schedule_id}/enable", response_model=ScheduledScanResponse)
async def enable_scheduled_scan(
    schedule_id: UUID,
    db: AsyncSession = Depends(get_db),
):
    """Enable a disabled scheduled scan."""
    result = await db.execute(
        select(ScheduledScan).where(ScheduledScan.id == schedule_id)
    )
    schedule = result.scalar_one_or_none()

    if not schedule:
        raise HTTPException(status_code=404, detail="Scheduled scan not found")

    schedule.enabled = True
    await db.commit()
    await db.refresh(schedule)

    # Add back to scheduler
    await update_schedule(schedule)

    return ScheduledScanResponse.model_validate(schedule)


@router.post("/{schedule_id}/disable", response_model=ScheduledScanResponse)
async def disable_scheduled_scan(
    schedule_id: UUID,
    db: AsyncSession = Depends(get_db),
):
    """Disable an enabled scheduled scan without deleting it."""
    result = await db.execute(
        select(ScheduledScan).where(ScheduledScan.id == schedule_id)
    )
    schedule = result.scalar_one_or_none()

    if not schedule:
        raise HTTPException(status_code=404, detail="Scheduled scan not found")

    schedule.enabled = False
    await db.commit()
    await db.refresh(schedule)

    # Remove from scheduler
    await update_schedule(schedule)

    return ScheduledScanResponse.model_validate(schedule)
