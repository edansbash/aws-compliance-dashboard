"""
IaC (Infrastructure as Code) API router.

Provides endpoints for:
- Configuration status
- Manual sync triggers
- Sync history
- IaC findings
- Dashboard summary
"""

from uuid import UUID
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, case

from app.database import get_db
from app.models.iac import IaCSync, IaCFinding
from app.services.iac_config import IaCConfig
from app.services.iac_sync import IaCSyncService
from app.schemas.iac import (
    IaCConfigResponse,
    IaCSyncResponse,
    IaCSyncListResponse,
    IaCSyncTriggerResponse,
    IaCFindingResponse,
    IaCFindingListResponse,
    IaCSummaryResponse,
    SeverityCounts,
    StateCounts,
)

router = APIRouter()


# === Configuration ===

@router.get("/config", response_model=IaCConfigResponse)
async def get_iac_config(db: AsyncSession = Depends(get_db)):
    """Get current IaC configuration status."""
    config = IaCConfig.from_env()

    # Get last sync if any
    result = await db.execute(
        select(IaCSync).order_by(IaCSync.created_at.desc()).limit(1)
    )
    last_sync = result.scalar_one_or_none()

    return IaCConfigResponse(
        configured=config.is_configured(),
        owner=config.owner if config.is_configured() else None,
        repo=config.repo if config.is_configured() else None,
        branch=config.branch if config.is_configured() else None,
        last_sync=IaCSyncResponse.model_validate(last_sync) if last_sync else None,
    )


# === Syncs ===

@router.post("/sync", response_model=IaCSyncTriggerResponse, status_code=201)
async def trigger_sync(
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
):
    """Trigger a manual sync from GitHub Code Scanning API."""
    config = IaCConfig.from_env()
    if not config.is_configured():
        raise HTTPException(
            status_code=400,
            detail="IaC scanning not configured. Set GITHUB_TOKEN, IAC_GITHUB_OWNER, and IAC_GITHUB_REPO environment variables.",
        )

    # Create sync service and start sync
    sync_service = IaCSyncService(db)

    # Run sync in background
    sync = await sync_service.sync()

    return IaCSyncTriggerResponse(
        id=sync.id,
        status=sync.status,
        started_at=sync.started_at,
        message="Sync started. Fetching alerts from GitHub Code Scanning API...",
    )


@router.get("/syncs", response_model=IaCSyncListResponse)
async def list_syncs(
    page: int = 1,
    per_page: int = 20,
    db: AsyncSession = Depends(get_db),
):
    """List sync history."""
    offset = (page - 1) * per_page
    query = (
        select(IaCSync)
        .order_by(IaCSync.created_at.desc())
        .offset(offset)
        .limit(per_page)
    )
    result = await db.execute(query)
    syncs = result.scalars().all()

    # Get total count
    count_result = await db.execute(select(func.count(IaCSync.id)))
    total = count_result.scalar() or 0

    return IaCSyncListResponse(
        items=[IaCSyncResponse.model_validate(s) for s in syncs],
        total=total,
        page=page,
        per_page=per_page,
        pages=(total + per_page - 1) // per_page if total > 0 else 1,
    )


@router.get("/syncs/{sync_id}", response_model=IaCSyncResponse)
async def get_sync(
    sync_id: UUID,
    db: AsyncSession = Depends(get_db),
):
    """Get sync details."""
    result = await db.execute(select(IaCSync).where(IaCSync.id == sync_id))
    sync = result.scalar_one_or_none()

    if not sync:
        raise HTTPException(status_code=404, detail="Sync not found")

    return IaCSyncResponse.model_validate(sync)


# === Findings ===

@router.get("/findings", response_model=IaCFindingListResponse)
async def list_findings(
    page: int = 1,
    per_page: int = 20,
    state: Optional[str] = None,  # open, fixed, dismissed
    severity: Optional[str] = None,  # CRITICAL, HIGH, MEDIUM, LOW
    trivy_rule_id: Optional[str] = None,
    file_path: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
):
    """List IaC findings with filters."""
    offset = (page - 1) * per_page
    query = select(IaCFinding)

    # Apply filters
    if state:
        query = query.where(IaCFinding.github_alert_state == state)
    if severity:
        query = query.where(IaCFinding.severity == severity.upper())
    if trivy_rule_id:
        query = query.where(IaCFinding.trivy_rule_id == trivy_rule_id)
    if file_path:
        query = query.where(IaCFinding.file_path.ilike(f"%{file_path}%"))

    # Order by severity priority, then by creation date
    severity_order = case(
        (IaCFinding.severity == "CRITICAL", 1),
        (IaCFinding.severity == "HIGH", 2),
        (IaCFinding.severity == "MEDIUM", 3),
        (IaCFinding.severity == "LOW", 4),
        else_=5,
    )
    query = query.order_by(severity_order, IaCFinding.created_at.desc())
    query = query.offset(offset).limit(per_page)

    result = await db.execute(query)
    findings = result.scalars().all()

    # Get total count with same filters
    count_query = select(func.count(IaCFinding.id))
    if state:
        count_query = count_query.where(IaCFinding.github_alert_state == state)
    if severity:
        count_query = count_query.where(IaCFinding.severity == severity.upper())
    if trivy_rule_id:
        count_query = count_query.where(IaCFinding.trivy_rule_id == trivy_rule_id)
    if file_path:
        count_query = count_query.where(IaCFinding.file_path.ilike(f"%{file_path}%"))

    count_result = await db.execute(count_query)
    total = count_result.scalar() or 0

    # Add github_file_link to each finding
    config = IaCConfig.from_env()
    items = []
    for f in findings:
        response = IaCFindingResponse.model_validate(f)
        if config.is_configured():
            response.github_file_link = config.get_file_url(f.file_path, f.start_line)
        items.append(response)

    return IaCFindingListResponse(
        items=items,
        total=total,
        page=page,
        per_page=per_page,
        pages=(total + per_page - 1) // per_page if total > 0 else 1,
    )


@router.get("/findings/{finding_id}", response_model=IaCFindingResponse)
async def get_finding(
    finding_id: UUID,
    db: AsyncSession = Depends(get_db),
):
    """Get finding details."""
    result = await db.execute(select(IaCFinding).where(IaCFinding.id == finding_id))
    finding = result.scalar_one_or_none()

    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    response = IaCFindingResponse.model_validate(finding)

    # Add github_file_link
    config = IaCConfig.from_env()
    if config.is_configured():
        response.github_file_link = config.get_file_url(finding.file_path, finding.start_line)

    return response


# === Summary ===

@router.get("/summary", response_model=IaCSummaryResponse)
async def get_summary(db: AsyncSession = Depends(get_db)):
    """Get IaC dashboard summary."""
    config = IaCConfig.from_env()

    if not config.is_configured():
        return IaCSummaryResponse(
            configured=False,
            total_findings=0,
            by_severity=SeverityCounts(),
            by_state=StateCounts(),
        )

    # Get total findings count
    total_result = await db.execute(select(func.count(IaCFinding.id)))
    total_findings = total_result.scalar() or 0

    # Get counts by severity (only for OPEN findings)
    severity_counts = SeverityCounts()
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        count_result = await db.execute(
            select(func.count(IaCFinding.id)).where(
                IaCFinding.severity == sev,
                IaCFinding.github_alert_state == "open"
            )
        )
        setattr(severity_counts, sev, count_result.scalar() or 0)

    # Get counts by state
    state_counts = StateCounts()
    for state in ["open", "fixed", "dismissed"]:
        count_result = await db.execute(
            select(func.count(IaCFinding.id)).where(IaCFinding.github_alert_state == state)
        )
        setattr(state_counts, state, count_result.scalar() or 0)

    # Get last sync time
    last_sync_result = await db.execute(
        select(IaCSync)
        .where(IaCSync.status == "COMPLETED")
        .order_by(IaCSync.completed_at.desc())
        .limit(1)
    )
    last_sync = last_sync_result.scalar_one_or_none()

    return IaCSummaryResponse(
        configured=True,
        owner=config.owner,
        repo=config.repo,
        total_findings=total_findings,
        by_severity=severity_counts,
        by_state=state_counts,
        last_sync_at=last_sync.completed_at if last_sync else None,
    )
