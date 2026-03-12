from uuid import UUID
from typing import Optional, List
from datetime import datetime
import json
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from sqlalchemy.orm import selectinload
from sse_starlette.sse import EventSourceResponse

from app.database import get_db, AsyncSessionLocal
from app.models import Scan, Finding, AWSAccount, Rule, AuditLog
from app.models.scan import ScanStatus
from app.schemas.scan import (
    ScanCreate,
    ScanResponse,
    ScanListResponse,
    ScanDetailResponse,
)
from app.services.job_queue import enqueue_scan_job, get_job_status
from app.services.job_publisher import JobStatusSubscriber

router = APIRouter()


@router.get("", response_model=ScanListResponse)
async def list_scans(
    page: int = 1,
    per_page: int = 20,
    db: AsyncSession = Depends(get_db),
):
    """List scan history."""
    offset = (page - 1) * per_page
    query = (
        select(Scan)
        .order_by(Scan.created_at.desc())
        .offset(offset)
        .limit(per_page)
    )
    result = await db.execute(query)
    scans = result.scalars().all()

    # Get total count
    count_result = await db.execute(select(Scan))
    total = len(count_result.scalars().all())

    return ScanListResponse(
        items=[ScanResponse.model_validate(s) for s in scans],
        total=total,
        page=page,
        per_page=per_page,
        pages=(total + per_page - 1) // per_page if total > 0 else 1,
    )


@router.post("", response_model=ScanResponse, status_code=201)
async def create_scan(
    scan_request: ScanCreate,
    db: AsyncSession = Depends(get_db),
):
    """Trigger a new scan."""
    from app.config import settings

    # Get account IDs to scan
    if scan_request.account_ids:
        account_ids = scan_request.account_ids
    else:
        # Get all active accounts
        result = await db.execute(
            select(AWSAccount).where(AWSAccount.is_active == True)
        )
        accounts = result.scalars().all()
        account_ids = [str(a.id) for a in accounts]

    # Get regions to scan
    regions = scan_request.regions or settings.default_scan_regions

    # Get rule IDs if specified
    rule_ids = None
    if scan_request.rule_ids:
        rule_ids = scan_request.rule_ids

    # Create scan record with QUEUED status
    scan = Scan(
        status="QUEUED",
        regions=regions,
        account_ids=account_ids,
        rule_ids=rule_ids,
    )
    db.add(scan)
    await db.commit()
    await db.refresh(scan)

    # Create audit log
    audit_log = AuditLog(
        action="SCAN_STARTED",
        performed_by="system",
        details={
            "scan_id": str(scan.id),
            "account_ids": account_ids,
            "regions": regions,
            "rule_count": len(rule_ids) if rule_ids else "all",
        }
    )
    db.add(audit_log)
    await db.commit()

    # Enqueue scan job to Redis for worker to process
    await enqueue_scan_job(
        scan_id=str(scan.id),
        account_ids=account_ids,
        regions=regions,
        rule_ids=[str(r) for r in rule_ids] if rule_ids else None
    )

    return ScanResponse.model_validate(scan)


# NOTE: This route MUST be defined BEFORE /{scan_id} to avoid route matching issues
# FastAPI matches routes in order, so /status/stream must come first
@router.get("/{scan_id}/status/stream")
async def stream_scan_status(
    scan_id: UUID,
    db: AsyncSession = Depends(get_db),
):
    """
    Stream scan status updates via Server-Sent Events (SSE).

    This endpoint opens a persistent HTTP connection and pushes updates
    to the client in real-time as the scan progresses. The connection
    automatically closes when the scan completes or fails.
    """
    # Verify scan exists
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    return EventSourceResponse(scan_status_event_generator(str(scan_id)))


@router.get("/{scan_id}", response_model=ScanDetailResponse)
async def get_scan(
    scan_id: UUID,
    db: AsyncSession = Depends(get_db),
):
    """Get scan details."""
    result = await db.execute(
        select(Scan).where(Scan.id == scan_id)
    )
    scan = result.scalar_one_or_none()

    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    return ScanDetailResponse.model_validate(scan)


@router.get("/{scan_id}/findings")
async def get_scan_findings(
    scan_id: UUID,
    page: int = 1,
    per_page: int = 20,
    db: AsyncSession = Depends(get_db),
):
    """Get findings for a scan."""
    # Verify scan exists
    scan_result = await db.execute(select(Scan).where(Scan.id == scan_id))
    if not scan_result.scalar_one_or_none():
        raise HTTPException(status_code=404, detail="Scan not found")

    offset = (page - 1) * per_page
    query = (
        select(Finding)
        .where(Finding.scan_id == scan_id)
        .options(selectinload(Finding.rule))
        .offset(offset)
        .limit(per_page)
    )
    result = await db.execute(query)
    findings = result.scalars().all()

    # Get total
    count_result = await db.execute(
        select(Finding).where(Finding.scan_id == scan_id)
    )
    total = len(count_result.scalars().all())

    return {
        "items": [
            {
                "id": str(f.id),
                "resource_id": f.resource_id,
                "resource_name": f.resource_name,
                "resource_type": f.resource_type,
                "account_id": f.account_id,
                "region": f.region,
                "status": f.status.value,
                "workflow_status": f.workflow_status.value,
                "rule": {
                    "id": str(f.rule.id),
                    "rule_id": f.rule.rule_id,
                    "name": f.rule.name,
                    "severity": f.rule.severity.value,
                } if f.rule else None,
                "details": f.details,
                "created_at": f.created_at.isoformat(),
            }
            for f in findings
        ],
        "total": total,
        "page": page,
        "per_page": per_page,
        "pages": (total + per_page - 1) // per_page if total > 0 else 1,
    }


@router.post("/{scan_id}/cancel", response_model=ScanResponse)
async def cancel_scan(
    scan_id: UUID,
    db: AsyncSession = Depends(get_db),
):
    """Cancel a running or pending scan."""
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalar_one_or_none()

    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    if scan.status not in ["PENDING", "QUEUED", "RUNNING"]:
        raise HTTPException(
            status_code=400,
            detail=f"Cannot cancel scan with status {scan.status}"
        )

    scan.status = "FAILED"
    scan.completed_at = datetime.utcnow()
    scan.error_message = "Cancelled by user"
    await db.commit()
    await db.refresh(scan)

    return ScanResponse.model_validate(scan)


@router.post("/cancel-stale")
async def cancel_stale_scans(
    max_age_minutes: int = 30,
    db: AsyncSession = Depends(get_db),
):
    """Cancel all scans that have been running for longer than max_age_minutes."""
    from datetime import timedelta

    cutoff = datetime.utcnow() - timedelta(minutes=max_age_minutes)

    result = await db.execute(
        select(Scan).where(
            Scan.status.in_(["PENDING", "QUEUED", "RUNNING"]),
            Scan.created_at < cutoff
        )
    )
    stale_scans = result.scalars().all()

    cancelled_count = 0
    for scan in stale_scans:
        scan.status = "FAILED"
        scan.completed_at = datetime.utcnow()
        scan.error_message = f"Cancelled: stale scan (running > {max_age_minutes} minutes)"
        cancelled_count += 1

    await db.commit()

    return {"message": f"Cancelled {cancelled_count} stale scan(s)"}


@router.delete("/{scan_id}", status_code=204)
async def delete_scan(
    scan_id: UUID,
    db: AsyncSession = Depends(get_db),
):
    """Delete a scan and its findings."""
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalar_one_or_none()

    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    await db.delete(scan)
    await db.commit()


async def scan_status_event_generator(scan_id: str):
    """
    Generator that yields SSE events for scan status updates.

    How it works:
    1. First, check if scan is already complete (for late joiners)
    2. If still running, subscribe to Redis pub/sub channel
    3. Worker publishes status updates to Redis as scan progresses
    4. This generator receives those updates and yields them as SSE events
    5. When scan completes/fails, generator exits and connection closes

    The Redis pub/sub pattern means:
    - No polling - events are pushed in real-time
    - Minimal server load - one subscription per client
    - Instant updates - typically <10ms latency
    """
    # Check current scan status from database (for late joiners)
    async with AsyncSessionLocal() as session:
        result = await session.execute(
            select(Scan).where(Scan.id == scan_id)
        )
        scan = result.scalar_one_or_none()

        if scan:
            # Send current status immediately
            yield {
                "data": json.dumps({
                    "type": "status",
                    "status": scan.status,
                    "message": f"Current scan status: {scan.status}",
                    "total_resources": scan.total_resources,
                    "total_findings": scan.total_findings,
                })
            }

            # If scan is already complete, exit immediately
            if scan.status in ["COMPLETED", "FAILED"]:
                yield {
                    "data": json.dumps({
                        "type": "complete",
                        "status": scan.status,
                        "total_resources": scan.total_resources,
                        "total_findings": scan.total_findings,
                        "error_message": scan.error_message,
                    })
                }
                return

    # Also check Redis cache for most recent status (may be more up-to-date)
    cached_status = await get_job_status(scan_id)
    if cached_status:
        yield {
            "data": json.dumps({
                "type": "status",
                "status": cached_status.get("status"),
                "message": cached_status.get("message"),
                "progress": cached_status.get("progress"),
            })
        }

    # Subscribe to Redis pub/sub for real-time updates
    # JobStatusSubscriber filters messages for this specific scan_id
    async with JobStatusSubscriber(scan_id) as subscriber:
        async for message in subscriber:
            # Message is a dict from Redis pub/sub
            # It contains either a status update or a log message

            if "level" in message:
                # This is a log/progress message from the worker
                yield {
                    "data": json.dumps({
                        "type": "log",
                        "level": message.get("level"),
                        "message": message.get("message"),
                        "timestamp": message.get("timestamp"),
                        "details": message.get("details"),
                    })
                }
            elif "status" in message:
                # This is a status change
                status = message.get("status")
                yield {
                    "data": json.dumps({
                        "type": "status",
                        "status": status,
                        "message": message.get("message"),
                        "progress": message.get("progress"),
                    })
                }

                # If scan completed or failed, send final event and exit
                if status in ["COMPLETED", "FAILED"]:
                    # Fetch final stats from database
                    async with AsyncSessionLocal() as session:
                        result = await session.execute(
                            select(Scan).where(Scan.id == scan_id)
                        )
                        final_scan = result.scalar_one_or_none()
                        if final_scan:
                            yield {
                                "data": json.dumps({
                                    "type": "complete",
                                    "status": final_scan.status,
                                    "total_resources": final_scan.total_resources,
                                    "total_findings": final_scan.total_findings,
                                    "error_message": final_scan.error_message,
                                })
                            }
                    # Exit generator - this closes the SSE connection
                    return
