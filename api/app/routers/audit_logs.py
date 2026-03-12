from uuid import UUID
from typing import Optional
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_
from sqlalchemy.orm import selectinload
import csv
import io

from app.database import get_db
from app.models import AuditLog, Rule
from app.schemas.audit import AuditLogResponse, AuditLogListResponse

router = APIRouter()


@router.get("", response_model=AuditLogListResponse)
async def list_audit_logs(
    action: Optional[str] = None,
    resource_id: Optional[str] = None,
    account_id: Optional[str] = None,
    user: Optional[str] = None,
    start_date: Optional[datetime] = None,
    end_date: Optional[datetime] = None,
    page: int = 1,
    per_page: int = 50,
    db: AsyncSession = Depends(get_db),
):
    """List audit logs with filters."""
    offset = (page - 1) * per_page

    conditions = []
    # Filter by action (ignore empty strings)
    if action and action.strip():
        conditions.append(AuditLog.action == action)
    if resource_id and resource_id.strip():
        conditions.append(AuditLog.resource_id == resource_id)
    if account_id and account_id.strip():
        conditions.append(AuditLog.account_id == account_id)
    if user and user.strip():
        conditions.append(AuditLog.performed_by.ilike(f"%{user.strip()}%"))
    if start_date:
        conditions.append(AuditLog.created_at >= start_date)
    if end_date:
        conditions.append(AuditLog.created_at <= end_date)

    query = (
        select(AuditLog)
        .options(selectinload(AuditLog.rule))
        .order_by(AuditLog.created_at.desc())
    )

    if conditions:
        query = query.where(and_(*conditions))

    query = query.offset(offset).limit(per_page)
    result = await db.execute(query)
    logs = result.scalars().all()

    # Get total
    count_query = select(AuditLog)
    if conditions:
        count_query = count_query.where(and_(*conditions))
    count_result = await db.execute(count_query)
    total = len(count_result.scalars().all())

    return AuditLogListResponse(
        items=[
            {
                "id": str(log.id),
                "action": log.action,
                "resource_id": log.resource_id,
                "resource_type": log.resource_type,
                "account_id": log.account_id,
                "region": log.region,
                "rule": {
                    "id": str(log.rule.id),
                    "rule_id": log.rule.rule_id,
                    "name": log.rule.name,
                } if log.rule else None,
                "performed_by": log.performed_by,
                "job_id": str(log.job_id) if log.job_id else None,
                "before_state": log.before_state,
                "after_state": log.after_state,
                "details": log.details,
                "created_at": log.created_at.isoformat(),
            }
            for log in logs
        ],
        total=total,
        page=page,
        per_page=per_page,
        pages=(total + per_page - 1) // per_page if total > 0 else 1,
    )


@router.get("/export")
async def export_audit_logs(
    action: Optional[str] = None,
    resource_id: Optional[str] = None,
    account_id: Optional[str] = None,
    user: Optional[str] = None,
    start_date: Optional[datetime] = None,
    end_date: Optional[datetime] = None,
    db: AsyncSession = Depends(get_db),
):
    """Export audit logs to CSV."""
    conditions = []
    if action and action.strip():
        conditions.append(AuditLog.action == action)
    if resource_id and resource_id.strip():
        conditions.append(AuditLog.resource_id == resource_id)
    if account_id and account_id.strip():
        conditions.append(AuditLog.account_id == account_id)
    if user and user.strip():
        conditions.append(AuditLog.performed_by.ilike(f"%{user.strip()}%"))
    if start_date:
        conditions.append(AuditLog.created_at >= start_date)
    if end_date:
        conditions.append(AuditLog.created_at <= end_date)

    query = (
        select(AuditLog)
        .options(selectinload(AuditLog.rule))
        .order_by(AuditLog.created_at.desc())
    )

    if conditions:
        query = query.where(and_(*conditions))

    result = await db.execute(query)
    logs = result.scalars().all()

    # Create CSV
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "Timestamp", "Action", "Resource ID", "Resource Type",
        "Account ID", "Region", "Rule", "Performed By"
    ])

    for log in logs:
        writer.writerow([
            log.created_at.isoformat(),
            log.action,
            log.resource_id or "",
            log.resource_type or "",
            log.account_id or "",
            log.region or "",
            log.rule.name if log.rule else "",
            log.performed_by,
        ])

    output.seek(0)

    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=audit_logs.csv"}
    )


@router.get("/{log_id}")
async def get_audit_log(
    log_id: UUID,
    db: AsyncSession = Depends(get_db),
):
    """Get audit log details."""
    result = await db.execute(
        select(AuditLog)
        .options(selectinload(AuditLog.rule))
        .where(AuditLog.id == log_id)
    )
    log = result.scalar_one_or_none()

    if not log:
        raise HTTPException(status_code=404, detail="Audit log not found")

    return {
        "id": str(log.id),
        "action": log.action,
        "resource_id": log.resource_id,
        "resource_type": log.resource_type,
        "account_id": log.account_id,
        "region": log.region,
        "rule": {
            "id": str(log.rule.id),
            "rule_id": log.rule.rule_id,
            "name": log.rule.name,
        } if log.rule else None,
        "performed_by": log.performed_by,
        "job_id": str(log.job_id) if log.job_id else None,
        "before_state": log.before_state,
        "after_state": log.after_state,
        "details": log.details,
        "created_at": log.created_at.isoformat(),
    }
