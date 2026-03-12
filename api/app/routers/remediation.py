import uuid
from uuid import UUID
from typing import Optional, List
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from sqlalchemy.orm import selectinload
from sse_starlette.sse import EventSourceResponse
import asyncio
import json

from app.database import get_db, AsyncSessionLocal
from app.models import RemediationJob, RemediationLog, Finding, AuditLog
from app.models.remediation import RemediationStatus, LogLevel
from app.schemas.remediation import (
    RemediationPreviewRequest,
    RemediationPreviewResponse,
    RemediationCreateRequest,
    RemediationJobResponse,
    RemediationListResponse,
)
from app.services.cache import (
    invalidate_pattern, CACHE_FINDINGS, CACHE_SUMMARY, CACHE_RULES
)
from app.services.job_queue import enqueue_remediation_job
from app.services.job_publisher import JobStatusSubscriber

router = APIRouter()


@router.get("/available")
async def list_available_remediations():
    """
    List all rules that have remediation capability.
    Returns rule metadata including remediation description and tested status.
    """
    from app.services.rules import RULE_REGISTRY

    remediations = []
    for rule_id, rule_class in RULE_REGISTRY.items():
        if rule_class.has_remediation:
            remediations.append({
                "rule_id": rule_class.rule_id,
                "name": rule_class.name,
                "description": rule_class.description,
                "resource_type": rule_class.resource_type,
                "severity": rule_class.severity.value if hasattr(rule_class.severity, 'value') else rule_class.severity,
                "remediation_description": rule_class.get_remediation_description(),
                "remediation_tested": rule_class.remediation_tested,
            })

    # Sort by severity (CRITICAL first), then by name
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    remediations.sort(key=lambda x: (severity_order.get(x["severity"], 5), x["name"]))

    return {
        "items": remediations,
        "total": len(remediations),
    }


@router.get("", response_model=RemediationListResponse)
async def list_remediation_jobs(
    page: int = 1,
    per_page: int = 20,
    db: AsyncSession = Depends(get_db),
):
    """List remediation jobs."""
    offset = (page - 1) * per_page
    query = (
        select(RemediationJob)
        .options(
            selectinload(RemediationJob.finding).selectinload(Finding.rule)
        )
        .order_by(RemediationJob.created_at.desc())
        .offset(offset)
        .limit(per_page)
    )
    result = await db.execute(query)
    jobs = result.scalars().all()

    count_result = await db.execute(select(RemediationJob))
    total = len(count_result.scalars().all())

    # Convert jobs to response format with finding data
    job_responses = []
    for job in jobs:
        job_dict = {
            "id": job.id,
            "status": job.status,
            "finding_id": job.finding_id,
            "batch_id": job.batch_id,
            "confirmed_by": job.confirmed_by,
            "started_at": job.started_at,
            "completed_at": job.completed_at,
            "error_message": job.error_message,
            "created_at": job.created_at,
        }

        # Add finding info if available
        if job.finding:
            job_dict["finding"] = {
                "resource_id": job.finding.resource_id,
                "resource_name": job.finding.resource_name,
                "account_id": job.finding.account_id,
                "region": job.finding.region,
                "rule": {
                    "name": job.finding.rule.name
                } if job.finding.rule else None
            }

        job_responses.append(RemediationJobResponse(**job_dict))

    return RemediationListResponse(
        items=job_responses,
        total=total,
        page=page,
        per_page=per_page,
        pages=(total + per_page - 1) // per_page if total > 0 else 1,
    )


@router.post("/preview", response_model=RemediationPreviewResponse)
async def preview_remediation(
    request: RemediationPreviewRequest,
    db: AsyncSession = Depends(get_db),
):
    """Preview planned changes (no persistence)."""
    from app.services.rules import RULE_REGISTRY

    findings_preview = []
    remediable_count = 0

    for finding_id in request.finding_ids:
        result = await db.execute(
            select(Finding)
            .options(selectinload(Finding.rule))
            .where(Finding.id == finding_id)
        )
        finding = result.scalar_one_or_none()

        if not finding:
            continue

        # Check if rule has remediation
        rule_class = RULE_REGISTRY.get(finding.rule.rule_id) if finding.rule else None
        can_remediate = rule_class is not None and rule_class.has_remediation if rule_class else False

        preview_item = {
            "finding_id": str(finding.id),
            "resource_id": finding.resource_id,
            "resource_name": finding.resource_name,
            "rule_name": finding.rule.name if finding.rule else "Unknown",
            "can_remediate": can_remediate,
        }

        if can_remediate:
            # Get preview from rule
            preview_item["planned_action"] = rule_class.get_remediation_description()
            preview_item["preview"] = {
                "before": finding.details,
                "after": rule_class.get_expected_state(finding.details),
            }
            remediable_count += 1
        else:
            preview_item["planned_action"] = None
            preview_item["reason"] = "Remediation not supported for this rule"

        findings_preview.append(preview_item)

    return RemediationPreviewResponse(
        findings=findings_preview,
        total=len(findings_preview),
        remediable=remediable_count,
    )


@router.post("")
async def create_remediation_job(
    request: RemediationCreateRequest,
    db: AsyncSession = Depends(get_db),
):
    """Create individual remediation jobs for each finding."""
    from app.schemas.remediation import RemediationBatchResponse

    # Generate batch_id to group related jobs
    batch_id = uuid.uuid4()
    jobs = []

    # Create one job per finding
    for finding_id in request.finding_ids:
        job = RemediationJob(
            status=RemediationStatus.QUEUED,
            finding_id=finding_id,
            batch_id=batch_id,
            confirmed_by=request.confirmed_by,
        )
        db.add(job)
        jobs.append(job)

    # Flush to ensure IDs are assigned by SQLAlchemy
    await db.flush()

    # Now collect the IDs after flush
    job_ids = [job.id for job in jobs]

    await db.commit()

    # Enqueue each job to Redis for worker to process
    for job_id, finding_id in zip(job_ids, request.finding_ids):
        await enqueue_remediation_job(
            remediation_job_id=str(job_id),
            finding_ids=[str(finding_id)],
            confirmed_by=request.confirmed_by
        )

    return RemediationBatchResponse(
        batch_id=batch_id,
        job_ids=job_ids,
        total_jobs=len(job_ids)
    )


@router.get("/{job_id}", response_model=RemediationJobResponse)
async def get_remediation_job(
    job_id: UUID,
    db: AsyncSession = Depends(get_db),
):
    """Get remediation job details."""
    result = await db.execute(
        select(RemediationJob).where(RemediationJob.id == job_id)
    )
    job = result.scalar_one_or_none()

    if not job:
        raise HTTPException(status_code=404, detail="Job not found")

    return RemediationJobResponse.model_validate(job)


@router.post("/{job_id}/cancel", response_model=RemediationJobResponse)
async def cancel_remediation_job(
    job_id: UUID,
    db: AsyncSession = Depends(get_db),
):
    """Cancel a running remediation job."""
    result = await db.execute(
        select(RemediationJob).where(RemediationJob.id == job_id)
    )
    job = result.scalar_one_or_none()

    if not job:
        raise HTTPException(status_code=404, detail="Job not found")

    if job.status not in [RemediationStatus.QUEUED, RemediationStatus.RUNNING]:
        raise HTTPException(status_code=400, detail="Job is not queued or running")

    job.status = RemediationStatus.CANCELLED
    job.completed_at = datetime.utcnow()
    await db.commit()
    await db.refresh(job)

    return RemediationJobResponse.model_validate(job)


@router.get("/{job_id}/logs")
async def get_remediation_logs(
    job_id: UUID,
    after: Optional[datetime] = None,
    db: AsyncSession = Depends(get_db),
):
    """Get execution logs."""
    # Verify job exists
    job_result = await db.execute(
        select(RemediationJob).where(RemediationJob.id == job_id)
    )
    if not job_result.scalar_one_or_none():
        raise HTTPException(status_code=404, detail="Job not found")

    query = (
        select(RemediationLog)
        .where(RemediationLog.job_id == job_id)
        .order_by(RemediationLog.created_at)
    )

    if after:
        query = query.where(RemediationLog.created_at > after)

    result = await db.execute(query)
    logs = result.scalars().all()

    return {
        "logs": [
            {
                "id": str(log.id),
                "resource_id": log.resource_id,
                "level": log.level.value if hasattr(log.level, 'value') else log.level,
                "message": log.message,
                "details": log.details,
                "timestamp": log.created_at.isoformat(),
            }
            for log in logs
        ]
    }


@router.get("/{job_id}/logs/stream")
async def stream_remediation_logs(
    job_id: UUID,
    use_pubsub: bool = True,
    db: AsyncSession = Depends(get_db),
):
    """
    Stream logs via Server-Sent Events.

    Args:
        job_id: The remediation job ID
        use_pubsub: If True (default), use Redis pub/sub for real-time streaming.
                   If False, fall back to DB polling (useful if pub/sub unavailable).
    """
    # Verify job exists
    job_result = await db.execute(
        select(RemediationJob).where(RemediationJob.id == job_id)
    )
    job = job_result.scalar_one_or_none()
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")

    if use_pubsub:
        return EventSourceResponse(pubsub_event_generator(str(job_id)))
    else:
        return EventSourceResponse(db_polling_event_generator(job_id))


async def pubsub_event_generator(job_id: str):
    """
    Stream logs using Redis pub/sub for real-time updates.
    This is faster than DB polling as logs are pushed immediately.
    """
    # First, send any existing logs from DB (for late joiners)
    async with AsyncSessionLocal() as session:
        result = await session.execute(
            select(RemediationLog)
            .where(RemediationLog.job_id == job_id)
            .order_by(RemediationLog.created_at)
        )
        existing_logs = result.scalars().all()

        for log in existing_logs:
            yield {
                "data": json.dumps({
                    "type": "log",
                    "message": log.message,
                    "timestamp": log.created_at.isoformat(),
                    "level": log.level.value if hasattr(log.level, 'value') else log.level,
                    "resource_id": log.resource_id,
                    "details": log.details,
                })
            }

        # Check if job is already complete
        job_result = await session.execute(
            select(RemediationJob).where(RemediationJob.id == job_id)
        )
        job = job_result.scalar_one_or_none()
        if job and job.status not in [RemediationStatus.QUEUED, RemediationStatus.RUNNING]:
            yield {
                "data": json.dumps({
                    "type": "status",
                    "status": job.status.value if hasattr(job.status, 'value') else job.status,
                    "error_message": job.error_message,
                })
            }
            return

    # Subscribe to Redis pub/sub for real-time updates
    async with JobStatusSubscriber(job_id) as subscriber:
        async for message in subscriber:
            # Message is the decoded JSON payload from Redis
            # Determine type based on fields present
            if "level" in message:
                # This is a log message
                yield {
                    "data": json.dumps({
                        "type": "log",
                        "message": message.get("message", ""),
                        "timestamp": message.get("timestamp"),
                        "level": message.get("level"),
                        "resource_id": message.get("resource_id"),
                        "details": message.get("details"),
                    })
                }
            elif "status" in message:
                # This is a status update
                status = message.get("status")
                # Check if this is a completion status
                if status not in ["QUEUED", "RUNNING"]:
                    yield {
                        "data": json.dumps({
                            "type": "status",
                            "status": status,
                            "message": message.get("message"),
                        })
                    }
                    break
                else:
                    # Send progress update
                    yield {
                        "data": json.dumps({
                            "type": "status",
                            "status": status,
                            "message": message.get("message"),
                            "progress": message.get("progress"),
                        })
                    }


async def db_polling_event_generator(job_id: UUID):
    """
    Stream logs by polling the database.
    Fallback method if Redis pub/sub is unavailable.
    """
    last_log_id = None

    while True:
        async with AsyncSessionLocal() as session:
            # Get job status
            job_result = await session.execute(
                select(RemediationJob).where(RemediationJob.id == job_id)
            )
            current_job = job_result.scalar_one_or_none()

            # Get new logs
            query = (
                select(RemediationLog)
                .where(RemediationLog.job_id == job_id)
                .order_by(RemediationLog.created_at)
            )
            if last_log_id:
                query = query.where(RemediationLog.id > last_log_id)

            result = await session.execute(query)
            logs = result.scalars().all()

            for log in logs:
                last_log_id = log.id
                yield {
                    "data": json.dumps({
                        "type": "log",
                        "message": log.message,
                        "timestamp": log.created_at.isoformat(),
                        "level": log.level.value if hasattr(log.level, 'value') else log.level,
                        "resource_id": log.resource_id,
                        "details": log.details,
                    })
                }

            # Check if job is complete (not QUEUED or RUNNING)
            if current_job and current_job.status not in [RemediationStatus.QUEUED, RemediationStatus.RUNNING]:
                yield {
                    "data": json.dumps({
                        "type": "status",
                        "status": current_job.status.value if hasattr(current_job.status, 'value') else current_job.status,
                        "error_message": current_job.error_message,
                    })
                }
                break

        await asyncio.sleep(0.5)


async def log_remediation(
    db,
    job_id: str,
    resource_id: str,
    level: LogLevel,
    message: str,
    details: dict = None
):
    """
    Log remediation event to both DB (persistence) and Redis pub/sub (real-time).

    This hybrid approach provides:
    - DB: Audit trail, historical queries, compliance records
    - Redis: Real-time SSE streaming to frontend
    """
    from app.services.job_publisher import publish_job_log, LogLevel as PubSubLogLevel

    # Write to DB for persistence
    log = RemediationLog(
        job_id=job_id,
        resource_id=resource_id,
        level=level,
        message=message,
        details=details,
    )
    db.add(log)

    # Publish to Redis for real-time streaming
    await publish_job_log(
        entity_id=str(job_id),
        level=PubSubLogLevel(level.value),
        message=message,
        resource_id=resource_id,
        details=details,
    )


async def execute_remediation(job_id: str):
    """Execute remediation for a single finding (called by worker)."""
    from app.services.rules import RULE_REGISTRY
    from app.services.scanner import get_aws_session
    from app.services.job_publisher import publish_job_status

    async with AsyncSessionLocal() as db:
        # Get job with finding relationship
        result = await db.execute(
            select(RemediationJob)
            .options(selectinload(RemediationJob.finding).selectinload(Finding.rule))
            .where(RemediationJob.id == job_id)
        )
        job = result.scalar_one_or_none()
        if not job:
            return

        finding = job.finding

        # Update status to RUNNING
        job.status = RemediationStatus.RUNNING
        job.started_at = datetime.utcnow()

        # Create audit log for remediation started
        audit_log = AuditLog(
            action="REMEDIATION_STARTED",
            resource_id=finding.resource_id,
            resource_type=finding.resource_type,
            account_id=finding.account_id,
            region=finding.region,
            rule_id=finding.rule_id,
            job_id=job.id,
            performed_by=job.confirmed_by,
            details={
                "job_id": str(job.id),
                "finding_id": str(finding.id),
                "resource_name": finding.resource_name,
            }
        )
        db.add(audit_log)
        await db.commit()

        # Publish status update
        await publish_job_status(
            entity_id=str(job_id),
            status="RUNNING",
            message=f"Starting remediation for {finding.resource_name}"
        )

        try:
            # Validate finding and rule
            if not finding or not finding.rule:
                raise Exception(f"Finding {job.finding_id} not found or has no associated rule")

            # Get rule class
            rule_class = RULE_REGISTRY.get(finding.rule.rule_id)
            if not rule_class or not rule_class.has_remediation:
                raise Exception(f"No remediation available for rule '{finding.rule.name}'")

            # Log start with detailed context
            await log_remediation(
                db, job.id, finding.resource_id, LogLevel.INFO,
                f"Starting remediation for {finding.resource_name}",
                details={
                    "resource_id": finding.resource_id,
                    "resource_name": finding.resource_name,
                    "resource_type": finding.resource_type,
                    "rule_id": finding.rule.rule_id,
                    "rule_name": finding.rule.name,
                    "account_id": finding.account_id,
                    "region": finding.region,
                    "planned_action": rule_class.get_remediation_description() if hasattr(rule_class, 'get_remediation_description') else None,
                }
            )
            await db.commit()

            # Get AWS session
            session = await get_aws_session(finding.account_id)

            # Execute remediation
            rule_instance = rule_class()
            await rule_instance.remediate(session, finding.resource_id, finding.region, finding.details)

            # Log success with details
            await log_remediation(
                db, job.id, finding.resource_id, LogLevel.SUCCESS,
                f"Successfully remediated {finding.resource_name}",
                details={
                    "resource_id": finding.resource_id,
                    "resource_name": finding.resource_name,
                    "rule_id": finding.rule.rule_id,
                    "action_taken": rule_class.get_remediation_description() if hasattr(rule_class, 'get_remediation_description') else "Remediation applied",
                }
            )

            # Update finding status
            from app.models.finding import FindingStatus, WorkflowStatus
            finding.status = FindingStatus.PASS
            finding.workflow_status = WorkflowStatus.RESOLVED
            finding.workflow_updated_at = datetime.utcnow()

            # Update job status to COMPLETED
            job.status = RemediationStatus.COMPLETED
            job.completed_at = datetime.utcnow()

            # Create audit log for remediation completed
            audit_log = AuditLog(
                action="REMEDIATION_COMPLETED",
                resource_id=finding.resource_id,
                resource_type=finding.resource_type,
                account_id=finding.account_id,
                region=finding.region,
                rule_id=finding.rule_id,
                job_id=job.id,
                performed_by=job.confirmed_by,
                details={
                    "job_id": str(job.id),
                    "finding_id": str(finding.id),
                    "resource_name": finding.resource_name,
                    "duration_seconds": (job.completed_at - job.started_at).total_seconds() if job.started_at else None,
                }
            )
            db.add(audit_log)
            await db.commit()

            # Resolve JIRA ticket if one exists for this finding
            if finding.jira_ticket_key:
                try:
                    from app.services.notifications.jira import resolve_jira_ticket_for_remediation

                    remediation_action = (
                        rule_class.get_remediation_description()
                        if hasattr(rule_class, 'get_remediation_description')
                        else "Automated remediation applied"
                    )

                    resolved = await resolve_jira_ticket_for_remediation(
                        jira_ticket_key=finding.jira_ticket_key,
                        resource_name=finding.resource_name,
                        remediation_action=remediation_action,
                        performed_by=job.confirmed_by or "system",
                    )

                    if resolved:
                        await log_remediation(
                            db, job.id, finding.resource_id, LogLevel.INFO,
                            f"JIRA ticket {finding.jira_ticket_key} resolved",
                            details={"jira_ticket_key": finding.jira_ticket_key}
                        )
                        await db.commit()
                except Exception as jira_error:
                    # Log but don't fail the remediation for JIRA errors
                    await log_remediation(
                        db, job.id, finding.resource_id, LogLevel.WARNING,
                        f"Failed to resolve JIRA ticket {finding.jira_ticket_key}: {str(jira_error)}",
                        details={"jira_ticket_key": finding.jira_ticket_key, "error": str(jira_error)}
                    )
                    await db.commit()

            # Publish success status
            await publish_job_status(
                entity_id=str(job_id),
                status="COMPLETED",
                message=f"Successfully remediated {finding.resource_name}"
            )

        except Exception as e:
            # Log error with full context
            import traceback
            error_msg = str(e)

            await log_remediation(
                db, job.id, finding.resource_id if finding else None, LogLevel.ERROR,
                f"Failed to remediate {finding.resource_name if finding else 'resource'}: {error_msg}",
                details={
                    "resource_id": finding.resource_id if finding else None,
                    "resource_name": finding.resource_name if finding else None,
                    "rule_id": finding.rule.rule_id if finding and finding.rule else None,
                    "error": error_msg,
                    "error_type": type(e).__name__,
                    "traceback": traceback.format_exc(),
                }
            )

            # Update job status to FAILED
            job.status = RemediationStatus.FAILED
            job.completed_at = datetime.utcnow()
            job.error_message = error_msg[:1000]  # Truncate if too long

            # Create audit log for remediation failed
            audit_log = AuditLog(
                action="REMEDIATION_FAILED",
                resource_id=finding.resource_id if finding else None,
                resource_type=finding.resource_type if finding else None,
                account_id=finding.account_id if finding else None,
                region=finding.region if finding else None,
                rule_id=finding.rule_id if finding else None,
                job_id=job.id,
                performed_by=job.confirmed_by,
                details={
                    "job_id": str(job.id),
                    "finding_id": str(finding.id) if finding else None,
                    "resource_name": finding.resource_name if finding else None,
                    "error": error_msg,
                    "duration_seconds": (job.completed_at - job.started_at).total_seconds() if job.started_at else None,
                }
            )
            db.add(audit_log)
            await db.commit()

            # Publish failure status
            await publish_job_status(
                entity_id=str(job_id),
                status="FAILED",
                message=f"Failed: {error_msg}"
            )

        # Invalidate caches after remediation
        await invalidate_pattern(f"{CACHE_FINDINGS}:*")
        await invalidate_pattern(f"{CACHE_SUMMARY}:*")
        await invalidate_pattern(f"{CACHE_RULES}:*")
