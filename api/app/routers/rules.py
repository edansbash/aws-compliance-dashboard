from uuid import UUID
import uuid
from typing import Optional
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
import asyncio

from app.database import get_db
from app.models import Rule, Finding, Scan, AWSAccount, RemediationJob
from app.models.finding import FindingStatus
from app.models.remediation import RemediationStatus
from app.schemas.rule import RuleResponse, RuleListResponse, RuleUpdate
from app.schemas.scan import ScanResponse
from app.schemas.remediation import RemediationJobResponse, RemediationBatchResponse
from app.services.rules import RULE_REGISTRY
from app.services.scanner import execute_scan
from app.services.job_queue import enqueue_remediation_job, enqueue_scan_job
from app.services.cache import (
    get_cached, set_cached, invalidate_pattern,
    make_cache_key, CACHE_RULES
)
from app.routers.remediation import execute_remediation

router = APIRouter()


@router.post("/sync")
async def sync_rules(db: AsyncSession = Depends(get_db)):
    """Sync rules from code registry to database."""
    synced = 0
    updated = 0
    for rule_id, rule_class in RULE_REGISTRY.items():
        result = await db.execute(
            select(Rule).where(Rule.rule_id == rule_id)
        )
        existing = result.scalar_one_or_none()

        if not existing:
            rule = Rule(
                rule_id=rule_class.rule_id,
                name=rule_class.name,
                description=rule_class.description,
                resource_type=rule_class.resource_type,
                severity=rule_class.severity.value,
                is_enabled=True,
                has_remediation=rule_class.has_remediation,
                remediation_tested=rule_class.remediation_tested,
            )
            db.add(rule)
            synced += 1
        else:
            # Update remediation fields from code
            existing.has_remediation = rule_class.has_remediation
            existing.remediation_tested = rule_class.remediation_tested
            updated += 1

    await db.commit()
    return {"message": f"Synced {synced} new rules, updated {updated} existing", "total_rules": len(RULE_REGISTRY)}


@router.get("", response_model=RuleListResponse)
async def list_rules(
    page: int = 1,
    per_page: int = 50,
    db: AsyncSession = Depends(get_db),
):
    """List all rules."""
    # Check cache first
    cache_key = make_cache_key(CACHE_RULES, "list", page=page, per_page=per_page)
    cached = await get_cached(cache_key)
    if cached:
        return RuleListResponse(**cached)

    offset = (page - 1) * per_page
    query = select(Rule).order_by(Rule.name).offset(offset).limit(per_page)
    result = await db.execute(query)
    rules = result.scalars().all()

    # Get finding counts per rule (only count FAIL findings for status)
    rules_with_counts = []
    for rule in rules:
        # Count only FAIL findings to determine if rule is failing
        fail_count_result = await db.execute(
            select(Finding).where(
                Finding.rule_id == rule.id,
                Finding.status == FindingStatus.FAIL
            )
        )
        fail_count = len(fail_count_result.scalars().all())
        rules_with_counts.append({
            **RuleResponse.model_validate(rule).model_dump(),
            "finding_count": fail_count,
        })

    count_result = await db.execute(select(Rule))
    total = len(count_result.scalars().all())

    response = RuleListResponse(
        items=rules_with_counts,
        total=total,
        page=page,
        per_page=per_page,
        pages=(total + per_page - 1) // per_page if total > 0 else 1,
    )

    # Cache the response
    await set_cached(cache_key, response.model_dump())

    return response


@router.get("/{rule_id}", response_model=RuleResponse)
async def get_rule(
    rule_id: UUID,
    db: AsyncSession = Depends(get_db),
):
    """Get rule details."""
    result = await db.execute(select(Rule).where(Rule.id == rule_id))
    rule = result.scalar_one_or_none()

    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")

    return RuleResponse.model_validate(rule)


@router.put("/{rule_id}", response_model=RuleResponse)
async def update_rule(
    rule_id: UUID,
    rule_update: RuleUpdate,
    db: AsyncSession = Depends(get_db),
):
    """Update rule (enable/disable)."""
    result = await db.execute(select(Rule).where(Rule.id == rule_id))
    rule = result.scalar_one_or_none()

    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")

    if rule_update.is_enabled is not None:
        rule.is_enabled = rule_update.is_enabled

    await db.commit()
    await db.refresh(rule)

    # Invalidate rules cache
    await invalidate_pattern(f"{CACHE_RULES}:*")

    return RuleResponse.model_validate(rule)


@router.get("/{rule_id}/findings")
async def get_rule_findings(
    rule_id: UUID,
    page: int = 1,
    per_page: int = 20,
    db: AsyncSession = Depends(get_db),
):
    """Get findings for a specific rule."""
    # Verify rule exists
    rule_result = await db.execute(select(Rule).where(Rule.id == rule_id))
    if not rule_result.scalar_one_or_none():
        raise HTTPException(status_code=404, detail="Rule not found")

    offset = (page - 1) * per_page
    query = (
        select(Finding)
        .where(Finding.rule_id == rule_id)
        .offset(offset)
        .limit(per_page)
    )
    result = await db.execute(query)
    findings = result.scalars().all()

    count_result = await db.execute(
        select(Finding).where(Finding.rule_id == rule_id)
    )
    total = len(count_result.scalars().all())

    return {
        "items": [
            {
                "id": str(f.id),
                "resource_id": f.resource_id,
                "resource_name": f.resource_name,
                "account_id": f.account_id,
                "region": f.region,
                "status": f.status.value,
                "workflow_status": f.workflow_status.value,
                "created_at": f.created_at.isoformat(),
            }
            for f in findings
        ],
        "total": total,
        "page": page,
        "per_page": per_page,
        "pages": (total + per_page - 1) // per_page if total > 0 else 1,
    }


@router.post("/{rule_id}/scan", response_model=ScanResponse)
async def scan_rule(
    rule_id: UUID,
    db: AsyncSession = Depends(get_db),
):
    """
    Trigger a scan for a specific rule.

    This endpoint:
    1. Creates a scan record in PostgreSQL with status QUEUED
    2. Enqueues the scan job to Redis for the worker to process
    3. Returns immediately with the scan ID

    The worker will:
    1. Pick up the job from Redis queue
    2. Execute the scan and publish status updates to Redis pub/sub
    3. Frontend can subscribe to /scans/{scan_id}/status/stream for real-time updates
    """
    from app.config import settings

    # Verify rule exists
    rule_result = await db.execute(select(Rule).where(Rule.id == rule_id))
    rule = rule_result.scalar_one_or_none()

    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")

    # Get all active accounts
    result = await db.execute(
        select(AWSAccount).where(AWSAccount.is_active == True)
    )
    accounts = result.scalars().all()
    account_ids = [str(a.id) for a in accounts]

    # Get default regions
    regions = settings.default_scan_regions

    # Create scan record with QUEUED status (will be picked up by worker)
    scan = Scan(
        status="QUEUED",
        regions=regions,
        account_ids=account_ids,
        rule_ids=[str(rule_id)],
    )
    db.add(scan)
    await db.commit()
    await db.refresh(scan)

    # Enqueue scan job to Redis for worker to process
    # Worker will publish status updates to Redis pub/sub as it runs
    await enqueue_scan_job(
        scan_id=str(scan.id),
        account_ids=account_ids,
        regions=regions,
        rule_ids=[str(rule_id)]
    )

    return ScanResponse.model_validate(scan)


@router.post("/{rule_id}/remediate-all", response_model=RemediationBatchResponse, status_code=201)
async def remediate_all_findings(
    rule_id: UUID,
    db: AsyncSession = Depends(get_db),
):
    """Remediate all FAIL findings for a specific rule."""
    # Verify rule exists
    rule_result = await db.execute(select(Rule).where(Rule.id == rule_id))
    rule = rule_result.scalar_one_or_none()

    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")

    # Check if rule has remediation
    rule_class = RULE_REGISTRY.get(rule.rule_id)
    if not rule_class or not rule_class.has_remediation:
        raise HTTPException(
            status_code=400,
            detail="Remediation not available for this rule"
        )

    # Get all FAIL findings for this rule
    result = await db.execute(
        select(Finding).where(
            Finding.rule_id == rule_id,
            Finding.status == FindingStatus.FAIL
        )
    )
    findings = result.scalars().all()

    if not findings:
        raise HTTPException(
            status_code=400,
            detail="No failed findings to remediate for this rule"
        )

    # Generate batch_id to group related jobs
    batch_id = uuid.uuid4()
    jobs = []

    # Create one job per finding
    for finding in findings:
        job = RemediationJob(
            status=RemediationStatus.QUEUED,
            finding_id=finding.id,
            batch_id=batch_id,
            confirmed_by="system",
        )
        db.add(job)
        jobs.append(job)

    # Flush to ensure IDs are assigned by SQLAlchemy
    await db.flush()

    # Now collect the IDs after flush
    job_ids = [job.id for job in jobs]

    await db.commit()

    # Enqueue each job to Redis for worker to process
    for job_id, finding in zip(job_ids, findings):
        await enqueue_remediation_job(
            remediation_job_id=str(job_id),
            finding_ids=[str(finding.id)],
            confirmed_by="system"
        )

    return RemediationBatchResponse(
        batch_id=batch_id,
        job_ids=job_ids,
        total_jobs=len(job_ids)
    )
