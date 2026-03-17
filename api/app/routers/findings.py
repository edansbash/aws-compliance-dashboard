from uuid import UUID
from typing import Optional
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_, or_
from sqlalchemy.orm import selectinload

from app.database import get_db
from app.models import Finding, Rule, ComplianceException, AuditLog
from app.schemas.finding import (
    FindingListResponse,
    WorkflowUpdate,
    WorkflowUpdateResponse,
    RescanResponse,
)
from app.services.cache import (
    get_cached, set_cached, invalidate_pattern,
    make_cache_key, CACHE_FINDINGS, CACHE_SUMMARY, CACHE_RULES
)
from app.services.notifications.jira import (
    get_jira_config,
    JiraNotifier,
)

router = APIRouter()


@router.get("", response_model=FindingListResponse)
async def list_findings(
    status: Optional[str] = None,
    workflow_status: Optional[str] = None,
    severity: Optional[str] = None,
    account_id: Optional[str] = None,
    region: Optional[str] = None,
    rule_id: Optional[UUID] = None,
    search: Optional[str] = None,
    page: int = 1,
    per_page: int = 20,
    db: AsyncSession = Depends(get_db),
):
    """List findings with filters."""
    offset = (page - 1) * per_page

    # Build query with filters
    conditions = []
    if status:
        conditions.append(Finding.status == status)
    if workflow_status:
        conditions.append(Finding.workflow_status == workflow_status)
    if account_id:
        conditions.append(Finding.account_id == account_id)
    if region:
        conditions.append(Finding.region == region)
    if rule_id:
        conditions.append(Finding.rule_id == rule_id)
    if search:
        search_pattern = f"%{search}%"
        conditions.append(
            or_(
                Finding.resource_name.ilike(search_pattern),
                Finding.resource_id.ilike(search_pattern),
            )
        )

    query = (
        select(Finding)
        .options(selectinload(Finding.rule), selectinload(Finding.scan))
        .order_by(Finding.created_at.desc())
    )

    if conditions:
        query = query.where(and_(*conditions))

    # Filter by severity if specified (need to join with Rule)
    if severity:
        query = query.join(Rule).where(Rule.severity == severity)

    query = query.offset(offset).limit(per_page)

    result = await db.execute(query)
    findings = result.scalars().all()

    # Get total count
    count_query = select(Finding)
    if conditions:
        count_query = count_query.where(and_(*conditions))
    if severity:
        count_query = count_query.join(Rule).where(Rule.severity == severity)

    count_result = await db.execute(count_query)
    total = len(count_result.scalars().all())

    return FindingListResponse(
        items=[
            {
                "id": str(f.id),
                "scan_id": str(f.scan_id),
                "resource_id": f.resource_id,
                "resource_name": f.resource_name,
                "resource_type": f.resource_type,
                "account_id": f.account_id,
                "region": f.region,
                "status": f.status,
                "workflow_status": f.workflow_status,
                "workflow_notes": f.workflow_notes,
                "rule": {
                    "id": str(f.rule.id),
                    "rule_id": f.rule.rule_id,
                    "name": f.rule.name,
                    "severity": f.rule.severity,
                } if f.rule else None,
                "details": f.details,
                "created_at": f.created_at.isoformat(),
                "last_scanned_at": f.last_scanned_at.isoformat() if f.last_scanned_at else (f.scan.created_at.isoformat() if f.scan else None),
                "jira_ticket_key": f.jira_ticket_key,
            }
            for f in findings
        ],
        total=total,
        page=page,
        per_page=per_page,
        pages=(total + per_page - 1) // per_page if total > 0 else 1,
    )


@router.get("/summary")
async def get_findings_summary(
    account_id: Optional[str] = None,
    region: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
):
    """Get aggregated compliance summary."""
    # Check cache first
    cache_key = make_cache_key(CACHE_SUMMARY, account_id=account_id, region=region)
    cached = await get_cached(cache_key)
    if cached:
        return cached

    conditions = []
    if account_id:
        conditions.append(Finding.account_id == account_id)
    if region:
        conditions.append(Finding.region == region)

    query = select(Finding).options(selectinload(Finding.rule))
    if conditions:
        query = query.where(and_(*conditions))

    result = await db.execute(query)
    findings = result.scalars().all()

    # Calculate summary
    total = len(findings)
    by_status = {}
    by_severity = {}
    by_workflow = {}
    by_account = {}
    by_resource_type = {}
    failing_by_severity = {}
    unique_resources = set()
    # Track status breakdown by severity
    by_severity_status = {
        "CRITICAL": {"PASS": 0, "FAIL": 0, "EXCEPTION": 0},
        "HIGH": {"PASS": 0, "FAIL": 0, "EXCEPTION": 0},
        "MEDIUM": {"PASS": 0, "FAIL": 0, "EXCEPTION": 0},
        "LOW": {"PASS": 0, "FAIL": 0, "EXCEPTION": 0},
    }

    for f in findings:
        # Track unique resources
        unique_resources.add(f.resource_id)

        # By resource type (track unique resources per type)
        if f.resource_type not in by_resource_type:
            by_resource_type[f.resource_type] = {"resources": set(), "findings": 0, "failing": 0}
        by_resource_type[f.resource_type]["resources"].add(f.resource_id)
        by_resource_type[f.resource_type]["findings"] += 1
        if f.status == "FAIL":
            by_resource_type[f.resource_type]["failing"] += 1

        # By status
        by_status[f.status] = by_status.get(f.status, 0) + 1

        # By severity
        if f.rule:
            by_severity[f.rule.severity] = by_severity.get(f.rule.severity, 0) + 1

            # Failing findings by severity (only count FAIL status)
            if f.status == "FAIL":
                failing_by_severity[f.rule.severity] = failing_by_severity.get(f.rule.severity, 0) + 1

            # Track status breakdown by severity
            if f.rule.severity in by_severity_status:
                status_key = f.status if f.status in ["PASS", "FAIL", "EXCEPTION"] else "FAIL"
                by_severity_status[f.rule.severity][status_key] += 1

        # By workflow status
        by_workflow[f.workflow_status] = by_workflow.get(f.workflow_status, 0) + 1

        # By account
        if f.account_id not in by_account:
            by_account[f.account_id] = {
                "total": 0,
                "passing": 0,
                "failing": 0,
                "exceptions": 0,
                "resources": set(),
                "by_severity": {},
                "failing_by_severity": {},
            }
        by_account[f.account_id]["total"] += 1
        by_account[f.account_id]["resources"].add(f.resource_id)
        if f.status == "PASS":
            by_account[f.account_id]["passing"] += 1
        elif f.status == "FAIL":
            by_account[f.account_id]["failing"] += 1
            if f.rule:
                sev = f.rule.severity
                by_account[f.account_id]["failing_by_severity"][sev] = \
                    by_account[f.account_id]["failing_by_severity"].get(sev, 0) + 1
        elif f.status == "EXCEPTION":
            by_account[f.account_id]["exceptions"] += 1
        if f.rule:
            sev = f.rule.severity
            by_account[f.account_id]["by_severity"][sev] = \
                by_account[f.account_id]["by_severity"].get(sev, 0) + 1

    # Count PASS and EXCEPTION as compliant (EXCEPTION means explicitly allowed)
    passing = by_status.get("PASS", 0) + by_status.get("EXCEPTION", 0)
    compliance_score = (passing / total * 100) if total > 0 else 100

    # Convert resource sets to counts for JSON serialization
    by_account_serializable = {}
    for account_id, data in by_account.items():
        by_account_serializable[account_id] = {
            "total": data["total"],
            "passing": data["passing"],
            "failing": data["failing"],
            "exceptions": data["exceptions"],
            "resource_count": len(data["resources"]),
            "by_severity": data["by_severity"],
            "failing_by_severity": data["failing_by_severity"],
        }

    # Convert resource type sets to counts
    by_resource_type_serializable = {}
    for resource_type, data in by_resource_type.items():
        by_resource_type_serializable[resource_type] = {
            "resource_count": len(data["resources"]),
            "finding_count": data["findings"],
            "failing_count": data["failing"],
        }

    response = {
        "total_findings": total,
        "total_resources": len(unique_resources),
        "compliance_score": round(compliance_score, 1),
        "by_status": by_status,
        "by_severity": by_severity,
        "failing_by_severity": failing_by_severity,
        "by_severity_status": by_severity_status,
        "by_workflow_status": by_workflow,
        "by_account": by_account_serializable,
        "by_resource_type": by_resource_type_serializable,
    }

    # Cache the response
    await set_cached(cache_key, response)

    return response


@router.get("/{finding_id}")
async def get_finding(
    finding_id: UUID,
    db: AsyncSession = Depends(get_db),
):
    """Get finding details."""
    result = await db.execute(
        select(Finding)
        .options(selectinload(Finding.rule))
        .where(Finding.id == finding_id)
    )
    finding = result.scalar_one_or_none()

    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    return {
        "id": str(finding.id),
        "scan_id": str(finding.scan_id),
        "resource_id": finding.resource_id,
        "resource_name": finding.resource_name,
        "resource_type": finding.resource_type,
        "account_id": finding.account_id,
        "region": finding.region,
        "status": finding.status,
        "workflow_status": finding.workflow_status,
        "workflow_updated_by": finding.workflow_updated_by,
        "workflow_updated_at": finding.workflow_updated_at.isoformat() if finding.workflow_updated_at else None,
        "workflow_notes": finding.workflow_notes,
        "rule": {
            "id": str(finding.rule.id),
            "rule_id": finding.rule.rule_id,
            "name": finding.rule.name,
            "description": finding.rule.description,
            "severity": finding.rule.severity,
            "has_remediation": finding.rule.has_remediation,
        } if finding.rule else None,
        "details": finding.details,
        "created_at": finding.created_at.isoformat(),
        "jira_ticket_key": finding.jira_ticket_key,
    }


@router.patch("/{finding_id}/workflow", response_model=WorkflowUpdateResponse)
async def update_workflow_status(
    finding_id: UUID,
    workflow_update: WorkflowUpdate,
    db: AsyncSession = Depends(get_db),
):
    """Update finding workflow status."""
    result = await db.execute(
        select(Finding).where(Finding.id == finding_id)
    )
    finding = result.scalar_one_or_none()

    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    finding.workflow_status = workflow_update.workflow_status
    finding.workflow_updated_by = workflow_update.updated_by or "system"
    finding.workflow_updated_at = datetime.utcnow()

    if workflow_update.notes is not None:
        finding.workflow_notes = workflow_update.notes

    # Create audit log based on workflow status
    audit_action = None
    if workflow_update.workflow_status == "ACKNOWLEDGED":
        audit_action = "FINDING_ACKNOWLEDGED"
    elif workflow_update.workflow_status == "RESOLVED":
        audit_action = "FINDING_RESOLVED"

    if audit_action:
        audit_log = AuditLog(
            action=audit_action,
            resource_id=finding.resource_id,
            resource_type=finding.resource_type,
            account_id=finding.account_id,
            region=finding.region,
            rule_id=finding.rule_id,
            performed_by=workflow_update.updated_by or "system",
            details={
                "finding_id": str(finding.id),
                "status": finding.status,
                "notes": finding.workflow_notes,
            }
        )
        db.add(audit_log)

    await db.commit()
    await db.refresh(finding)

    # Invalidate caches
    await invalidate_pattern(f"{CACHE_FINDINGS}:*")
    await invalidate_pattern(f"{CACHE_SUMMARY}:*")
    await invalidate_pattern(f"{CACHE_RULES}:*")

    return WorkflowUpdateResponse(
        id=finding.id,
        workflow_status=finding.workflow_status,
        workflow_updated_by=finding.workflow_updated_by,
        workflow_updated_at=finding.workflow_updated_at,
        workflow_notes=finding.workflow_notes,
    )


@router.post("/{finding_id}/rescan", response_model=RescanResponse)
async def rescan_finding(
    finding_id: UUID,
    db: AsyncSession = Depends(get_db),
):
    """Rescan a single resource to verify fix."""
    result = await db.execute(
        select(Finding)
        .options(selectinload(Finding.rule))
        .where(Finding.id == finding_id)
    )
    finding = result.scalar_one_or_none()

    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    # Import and execute single resource scan
    from app.services.scanner import rescan_single_resource

    try:
        scan_result, updated_details = await rescan_single_resource(finding)
        previous_status = finding.status

        # Update finding details with latest resource data (including tags)
        finding.details = updated_details

        # Check if there's an active exception for this finding
        exception_query = select(ComplianceException).where(
            and_(
                ComplianceException.rule_id == finding.rule_id,
                or_(
                    # Resource-level exception
                    and_(
                        ComplianceException.scope == "RESOURCE",
                        ComplianceException.resource_id == finding.resource_id,
                    ),
                    # Account-level exception
                    and_(
                        ComplianceException.scope == "ACCOUNT",
                        ComplianceException.account_id == finding.account_id,
                    ),
                    # Rule-level exception
                    ComplianceException.scope == "RULE",
                ),
                or_(
                    ComplianceException.expires_at.is_(None),
                    ComplianceException.expires_at > datetime.utcnow(),
                ),
            )
        )
        exception_result = await db.execute(exception_query)
        has_active_exception = exception_result.scalar_one_or_none() is not None

        # If there's an active exception, keep EXCEPTION status regardless of scan result
        if has_active_exception:
            new_status = "EXCEPTION"
            message = f"Resource scan result: {scan_result} (exception active)"
        else:
            new_status = scan_result
            message = "Resource now compliant" if new_status == "PASS" else "Resource still non-compliant"

        finding.status = new_status
        finding.last_scanned_at = datetime.utcnow()
        if new_status == "PASS":
            finding.workflow_status = "RESOLVED"
            finding.workflow_updated_at = datetime.utcnow()

        await db.commit()

        # Close JIRA ticket if rescan passes and ticket exists
        if new_status == "PASS" and finding.jira_ticket_key:
            try:
                from app.services.notifications.jira import close_jira_ticket_for_rescan_pass
                rule_name = finding.rule.name if finding.rule else "Unknown Rule"
                await close_jira_ticket_for_rescan_pass(
                    jira_ticket_key=finding.jira_ticket_key,
                    resource_name=finding.resource_name,
                    rule_name=rule_name,
                )
            except Exception as e:
                # Log but don't fail the rescan
                import logging
                logging.getLogger(__name__).warning(
                    f"Failed to close JIRA ticket {finding.jira_ticket_key} for rescan pass: {e}"
                )

        return RescanResponse(
            finding_id=finding.id,
            previous_status=previous_status,
            new_status=new_status,
            resource_id=finding.resource_id,
            message=message,
            scanned_at=datetime.utcnow(),
        )
    except Exception as e:
        return RescanResponse(
            finding_id=finding.id,
            previous_status=finding.status,
            new_status="ERROR",
            resource_id=finding.resource_id,
            message=f"Error during rescan: {str(e)}",
            scanned_at=datetime.utcnow(),
        )


@router.post("/{finding_id}/create-jira-ticket")
async def create_jira_ticket_for_finding(
    finding_id: UUID,
    db: AsyncSession = Depends(get_db),
):
    """
    Manually create a JIRA ticket for a finding.

    This endpoint creates a JIRA ticket with all AWS Security Hub custom fields
    populated, similar to automatic ticket creation during scans.
    """
    import logging
    logger = logging.getLogger(__name__)

    # Get finding with rule relationship
    result = await db.execute(
        select(Finding)
        .options(selectinload(Finding.rule))
        .where(Finding.id == finding_id)
    )
    finding = result.scalar_one_or_none()

    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    # Check if finding already has a JIRA ticket
    if finding.jira_ticket_key:
        raise HTTPException(
            status_code=400,
            detail=f"Finding already has JIRA ticket: {finding.jira_ticket_key}"
        )

    # Get JIRA configuration
    config = await get_jira_config()
    if not config or not config.is_enabled:
        raise HTTPException(
            status_code=400,
            detail="JIRA integration is not enabled"
        )

    if not all([config.base_url, config.email, config.api_token, config.project_key]):
        raise HTTPException(
            status_code=400,
            detail="JIRA configuration is incomplete"
        )

    # Create the JIRA ticket
    async with JiraNotifier(
        base_url=config.base_url,
        email=config.email,
        api_token=config.api_token,
        project_key=config.project_key,
        issue_type=config.issue_type or "Bug",
        min_severity=config.min_severity,
        assignee_email=config.assignee_email,
    ) as notifier:
        # Get rule info for ticket
        rule = finding.rule
        if not rule:
            raise HTTPException(
                status_code=400,
                detail="Finding has no associated rule"
            )

        # Determine finding type based on status
        finding_type = "new"

        # Get remediation text if rule has remediation
        remediation_text = None
        if rule.has_remediation:
            from app.services.rules import RULE_REGISTRY
            rule_class = RULE_REGISTRY.get(rule.rule_id)
            if rule_class:
                remediation_text = rule_class.get_remediation_description()

        issue_key = await notifier.create_finding_ticket(
            finding_id=str(finding.id),
            finding_type=finding_type,
            rule_id=rule.rule_id,
            rule_name=rule.name,
            rule_description=rule.description or "",
            rule_severity=rule.severity,
            resource_id=finding.resource_id,
            resource_name=finding.resource_name,
            resource_type=finding.resource_type,
            account_id=finding.account_id,
            region=finding.region,
            created_at=finding.created_at,
            first_seen_at=finding.created_at,
            details=finding.details,
            remediation_text=remediation_text,
            skip_duplicate_check=True,  # We already checked above
        )

        if not issue_key:
            raise HTTPException(
                status_code=500,
                detail="Failed to create JIRA ticket"
            )

        # Store the ticket key on the finding
        finding.jira_ticket_key = issue_key
        await db.commit()

        # Create audit log
        audit_log = AuditLog(
            action="JIRA_TICKET_CREATED",
            resource_id=finding.resource_id,
            resource_type=finding.resource_type,
            account_id=finding.account_id,
            region=finding.region,
            rule_id=finding.rule_id,
            performed_by="user",
            details={
                "finding_id": str(finding.id),
                "jira_ticket_key": issue_key,
                "manual": True,
            }
        )
        db.add(audit_log)
        await db.commit()

        logger.info(f"Manually created JIRA ticket {issue_key} for finding {finding_id}")

        return {
            "success": True,
            "jira_ticket_key": issue_key,
            "jira_ticket_url": f"{config.base_url}/browse/{issue_key}",
        }
