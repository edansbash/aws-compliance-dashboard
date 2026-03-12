from uuid import UUID
from typing import Optional, List
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_, func
from sqlalchemy.orm import selectinload, joinedload

from app.database import get_db
from app.models import ComplianceException, Finding, Rule, AuditLog
from app.schemas.exception import (
    ExceptionCreate,
    ExceptionBulkCreate,
    ExceptionUpdate,
    ExceptionBulkUpdate,
    ExceptionResponse,
    ExceptionListResponse,
    BulkExceptionResponse,
    BulkUpdateResponse,
)

router = APIRouter()


@router.get("", response_model=ExceptionListResponse)
async def list_exceptions(
    scope: Optional[str] = None,
    rule_id: Optional[UUID] = None,
    account_id: Optional[str] = None,
    page: int = 1,
    per_page: int = 20,
    db: AsyncSession = Depends(get_db),
):
    """List all exceptions sorted by rule name, then resource name."""
    offset = (page - 1) * per_page
    query = (
        select(ComplianceException)
        .join(Rule, ComplianceException.rule_id == Rule.id)
        .options(selectinload(ComplianceException.rule))
        .order_by(Rule.name.asc(), ComplianceException.resource_id.asc())
    )

    if scope:
        query = query.where(ComplianceException.scope == scope)
    if rule_id:
        query = query.where(ComplianceException.rule_id == rule_id)
    if account_id:
        query = query.where(ComplianceException.account_id == account_id)

    query = query.offset(offset).limit(per_page)
    result = await db.execute(query)
    exceptions = result.scalars().all()

    # Get total
    count_query = select(ComplianceException)
    if scope:
        count_query = count_query.where(ComplianceException.scope == scope)
    if rule_id:
        count_query = count_query.where(ComplianceException.rule_id == rule_id)
    if account_id:
        count_query = count_query.where(ComplianceException.account_id == account_id)

    count_result = await db.execute(count_query)
    total = len(count_result.scalars().all())

    return ExceptionListResponse(
        items=[ExceptionResponse.model_validate(e) for e in exceptions],
        total=total,
        page=page,
        per_page=per_page,
        pages=(total + per_page - 1) // per_page if total > 0 else 1,
    )


@router.post("", response_model=ExceptionResponse, status_code=201)
async def create_exception(
    exception: ExceptionCreate,
    db: AsyncSession = Depends(get_db),
):
    """Create a single exception."""
    # Verify rule exists
    rule_result = await db.execute(select(Rule).where(Rule.id == exception.rule_id))
    if not rule_result.scalar_one_or_none():
        raise HTTPException(status_code=404, detail="Rule not found")

    db_exception = ComplianceException(
        rule_id=exception.rule_id,
        resource_id=exception.resource_id,
        account_id=exception.account_id,
        scope=exception.scope,
        justification=exception.justification,
        created_by=exception.created_by,
        expires_at=exception.expires_at,
    )
    db.add(db_exception)

    # Update matching findings to EXCEPTION status based on scope
    conditions = [Finding.rule_id == exception.rule_id, Finding.status == "FAIL"]
    if exception.scope == "RESOURCE" and exception.resource_id:
        conditions.append(Finding.resource_id == exception.resource_id)
    elif exception.scope == "ACCOUNT" and exception.account_id:
        conditions.append(Finding.account_id == exception.account_id)
    # For RULE scope, only filter by rule_id (already added)

    findings_result = await db.execute(
        select(Finding).where(and_(*conditions))
    )
    findings = findings_result.scalars().all()

    # Track findings with JIRA tickets to close
    findings_with_jira = []
    for finding in findings:
        finding.status = "EXCEPTION"
        finding.workflow_status = "RESOLVED"
        finding.workflow_updated_at = datetime.utcnow()
        if finding.jira_ticket_key:
            findings_with_jira.append({
                "jira_ticket_key": finding.jira_ticket_key,
                "resource_name": finding.resource_name,
            })

    # Create audit log
    audit_log = AuditLog(
        action="EXCEPTION_CREATED",
        resource_id=exception.resource_id,
        account_id=exception.account_id,
        rule_id=exception.rule_id,
        performed_by=exception.created_by,
        details={
            "exception_id": str(db_exception.id),
            "scope": exception.scope,
            "justification": exception.justification,
            "affected_findings": len(findings),
        }
    )
    db.add(audit_log)

    await db.commit()
    await db.refresh(db_exception)

    # Close JIRA tickets for affected findings
    if findings_with_jira:
        try:
            from app.services.notifications.jira import close_jira_ticket_for_exception
            import logging
            logger = logging.getLogger(__name__)
            for finding_info in findings_with_jira:
                try:
                    await close_jira_ticket_for_exception(
                        jira_ticket_key=finding_info["jira_ticket_key"],
                        resource_name=finding_info["resource_name"],
                        justification=exception.justification,
                        created_by=exception.created_by,
                    )
                except Exception as e:
                    logger.warning(
                        f"Failed to close JIRA ticket {finding_info['jira_ticket_key']} for exception: {e}"
                    )
        except ImportError:
            pass  # JIRA integration not available

    # Load rule relationship
    await db.refresh(db_exception, ["rule"])

    return ExceptionResponse.model_validate(db_exception)


@router.post("/bulk", response_model=BulkExceptionResponse, status_code=201)
async def bulk_create_exceptions(
    bulk_request: ExceptionBulkCreate,
    db: AsyncSession = Depends(get_db),
):
    """Create exceptions for multiple findings."""
    created_exceptions = []
    findings_with_jira = []

    for finding_id in bulk_request.finding_ids:
        # Get finding to get rule_id and resource_id
        finding_result = await db.execute(
            select(Finding).where(Finding.id == finding_id)
        )
        finding = finding_result.scalar_one_or_none()

        if not finding:
            continue

        db_exception = ComplianceException(
            rule_id=finding.rule_id,
            resource_id=finding.resource_id,
            account_id=finding.account_id,
            scope="RESOURCE",
            justification=bulk_request.justification,
            created_by=bulk_request.created_by,
            expires_at=bulk_request.expires_at,
        )
        db.add(db_exception)

        # Update finding status to EXCEPTION
        finding.status = "EXCEPTION"
        finding.workflow_status = "RESOLVED"
        finding.workflow_updated_at = datetime.utcnow()

        # Track for JIRA ticket close
        if finding.jira_ticket_key:
            findings_with_jira.append({
                "jira_ticket_key": finding.jira_ticket_key,
                "resource_name": finding.resource_name,
            })

        await db.flush()

        created_exceptions.append({
            "id": str(db_exception.id),
            "finding_id": str(finding_id),
        })

    await db.commit()

    # Close JIRA tickets for affected findings
    if findings_with_jira:
        try:
            from app.services.notifications.jira import close_jira_ticket_for_exception
            import logging
            logger = logging.getLogger(__name__)
            for finding_info in findings_with_jira:
                try:
                    await close_jira_ticket_for_exception(
                        jira_ticket_key=finding_info["jira_ticket_key"],
                        resource_name=finding_info["resource_name"],
                        justification=bulk_request.justification,
                        created_by=bulk_request.created_by,
                    )
                except Exception as e:
                    logger.warning(
                        f"Failed to close JIRA ticket {finding_info['jira_ticket_key']} for exception: {e}"
                    )
        except ImportError:
            pass  # JIRA integration not available

    return BulkExceptionResponse(
        created=len(created_exceptions),
        exceptions=created_exceptions,
    )


@router.get("/{exception_id}", response_model=ExceptionResponse)
async def get_exception(
    exception_id: UUID,
    db: AsyncSession = Depends(get_db),
):
    """Get exception details."""
    result = await db.execute(
        select(ComplianceException)
        .options(selectinload(ComplianceException.rule))
        .where(ComplianceException.id == exception_id)
    )
    exception = result.scalar_one_or_none()

    if not exception:
        raise HTTPException(status_code=404, detail="Exception not found")

    return ExceptionResponse.model_validate(exception)


@router.patch("/{exception_id}", response_model=ExceptionResponse)
async def update_exception(
    exception_id: UUID,
    update_data: ExceptionUpdate,
    db: AsyncSession = Depends(get_db),
):
    """Update an exception's justification or expiration."""
    result = await db.execute(
        select(ComplianceException)
        .options(selectinload(ComplianceException.rule))
        .where(ComplianceException.id == exception_id)
    )
    exception = result.scalar_one_or_none()

    if not exception:
        raise HTTPException(status_code=404, detail="Exception not found")

    if update_data.justification is not None:
        exception.justification = update_data.justification
    if update_data.expires_at is not None:
        exception.expires_at = update_data.expires_at

    await db.commit()
    await db.refresh(exception)

    return ExceptionResponse.model_validate(exception)


@router.patch("/bulk/update", response_model=BulkUpdateResponse)
async def bulk_update_exceptions(
    bulk_update: ExceptionBulkUpdate,
    db: AsyncSession = Depends(get_db),
):
    """Update multiple exceptions at once."""
    updated_ids = []

    for exception_id in bulk_update.exception_ids:
        result = await db.execute(
            select(ComplianceException).where(ComplianceException.id == exception_id)
        )
        exception = result.scalar_one_or_none()

        if exception:
            if bulk_update.justification is not None:
                exception.justification = bulk_update.justification
            if bulk_update.expires_at is not None:
                exception.expires_at = bulk_update.expires_at
            updated_ids.append(str(exception_id))

    await db.commit()

    return BulkUpdateResponse(
        updated=len(updated_ids),
        exception_ids=updated_ids,
    )


@router.delete("/{exception_id}", status_code=204)
async def delete_exception(
    exception_id: UUID,
    db: AsyncSession = Depends(get_db),
):
    """Remove an exception."""
    result = await db.execute(
        select(ComplianceException).where(ComplianceException.id == exception_id)
    )
    exception = result.scalar_one_or_none()

    if not exception:
        raise HTTPException(status_code=404, detail="Exception not found")

    # Find affected findings based on exception scope and revert their status
    conditions = [Finding.rule_id == exception.rule_id, Finding.status == "EXCEPTION"]
    if exception.scope == "RESOURCE" and exception.resource_id:
        conditions.append(Finding.resource_id == exception.resource_id)
    elif exception.scope == "ACCOUNT" and exception.account_id:
        conditions.append(Finding.account_id == exception.account_id)
    # For RULE scope, only filter by rule_id (already added)

    findings_result = await db.execute(
        select(Finding).where(and_(*conditions))
    )
    findings = findings_result.scalars().all()

    # Track findings with JIRA tickets to reopen
    findings_with_jira = []
    for finding in findings:
        finding.status = "FAIL"
        finding.workflow_status = "NEW"
        finding.workflow_updated_at = datetime.utcnow()
        if finding.jira_ticket_key:
            findings_with_jira.append({
                "jira_ticket_key": finding.jira_ticket_key,
                "resource_name": finding.resource_name,
            })

    # Create audit log before deleting
    audit_log = AuditLog(
        action="EXCEPTION_DELETED",
        resource_id=exception.resource_id,
        account_id=exception.account_id,
        rule_id=exception.rule_id,
        performed_by="system",
        details={
            "exception_id": str(exception.id),
            "scope": exception.scope,
            "justification": exception.justification,
            "affected_findings": len(findings),
        }
    )
    db.add(audit_log)

    await db.delete(exception)
    await db.commit()

    # Reopen JIRA tickets for affected findings
    if findings_with_jira:
        try:
            from app.services.notifications.jira import reopen_jira_ticket_for_exception_deleted
            import logging
            logger = logging.getLogger(__name__)
            for finding_info in findings_with_jira:
                try:
                    await reopen_jira_ticket_for_exception_deleted(
                        jira_ticket_key=finding_info["jira_ticket_key"],
                        resource_name=finding_info["resource_name"],
                    )
                except Exception as e:
                    logger.warning(
                        f"Failed to reopen JIRA ticket {finding_info['jira_ticket_key']} after exception deleted: {e}"
                    )
        except ImportError:
            pass  # JIRA integration not available
