from uuid import UUID
from typing import Optional
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from sqlalchemy.orm import selectinload

from app.database import get_db
from app.models import CompliancePack, Rule, Finding
from app.models.finding import FindingStatus
from app.schemas.rule import RuleResponse
from app.schemas.compliance_pack import (
    CompliancePackCreate,
    CompliancePackUpdate,
    CompliancePackRuleUpdate,
    CompliancePackResponse,
    CompliancePackDetailResponse,
    CompliancePackListResponse,
)

router = APIRouter()


async def get_rules_with_finding_counts(db: AsyncSession, rules):
    """Helper to add finding counts to rules (only FAIL findings for status)."""
    rules_with_counts = []
    for rule in rules:
        # Count only FAIL findings to determine if rule is failing
        count_result = await db.execute(
            select(func.count(Finding.id)).where(
                Finding.rule_id == rule.id,
                Finding.status == FindingStatus.FAIL
            )
        )
        finding_count = count_result.scalar() or 0
        rules_with_counts.append({
            **RuleResponse.model_validate(rule).model_dump(),
            "finding_count": finding_count,
        })
    return rules_with_counts


async def calculate_resource_metrics(db: AsyncSession, rules) -> dict:
    """Calculate resource-based metrics (total and failing resources)."""
    if not rules:
        return {"total_resources": 0, "failing_resources": 0, "resource_compliance_score": 100.0}

    rule_ids = [r.id for r in rules]

    # Count total resources (all findings regardless of status)
    total_result = await db.execute(
        select(func.count(Finding.id)).where(Finding.rule_id.in_(rule_ids))
    )
    total_resources = total_result.scalar() or 0

    # Count failing resources (only FAIL status)
    failing_result = await db.execute(
        select(func.count(Finding.id)).where(
            Finding.rule_id.in_(rule_ids),
            Finding.status == FindingStatus.FAIL
        )
    )
    failing_resources = failing_result.scalar() or 0

    # Calculate resource compliance score
    if total_resources == 0:
        resource_compliance_score = 100.0
    else:
        passing_resources = total_resources - failing_resources
        resource_compliance_score = (passing_resources / total_resources) * 100

    return {
        "total_resources": total_resources,
        "failing_resources": failing_resources,
        "resource_compliance_score": round(resource_compliance_score, 1),
    }


def calculate_compliance_score(rules_with_counts: list) -> dict:
    """Calculate compliance score from rules with finding counts."""
    total_rules = len(rules_with_counts)
    if total_rules == 0:
        return {"compliance_score": 100.0, "passing_rules": 0, "failing_rules": 0}

    failing_rules = sum(1 for r in rules_with_counts if r.get("finding_count", 0) > 0)
    passing_rules = total_rules - failing_rules
    compliance_score = (passing_rules / total_rules) * 100

    return {
        "compliance_score": round(compliance_score, 1),
        "passing_rules": passing_rules,
        "failing_rules": failing_rules,
    }


@router.get("", response_model=CompliancePackListResponse)
async def list_compliance_packs(
    page: int = 1,
    per_page: int = 20,
    db: AsyncSession = Depends(get_db),
):
    """List all compliance packs."""
    offset = (page - 1) * per_page

    query = (
        select(CompliancePack)
        .options(selectinload(CompliancePack.rules))
        .order_by(CompliancePack.name)
        .offset(offset)
        .limit(per_page)
    )
    result = await db.execute(query)
    packs = result.scalars().all()

    # Get total count
    count_result = await db.execute(select(func.count(CompliancePack.id)))
    total = count_result.scalar() or 0

    return CompliancePackListResponse(
        items=[
            CompliancePackResponse(
                id=p.id,
                name=p.name,
                description=p.description,
                is_enabled=p.is_enabled,
                created_at=p.created_at,
                updated_at=p.updated_at,
                rule_count=len(p.rules),
            )
            for p in packs
        ],
        total=total,
        page=page,
        per_page=per_page,
        pages=(total + per_page - 1) // per_page if total > 0 else 1,
    )


@router.post("", response_model=CompliancePackDetailResponse, status_code=201)
async def create_compliance_pack(
    pack: CompliancePackCreate,
    db: AsyncSession = Depends(get_db),
):
    """Create a new compliance pack."""
    db_pack = CompliancePack(
        name=pack.name,
        description=pack.description,
    )

    # Add rules if provided
    if pack.rule_ids:
        rules_result = await db.execute(
            select(Rule).where(Rule.id.in_(pack.rule_ids))
        )
        rules = rules_result.scalars().all()
        db_pack.rules = list(rules)

    db.add(db_pack)
    await db.commit()
    await db.refresh(db_pack)

    # Load rules relationship
    await db.refresh(db_pack, ["rules"])

    rules_with_counts = await get_rules_with_finding_counts(db, db_pack.rules)
    score_data = calculate_compliance_score(rules_with_counts)
    resource_data = await calculate_resource_metrics(db, db_pack.rules)

    return CompliancePackDetailResponse(
        id=db_pack.id,
        name=db_pack.name,
        description=db_pack.description,
        is_enabled=db_pack.is_enabled,
        created_at=db_pack.created_at,
        updated_at=db_pack.updated_at,
        rules=rules_with_counts,
        **score_data,
        **resource_data,
    )


@router.get("/{pack_id}", response_model=CompliancePackDetailResponse)
async def get_compliance_pack(
    pack_id: UUID,
    db: AsyncSession = Depends(get_db),
):
    """Get compliance pack details with its rules."""
    result = await db.execute(
        select(CompliancePack)
        .options(selectinload(CompliancePack.rules))
        .where(CompliancePack.id == pack_id)
    )
    pack = result.scalar_one_or_none()

    if not pack:
        raise HTTPException(status_code=404, detail="Compliance pack not found")

    rules_with_counts = await get_rules_with_finding_counts(db, pack.rules)
    score_data = calculate_compliance_score(rules_with_counts)
    resource_data = await calculate_resource_metrics(db, pack.rules)

    return CompliancePackDetailResponse(
        id=pack.id,
        name=pack.name,
        description=pack.description,
        is_enabled=pack.is_enabled,
        created_at=pack.created_at,
        updated_at=pack.updated_at,
        rules=rules_with_counts,
        **score_data,
        **resource_data,
    )


@router.patch("/{pack_id}", response_model=CompliancePackDetailResponse)
async def update_compliance_pack(
    pack_id: UUID,
    pack_update: CompliancePackUpdate,
    db: AsyncSession = Depends(get_db),
):
    """Update compliance pack details."""
    result = await db.execute(
        select(CompliancePack)
        .options(selectinload(CompliancePack.rules))
        .where(CompliancePack.id == pack_id)
    )
    pack = result.scalar_one_or_none()

    if not pack:
        raise HTTPException(status_code=404, detail="Compliance pack not found")

    if pack_update.name is not None:
        pack.name = pack_update.name
    if pack_update.description is not None:
        pack.description = pack_update.description
    if pack_update.is_enabled is not None:
        pack.is_enabled = pack_update.is_enabled
        # When enabling/disabling pack, also enable/disable all rules in the pack
        for rule in pack.rules:
            rule.is_enabled = pack_update.is_enabled

    await db.commit()
    await db.refresh(pack)

    rules_with_counts = await get_rules_with_finding_counts(db, pack.rules)
    score_data = calculate_compliance_score(rules_with_counts)
    resource_data = await calculate_resource_metrics(db, pack.rules)

    return CompliancePackDetailResponse(
        id=pack.id,
        name=pack.name,
        description=pack.description,
        is_enabled=pack.is_enabled,
        created_at=pack.created_at,
        updated_at=pack.updated_at,
        rules=rules_with_counts,
        **score_data,
        **resource_data,
    )


@router.put("/{pack_id}/rules", response_model=CompliancePackDetailResponse)
async def update_compliance_pack_rules(
    pack_id: UUID,
    rules_update: CompliancePackRuleUpdate,
    db: AsyncSession = Depends(get_db),
):
    """Update the rules in a compliance pack."""
    result = await db.execute(
        select(CompliancePack)
        .options(selectinload(CompliancePack.rules))
        .where(CompliancePack.id == pack_id)
    )
    pack = result.scalar_one_or_none()

    if not pack:
        raise HTTPException(status_code=404, detail="Compliance pack not found")

    # Get the new rules
    rules_result = await db.execute(
        select(Rule).where(Rule.id.in_(rules_update.rule_ids))
    )
    rules = rules_result.scalars().all()

    # Update the pack's rules
    pack.rules = list(rules)

    # If pack is enabled, enable all rules; if disabled, disable all rules
    if pack.is_enabled:
        for rule in pack.rules:
            rule.is_enabled = True

    await db.commit()
    await db.refresh(pack)
    await db.refresh(pack, ["rules"])

    rules_with_counts = await get_rules_with_finding_counts(db, pack.rules)
    score_data = calculate_compliance_score(rules_with_counts)
    resource_data = await calculate_resource_metrics(db, pack.rules)

    return CompliancePackDetailResponse(
        id=pack.id,
        name=pack.name,
        description=pack.description,
        is_enabled=pack.is_enabled,
        created_at=pack.created_at,
        updated_at=pack.updated_at,
        rules=rules_with_counts,
        **score_data,
        **resource_data,
    )


@router.post("/{pack_id}/rules/{rule_id}", response_model=CompliancePackDetailResponse)
async def add_rule_to_pack(
    pack_id: UUID,
    rule_id: UUID,
    db: AsyncSession = Depends(get_db),
):
    """Add a single rule to a compliance pack."""
    result = await db.execute(
        select(CompliancePack)
        .options(selectinload(CompliancePack.rules))
        .where(CompliancePack.id == pack_id)
    )
    pack = result.scalar_one_or_none()

    if not pack:
        raise HTTPException(status_code=404, detail="Compliance pack not found")

    rule_result = await db.execute(select(Rule).where(Rule.id == rule_id))
    rule = rule_result.scalar_one_or_none()

    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")

    if rule not in pack.rules:
        pack.rules.append(rule)
        if pack.is_enabled:
            rule.is_enabled = True
        await db.commit()
        await db.refresh(pack)

    rules_with_counts = await get_rules_with_finding_counts(db, pack.rules)
    score_data = calculate_compliance_score(rules_with_counts)
    resource_data = await calculate_resource_metrics(db, pack.rules)

    return CompliancePackDetailResponse(
        id=pack.id,
        name=pack.name,
        description=pack.description,
        is_enabled=pack.is_enabled,
        created_at=pack.created_at,
        updated_at=pack.updated_at,
        rules=rules_with_counts,
        **score_data,
        **resource_data,
    )


@router.delete("/{pack_id}/rules/{rule_id}", response_model=CompliancePackDetailResponse)
async def remove_rule_from_pack(
    pack_id: UUID,
    rule_id: UUID,
    db: AsyncSession = Depends(get_db),
):
    """Remove a single rule from a compliance pack."""
    result = await db.execute(
        select(CompliancePack)
        .options(selectinload(CompliancePack.rules))
        .where(CompliancePack.id == pack_id)
    )
    pack = result.scalar_one_or_none()

    if not pack:
        raise HTTPException(status_code=404, detail="Compliance pack not found")

    rule_result = await db.execute(select(Rule).where(Rule.id == rule_id))
    rule = rule_result.scalar_one_or_none()

    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")

    if rule in pack.rules:
        pack.rules.remove(rule)
        await db.commit()
        await db.refresh(pack)

    rules_with_counts = await get_rules_with_finding_counts(db, pack.rules)
    score_data = calculate_compliance_score(rules_with_counts)
    resource_data = await calculate_resource_metrics(db, pack.rules)

    return CompliancePackDetailResponse(
        id=pack.id,
        name=pack.name,
        description=pack.description,
        is_enabled=pack.is_enabled,
        created_at=pack.created_at,
        updated_at=pack.updated_at,
        rules=rules_with_counts,
        **score_data,
        **resource_data,
    )


@router.delete("/{pack_id}", status_code=204)
async def delete_compliance_pack(
    pack_id: UUID,
    db: AsyncSession = Depends(get_db),
):
    """Delete a compliance pack."""
    result = await db.execute(
        select(CompliancePack).where(CompliancePack.id == pack_id)
    )
    pack = result.scalar_one_or_none()

    if not pack:
        raise HTTPException(status_code=404, detail="Compliance pack not found")

    await db.delete(pack)
    await db.commit()
