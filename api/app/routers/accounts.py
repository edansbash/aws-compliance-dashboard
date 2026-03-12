from uuid import UUID
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, delete
import boto3
from botocore.exceptions import ClientError

from app.database import get_db
from app.models import AWSAccount, Finding
from app.schemas.account import (
    AccountCreate,
    AccountUpdate,
    AccountResponse,
    AccountListResponse,
    AccountTestResponse,
)
from app.services.cache import (
    get_cached, set_cached, invalidate_pattern,
    make_cache_key, CACHE_ACCOUNTS, CACHE_FINDINGS, CACHE_SUMMARY, CACHE_RULES
)

router = APIRouter()


@router.get("", response_model=AccountListResponse)
async def list_accounts(
    page: int = 1,
    per_page: int = 20,
    db: AsyncSession = Depends(get_db),
):
    """List all AWS accounts."""
    # Check cache first
    cache_key = make_cache_key(CACHE_ACCOUNTS, "list", page=page, per_page=per_page)
    cached = await get_cached(cache_key)
    if cached:
        return AccountListResponse(**cached)

    offset = (page - 1) * per_page
    query = select(AWSAccount).offset(offset).limit(per_page)
    result = await db.execute(query)
    accounts = result.scalars().all()

    # Get total count
    count_query = select(AWSAccount)
    count_result = await db.execute(count_query)
    total = len(count_result.scalars().all())

    response = AccountListResponse(
        items=[AccountResponse.model_validate(a) for a in accounts],
        total=total,
        page=page,
        per_page=per_page,
        pages=(total + per_page - 1) // per_page,
    )

    # Cache the response
    await set_cached(cache_key, response.model_dump())

    return response


@router.post("", response_model=AccountResponse, status_code=201)
async def create_account(
    account: AccountCreate,
    db: AsyncSession = Depends(get_db),
):
    """Add a new AWS account."""
    # Check if account already exists
    existing = await db.execute(
        select(AWSAccount).where(AWSAccount.account_id == account.account_id)
    )
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=400, detail="Account ID already exists")

    db_account = AWSAccount(**account.model_dump())
    db.add(db_account)
    await db.commit()
    await db.refresh(db_account)

    # Invalidate accounts cache
    await invalidate_pattern(f"{CACHE_ACCOUNTS}:*")

    return AccountResponse.model_validate(db_account)


@router.get("/{account_uuid}", response_model=AccountResponse)
async def get_account(
    account_uuid: UUID,
    db: AsyncSession = Depends(get_db),
):
    """Get account details."""
    result = await db.execute(
        select(AWSAccount).where(AWSAccount.id == account_uuid)
    )
    account = result.scalar_one_or_none()

    if not account:
        raise HTTPException(status_code=404, detail="Account not found")

    return AccountResponse.model_validate(account)


@router.put("/{account_uuid}", response_model=AccountResponse)
async def update_account(
    account_uuid: UUID,
    account_update: AccountUpdate,
    db: AsyncSession = Depends(get_db),
):
    """Update an account."""
    result = await db.execute(
        select(AWSAccount).where(AWSAccount.id == account_uuid)
    )
    account = result.scalar_one_or_none()

    if not account:
        raise HTTPException(status_code=404, detail="Account not found")

    update_data = account_update.model_dump(exclude_unset=True)
    for field, value in update_data.items():
        setattr(account, field, value)

    await db.commit()
    await db.refresh(account)

    # Invalidate accounts cache
    await invalidate_pattern(f"{CACHE_ACCOUNTS}:*")

    return AccountResponse.model_validate(account)


@router.delete("/{account_uuid}", status_code=204)
async def delete_account(
    account_uuid: UUID,
    db: AsyncSession = Depends(get_db),
):
    """Remove an account and all associated findings."""
    result = await db.execute(
        select(AWSAccount).where(AWSAccount.id == account_uuid)
    )
    account = result.scalar_one_or_none()

    if not account:
        raise HTTPException(status_code=404, detail="Account not found")

    # Delete all findings associated with this AWS account ID
    await db.execute(
        delete(Finding).where(Finding.account_id == account.account_id)
    )

    await db.delete(account)
    await db.commit()

    # Invalidate all caches
    await invalidate_pattern(f"{CACHE_ACCOUNTS}:*")
    await invalidate_pattern(f"{CACHE_FINDINGS}:*")
    await invalidate_pattern(f"{CACHE_SUMMARY}:*")
    await invalidate_pattern(f"{CACHE_RULES}:*")


@router.post("/{account_uuid}/test", response_model=AccountTestResponse)
async def test_account(
    account_uuid: UUID,
    db: AsyncSession = Depends(get_db),
):
    """Test account connectivity."""
    result = await db.execute(
        select(AWSAccount).where(AWSAccount.id == account_uuid)
    )
    account = result.scalar_one_or_none()

    if not account:
        raise HTTPException(status_code=404, detail="Account not found")

    try:
        if account.role_arn:
            # Assume role for cross-account access
            sts = boto3.client("sts")
            assume_role_kwargs = {
                "RoleArn": account.role_arn,
                "RoleSessionName": "compliance-dashboard-test",
            }
            if account.external_id:
                assume_role_kwargs["ExternalId"] = account.external_id

            response = sts.assume_role(**assume_role_kwargs)
            credentials = response["Credentials"]

            # Test with assumed credentials
            test_sts = boto3.client(
                "sts",
                aws_access_key_id=credentials["AccessKeyId"],
                aws_secret_access_key=credentials["SecretAccessKey"],
                aws_session_token=credentials["SessionToken"],
            )
            identity = test_sts.get_caller_identity()
        else:
            # Test with default credentials
            sts = boto3.client("sts")
            identity = sts.get_caller_identity()

        return AccountTestResponse(
            success=True,
            message=f"Successfully connected as {identity['Arn']}",
            account_id=identity["Account"],
        )

    except ClientError as e:
        return AccountTestResponse(
            success=False,
            message=str(e),
            account_id=None,
        )
