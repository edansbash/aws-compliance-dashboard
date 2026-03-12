from datetime import datetime
from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import text
import boto3
from botocore.exceptions import ClientError, NoCredentialsError

from app.database import get_db
from app.config import settings
from app.schemas.health import HealthResponse, HealthChecks

router = APIRouter()


@router.get("/health", response_model=HealthResponse)
async def health_check(db: AsyncSession = Depends(get_db)):
    """Check health of all system components."""
    checks = HealthChecks(database="ok", aws_credentials="ok")
    status = "healthy"

    # Check database connection
    try:
        await db.execute(text("SELECT 1"))
    except Exception:
        checks.database = "error"
        status = "unhealthy"

    # Check AWS credentials
    try:
        sts = boto3.client("sts")
        sts.get_caller_identity()
    except (ClientError, NoCredentialsError):
        checks.aws_credentials = "error"
        # Don't mark as unhealthy - AWS creds might be configured per-account

    return HealthResponse(
        status=status,
        version=settings.app_version,
        checks=checks,
        timestamp=datetime.utcnow(),
    )


@router.get("/search")
async def global_search(
    q: str,
    type: str = "findings",
    page: int = 1,
    per_page: int = 20,
    db: AsyncSession = Depends(get_db),
):
    """Global search across findings."""
    from sqlalchemy import select, or_
    from app.models import Finding

    # Search findings by resource name or resource ID
    offset = (page - 1) * per_page

    query = (
        select(Finding)
        .where(
            or_(
                Finding.resource_name.ilike(f"%{q}%"),
                Finding.resource_id.ilike(f"%{q}%"),
                Finding.account_id.ilike(f"%{q}%"),
            )
        )
        .offset(offset)
        .limit(per_page)
    )

    result = await db.execute(query)
    findings = result.scalars().all()

    # Get total count
    count_query = select(Finding).where(
        or_(
            Finding.resource_name.ilike(f"%{q}%"),
            Finding.resource_id.ilike(f"%{q}%"),
            Finding.account_id.ilike(f"%{q}%"),
        )
    )
    count_result = await db.execute(count_query)
    total = len(count_result.scalars().all())

    return {
        "items": [
            {
                "type": "finding",
                "id": str(f.id),
                "resource_name": f.resource_name,
                "resource_id": f.resource_id,
                "account_id": f.account_id,
                "region": f.region,
                "status": f.status.value,
            }
            for f in findings
        ],
        "total": total,
        "page": page,
        "per_page": per_page,
    }
