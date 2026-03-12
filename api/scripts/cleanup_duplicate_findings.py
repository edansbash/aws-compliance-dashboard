"""Script to clean up duplicate findings in the database.

Keeps only the most recent finding for each unique combination of:
- rule_id
- resource_id
- account_id
- region
"""
import asyncio
from sqlalchemy import select, func, and_, delete
from sqlalchemy.orm import aliased

from app.database import AsyncSessionLocal
from app.models import Finding


async def cleanup_duplicates():
    """Remove duplicate findings, keeping only the most recent one."""
    async with AsyncSessionLocal() as db:
        # Find all duplicate groups (rule_id, resource_id, account_id, region with count > 1)
        subquery = (
            select(
                Finding.rule_id,
                Finding.resource_id,
                Finding.account_id,
                Finding.region,
                func.count(Finding.id).label("cnt"),
                func.max(Finding.created_at).label("max_created_at")
            )
            .group_by(
                Finding.rule_id,
                Finding.resource_id,
                Finding.account_id,
                Finding.region
            )
            .having(func.count(Finding.id) > 1)
        )

        result = await db.execute(subquery)
        duplicates = result.all()

        print(f"Found {len(duplicates)} groups with duplicate findings")

        total_deleted = 0

        for dup in duplicates:
            rule_id, resource_id, account_id, region, count, max_created_at = dup

            # Get the ID of the most recent finding to keep
            keep_result = await db.execute(
                select(Finding.id)
                .where(
                    and_(
                        Finding.rule_id == rule_id,
                        Finding.resource_id == resource_id,
                        Finding.account_id == account_id,
                        Finding.region == region,
                        Finding.created_at == max_created_at
                    )
                )
                .limit(1)
            )
            keep_id = keep_result.scalar_one_or_none()

            if keep_id:
                # Delete all other findings in this group
                delete_result = await db.execute(
                    delete(Finding).where(
                        and_(
                            Finding.rule_id == rule_id,
                            Finding.resource_id == resource_id,
                            Finding.account_id == account_id,
                            Finding.region == region,
                            Finding.id != keep_id
                        )
                    )
                )
                deleted = delete_result.rowcount
                total_deleted += deleted
                print(f"Deleted {deleted} duplicates for {resource_id}")

        await db.commit()
        print(f"\nTotal deleted: {total_deleted} duplicate findings")


if __name__ == "__main__":
    asyncio.run(cleanup_duplicates())
