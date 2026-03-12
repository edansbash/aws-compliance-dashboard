"""
Redis-based job queue for scan and remediation jobs.

This module provides functions to enqueue jobs to Redis queues
for processing by the worker process.
"""
import json
import uuid
from datetime import datetime
from typing import Optional, List

from app.services.cache import get_redis


# Queue names
SCAN_QUEUE = "queue:scan_jobs"
REMEDIATION_QUEUE = "queue:remediation_jobs"

# Job status cache prefix
JOB_STATUS_PREFIX = "job:status:"


async def enqueue_scan_job(
    scan_id: str,
    account_ids: List[str],
    regions: List[str],
    rule_ids: Optional[List[str]] = None
) -> str:
    """
    Enqueue a scan job to the Redis queue.

    Args:
        scan_id: UUID of the Scan record in PostgreSQL
        account_ids: List of account UUIDs to scan
        regions: List of AWS regions to scan
        rule_ids: Optional list of rule UUIDs (all enabled if None)

    Returns:
        job_id: UUID of the queued job
    """
    redis = await get_redis()

    job_id = str(uuid.uuid4())
    job = {
        "job_id": job_id,
        "job_type": "scan",
        "scan_id": scan_id,
        "account_ids": account_ids,
        "regions": regions,
        "rule_ids": rule_ids,
        "created_at": datetime.utcnow().isoformat()
    }

    # Push to queue (LPUSH for FIFO with BRPOP)
    await redis.lpush(SCAN_QUEUE, json.dumps(job))

    # Set initial job status in cache
    await redis.set(
        f"{JOB_STATUS_PREFIX}{scan_id}",
        json.dumps({"status": "QUEUED", "job_id": job_id}),
        ex=86400  # 24 hour TTL
    )

    return job_id


async def enqueue_remediation_job(
    remediation_job_id: str,
    finding_ids: List[str],
    confirmed_by: str
) -> str:
    """
    Enqueue a remediation job to the Redis queue.

    Args:
        remediation_job_id: UUID of the RemediationJob record in PostgreSQL
        finding_ids: List of finding UUIDs to remediate
        confirmed_by: User who confirmed the remediation

    Returns:
        job_id: UUID of the queued job
    """
    redis = await get_redis()

    job_id = str(uuid.uuid4())
    job = {
        "job_id": job_id,
        "job_type": "remediation",
        "remediation_job_id": remediation_job_id,
        "finding_ids": finding_ids,
        "confirmed_by": confirmed_by,
        "created_at": datetime.utcnow().isoformat()
    }

    # Push to queue
    await redis.lpush(REMEDIATION_QUEUE, json.dumps(job))

    # Set initial job status in cache
    await redis.set(
        f"{JOB_STATUS_PREFIX}{remediation_job_id}",
        json.dumps({"status": "QUEUED", "job_id": job_id}),
        ex=86400  # 24 hour TTL
    )

    return job_id


async def get_job_status(entity_id: str) -> Optional[dict]:
    """
    Get cached job status for a scan or remediation job.

    Args:
        entity_id: The scan_id or remediation_job_id

    Returns:
        Dict with status info or None if not found
    """
    redis = await get_redis()
    data = await redis.get(f"{JOB_STATUS_PREFIX}{entity_id}")
    if data:
        return json.loads(data)
    return None


async def update_job_status(
    entity_id: str,
    status: str,
    job_id: Optional[str] = None,
    progress: Optional[dict] = None,
    message: Optional[str] = None
):
    """
    Update cached job status.

    Args:
        entity_id: The scan_id or remediation_job_id
        status: New status value
        job_id: Optional job ID (preserved if not provided)
        progress: Optional progress dict
        message: Optional status message
    """
    redis = await get_redis()

    # Get existing data to preserve job_id if not provided
    existing = await get_job_status(entity_id)
    if existing and not job_id:
        job_id = existing.get("job_id")

    data = {
        "status": status,
        "job_id": job_id,
        "progress": progress,
        "message": message,
        "updated_at": datetime.utcnow().isoformat()
    }

    await redis.set(
        f"{JOB_STATUS_PREFIX}{entity_id}",
        json.dumps(data),
        ex=86400  # 24 hour TTL
    )


async def get_queue_length(queue: str) -> int:
    """
    Get the number of jobs waiting in a queue.

    Args:
        queue: Queue name (SCAN_QUEUE or REMEDIATION_QUEUE)

    Returns:
        Number of jobs in queue
    """
    redis = await get_redis()
    return await redis.llen(queue)


async def get_queue_stats() -> dict:
    """
    Get statistics for all queues.

    Returns:
        Dict with queue lengths
    """
    return {
        "scan_jobs": await get_queue_length(SCAN_QUEUE),
        "remediation_jobs": await get_queue_length(REMEDIATION_QUEUE)
    }
