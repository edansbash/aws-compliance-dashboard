"""
Redis pub/sub wrapper for real-time job status and log updates.

This module provides functions to publish job status updates and logs
via Redis pub/sub channels, and a subscriber class for consuming updates.
"""
import json
import asyncio
from datetime import datetime
from typing import Optional, AsyncIterator
from enum import Enum

from app.services.cache import get_redis
from app.services.job_queue import JOB_STATUS_PREFIX


# Pub/sub channels
CHANNEL_JOB_STATUS = "channel:job_status"
CHANNEL_JOB_LOGS = "channel:job_logs"


class LogLevel(str, Enum):
    """Log levels for job execution logs."""
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARN = "WARN"
    ERROR = "ERROR"
    SUCCESS = "SUCCESS"


async def publish_job_status(
    entity_id: str,
    status: str,
    job_id: Optional[str] = None,
    message: Optional[str] = None,
    progress: Optional[dict] = None
):
    """
    Publish job status update to subscribers.

    Args:
        entity_id: The scan_id or remediation_job_id
        status: New status (QUEUED, RUNNING, COMPLETED, FAILED, CANCELLED)
        job_id: Optional queue job ID
        message: Optional status message
        progress: Optional progress dict (e.g., {"current": 5, "total": 10})
    """
    redis = await get_redis()

    payload = {
        "entity_id": entity_id,
        "job_id": job_id,
        "status": status,
        "message": message,
        "progress": progress,
        "timestamp": datetime.utcnow().isoformat()
    }

    # Publish to channel
    await redis.publish(CHANNEL_JOB_STATUS, json.dumps(payload))

    # Also update cached status for polling fallback
    cache_data = {
        "status": status,
        "job_id": job_id,
        "progress": progress,
        "message": message,
        "updated_at": datetime.utcnow().isoformat()
    }
    await redis.set(
        f"{JOB_STATUS_PREFIX}{entity_id}",
        json.dumps(cache_data),
        ex=86400  # 24 hour TTL
    )


async def publish_job_log(
    entity_id: str,
    level: LogLevel,
    message: str,
    resource_id: Optional[str] = None,
    details: Optional[dict] = None
):
    """
    Publish job log entry to subscribers.

    Args:
        entity_id: The scan_id or remediation_job_id
        level: Log level (DEBUG, INFO, WARN, ERROR, SUCCESS)
        message: Log message
        resource_id: Optional AWS resource ID being processed
        details: Optional additional details dict
    """
    redis = await get_redis()

    payload = {
        "entity_id": entity_id,
        "level": level.value if isinstance(level, LogLevel) else level,
        "message": message,
        "resource_id": resource_id,
        "details": details,
        "timestamp": datetime.utcnow().isoformat()
    }

    await redis.publish(CHANNEL_JOB_LOGS, json.dumps(payload))


class JobStatusSubscriber:
    """
    Async context manager for subscribing to job status updates.

    Usage:
        async with JobStatusSubscriber(entity_id) as subscriber:
            async for event in subscriber:
                print(event)
    """

    def __init__(self, entity_id: str, timeout: float = 1.0):
        """
        Initialize subscriber.

        Args:
            entity_id: The scan_id or remediation_job_id to filter for
            timeout: Timeout in seconds for waiting for messages
        """
        self.entity_id = entity_id
        self.timeout = timeout
        self.pubsub = None
        self._redis = None

    async def __aenter__(self):
        self._redis = await get_redis()
        self.pubsub = self._redis.pubsub()
        await self.pubsub.subscribe(CHANNEL_JOB_STATUS, CHANNEL_JOB_LOGS)
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.pubsub:
            await self.pubsub.unsubscribe()
            await self.pubsub.close()

    def __aiter__(self):
        return self

    async def __anext__(self) -> dict:
        """
        Get next message for this entity.

        Returns:
            Dict with message data

        Raises:
            StopAsyncIteration: When subscription ends
        """
        while True:
            try:
                message = await self.pubsub.get_message(
                    ignore_subscribe_messages=True,
                    timeout=self.timeout
                )

                if message is None:
                    # Timeout, yield control and continue
                    await asyncio.sleep(0.1)
                    continue

                if message["type"] == "message":
                    data = json.loads(message["data"])
                    # Filter for our entity
                    if data.get("entity_id") == self.entity_id:
                        return data

            except Exception:
                raise StopAsyncIteration


async def subscribe_to_job(
    entity_id: str,
    timeout: float = 30.0
) -> AsyncIterator[dict]:
    """
    Subscribe to job updates for a specific entity.

    This is a simpler alternative to JobStatusSubscriber for one-off subscriptions.

    Args:
        entity_id: The scan_id or remediation_job_id
        timeout: Total timeout in seconds

    Yields:
        Dict with status or log events
    """
    start_time = datetime.utcnow()

    async with JobStatusSubscriber(entity_id) as subscriber:
        async for event in subscriber:
            yield event

            # Check for completion
            if event.get("status") in ("COMPLETED", "FAILED", "CANCELLED"):
                return

            # Check timeout
            elapsed = (datetime.utcnow() - start_time).total_seconds()
            if elapsed > timeout:
                return
