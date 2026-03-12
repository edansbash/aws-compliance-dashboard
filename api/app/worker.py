"""
Worker process for executing scan and remediation jobs from Redis queues.

This worker pulls jobs from Redis queues and executes them independently
from the API process, keeping the API responsive.

Usage:
    python -m app.worker
"""
import os
import sys
import json
import asyncio
import signal
import logging
from datetime import datetime
from typing import Optional, Callable, Awaitable

import redis.asyncio as redis

from app.config import settings
from app.database import AsyncSessionLocal
from app.services.job_queue import SCAN_QUEUE, REMEDIATION_QUEUE
from app.services.job_publisher import (
    publish_job_status,
    publish_job_log,
    LogLevel,
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger("worker")


class JobWorker:
    """
    Worker that pulls jobs from Redis queues and executes them.

    Supports graceful shutdown on SIGTERM/SIGINT.
    """

    def __init__(self, redis_url: str):
        self.redis_url = redis_url
        self.redis: Optional[redis.Redis] = None
        self.running = True
        self.current_job: Optional[dict] = None

    async def start(self):
        """Initialize connections and start processing."""
        logger.info("Starting worker process...")

        # Connect to Redis
        self.redis = redis.from_url(
            self.redis_url,
            encoding="utf-8",
            decode_responses=True
        )

        # Test connection
        try:
            await self.redis.ping()
            logger.info(f"Connected to Redis at {self.redis_url}")
        except Exception as e:
            logger.error(f"Failed to connect to Redis: {e}")
            raise

        # Setup signal handlers for graceful shutdown
        loop = asyncio.get_event_loop()
        for sig in (signal.SIGTERM, signal.SIGINT):
            loop.add_signal_handler(sig, self._handle_shutdown)

        # Start processing jobs
        await self.run()

    def _handle_shutdown(self):
        """Handle shutdown signal."""
        logger.info("Shutdown signal received, finishing current job...")
        self.running = False

    async def run(self):
        """Main worker loop - pulls from both queues."""
        logger.info(f"Listening on queues: {SCAN_QUEUE}, {REMEDIATION_QUEUE}")

        while self.running:
            try:
                # BRPOP blocks until a job is available
                # Checks scan_jobs first, then remediation_jobs
                result = await self.redis.brpop(
                    [SCAN_QUEUE, REMEDIATION_QUEUE],
                    timeout=5
                )

                if result is None:
                    # Timeout, no job available
                    continue

                queue_name, job_data = result
                job = json.loads(job_data)
                self.current_job = job

                job_id = job.get("job_id", "unknown")
                job_type = job.get("job_type", "unknown")
                logger.info(f"Processing {job_type} job {job_id} from {queue_name}")

                if job_type == "scan":
                    await self.process_scan_job(job)
                elif job_type == "remediation":
                    await self.process_remediation_job(job)
                else:
                    logger.error(f"Unknown job type: {job_type}")

                self.current_job = None

            except json.JSONDecodeError as e:
                logger.error(f"Invalid job data: {e}")
                self.current_job = None
            except Exception as e:
                logger.exception(f"Error processing job: {e}")
                if self.current_job:
                    await self._handle_job_failure(self.current_job, e)
                self.current_job = None

        logger.info("Worker stopped")
        await self._cleanup()

    async def process_scan_job(self, job: dict):
        """Execute a scan job."""
        scan_id = job["scan_id"]
        job_id = job["job_id"]

        logger.info(f"Starting scan {scan_id}")

        # Publish status update
        await publish_job_status(
            entity_id=scan_id,
            status="RUNNING",
            job_id=job_id,
            message="Scan started by worker"
        )

        try:
            # Import here to avoid circular imports at module load
            from app.services.scanner import execute_scan

            # Create progress callback that publishes to Redis
            async def progress_callback(message: str, progress: Optional[dict] = None):
                await publish_job_log(
                    entity_id=scan_id,
                    level=LogLevel.INFO,
                    message=message,
                    details=progress
                )

            # Execute scan with progress callback
            await execute_scan(
                scan_id=scan_id,
                progress_callback=progress_callback
            )

            await publish_job_status(
                entity_id=scan_id,
                status="COMPLETED",
                job_id=job_id,
                message="Scan completed successfully"
            )
            logger.info(f"Scan {scan_id} completed successfully")

        except Exception as e:
            logger.exception(f"Scan {scan_id} failed: {e}")
            await publish_job_status(
                entity_id=scan_id,
                status="FAILED",
                job_id=job_id,
                message=str(e)
            )
            raise

    async def process_remediation_job(self, job: dict):
        """Execute a remediation job."""
        remediation_job_id = job["remediation_job_id"]
        job_id = job["job_id"]
        finding_ids = job.get("finding_ids", [])

        logger.info(f"Starting remediation {remediation_job_id} for {len(finding_ids)} findings")

        await publish_job_status(
            entity_id=remediation_job_id,
            status="RUNNING",
            job_id=job_id,
            message="Remediation started by worker"
        )

        try:
            # Import here to avoid circular imports
            from app.routers.remediation import execute_remediation

            # Execute remediation
            # Note: execute_remediation handles its own logging to DB
            # We also publish to Redis for real-time streaming
            await execute_remediation(remediation_job_id)

            await publish_job_status(
                entity_id=remediation_job_id,
                status="COMPLETED",
                job_id=job_id,
                message="Remediation completed"
            )
            logger.info(f"Remediation {remediation_job_id} completed")

        except Exception as e:
            logger.exception(f"Remediation {remediation_job_id} failed: {e}")
            await publish_job_status(
                entity_id=remediation_job_id,
                status="FAILED",
                job_id=job_id,
                message=str(e)
            )
            raise

    async def _handle_job_failure(self, job: dict, error: Exception):
        """Handle job failure - update status."""
        entity_id = job.get("scan_id") or job.get("remediation_job_id")
        job_id = job.get("job_id")

        if entity_id:
            await publish_job_status(
                entity_id=entity_id,
                status="FAILED",
                job_id=job_id,
                message=f"Job failed: {str(error)}"
            )

        logger.error(f"Job {job_id} failed: {error}")

    async def _cleanup(self):
        """Cleanup resources on shutdown."""
        if self.redis:
            await self.redis.aclose()
            logger.info("Redis connection closed")


async def main():
    """Entry point for worker process."""
    redis_url = settings.redis_url
    logger.info(f"Worker starting with Redis URL: {redis_url}")

    worker = JobWorker(redis_url)

    try:
        await worker.start()
    except KeyboardInterrupt:
        logger.info("Worker interrupted")
    except Exception as e:
        logger.exception(f"Worker failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
