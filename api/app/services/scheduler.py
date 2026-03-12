"""
APScheduler-based scheduler service for recurring compliance scans.

This module manages scheduled scans using APScheduler's AsyncIOScheduler.
Schedules are stored in PostgreSQL and loaded at startup.
"""
import logging
from datetime import datetime
from typing import Optional, List
from uuid import UUID
import pytz

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger
from apscheduler.triggers.interval import IntervalTrigger
from apscheduler.jobstores.base import JobLookupError
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import AsyncSessionLocal
from app.models.scheduled_scan import ScheduledScan
from app.models.scan import Scan
from app.models.account import AWSAccount
from app.services.job_queue import enqueue_scan_job
from app.config import settings

logger = logging.getLogger(__name__)

# Global scheduler instance
_scheduler: Optional[AsyncIOScheduler] = None


def get_scheduler() -> AsyncIOScheduler:
    """Get the global scheduler instance."""
    global _scheduler
    if _scheduler is None:
        _scheduler = AsyncIOScheduler(
            timezone=pytz.UTC,
            job_defaults={
                "coalesce": True,  # Combine multiple missed runs into one
                "max_instances": 1,  # Only one instance of each job at a time
                "misfire_grace_time": 300,  # 5 minutes grace period
            }
        )
    return _scheduler


async def start_scheduler():
    """Start the scheduler and load all enabled schedules from database."""
    scheduler = get_scheduler()

    if scheduler.running:
        logger.warning("Scheduler is already running")
        return

    # Load all enabled schedules from database
    async with AsyncSessionLocal() as session:
        result = await session.execute(
            select(ScheduledScan).where(ScheduledScan.enabled == True)
        )
        schedules = result.scalars().all()

        for schedule in schedules:
            try:
                _add_job_for_schedule(scheduler, schedule)
                logger.info(f"Loaded schedule: {schedule.name} (ID: {schedule.id})")
            except Exception as e:
                logger.error(f"Failed to load schedule {schedule.id}: {e}")

    # Start scheduler first - jobs get next_run_time after start
    scheduler.start()
    logger.info(f"Scheduler started with {len(schedules)} schedule(s)")

    # Now update next_run_at for all schedules
    async with AsyncSessionLocal() as session:
        result = await session.execute(
            select(ScheduledScan).where(ScheduledScan.enabled == True)
        )
        schedules = result.scalars().all()

        for schedule in schedules:
            job = scheduler.get_job(f"scheduled_scan_{schedule.id}")
            if job and job.next_run_time:
                schedule.next_run_at = job.next_run_time.replace(tzinfo=None)
                logger.info(f"Set next_run_at for {schedule.name}: {schedule.next_run_at}")

        await session.commit()


async def shutdown_scheduler():
    """Gracefully shutdown the scheduler."""
    scheduler = get_scheduler()
    if scheduler.running:
        scheduler.shutdown(wait=True)
        logger.info("Scheduler shutdown complete")


def _add_job_for_schedule(scheduler: AsyncIOScheduler, schedule: ScheduledScan) -> None:
    """Add an APScheduler job for a scheduled scan."""
    job_id = f"scheduled_scan_{schedule.id}"

    # Create trigger based on schedule type
    if schedule.schedule_type == "cron":
        trigger = _parse_cron_expression(
            schedule.schedule_expression,
            schedule.timezone
        )
    else:  # interval
        trigger = _parse_interval_expression(schedule.schedule_expression)

    # Add job to scheduler
    scheduler.add_job(
        _execute_scheduled_scan,
        trigger=trigger,
        id=job_id,
        args=[str(schedule.id)],
        name=schedule.name,
        replace_existing=True,
    )


def _get_next_run_time(scheduler: AsyncIOScheduler, schedule_id: UUID) -> Optional[datetime]:
    """Get the next run time for a schedule from the running scheduler."""
    job = scheduler.get_job(f"scheduled_scan_{schedule_id}")
    if job and job.next_run_time:
        return job.next_run_time.replace(tzinfo=None)
    return None


def _parse_cron_expression(expression: str, timezone: str = "UTC") -> CronTrigger:
    """
    Parse a cron expression into an APScheduler CronTrigger.

    Supports standard 5-field cron format: minute hour day month day_of_week
    Examples:
        - "0 2 * * *"     -> Daily at 2:00 AM
        - "0 */6 * * *"   -> Every 6 hours
        - "0 9 * * 1-5"   -> Weekdays at 9:00 AM
        - "30 4 1 * *"    -> Monthly on 1st at 4:30 AM
    """
    parts = expression.split()

    if len(parts) == 5:
        minute, hour, day, month, day_of_week = parts
        return CronTrigger(
            minute=minute,
            hour=hour,
            day=day,
            month=month,
            day_of_week=day_of_week,
            timezone=pytz.timezone(timezone),
        )
    elif len(parts) == 6:
        # Extended format with seconds
        second, minute, hour, day, month, day_of_week = parts
        return CronTrigger(
            second=second,
            minute=minute,
            hour=hour,
            day=day,
            month=month,
            day_of_week=day_of_week,
            timezone=pytz.timezone(timezone),
        )
    else:
        raise ValueError(
            f"Invalid cron expression: {expression}. "
            "Expected 5 or 6 space-separated fields."
        )


def _parse_interval_expression(expression: str) -> IntervalTrigger:
    """
    Parse an interval expression into an APScheduler IntervalTrigger.

    Supports:
        - Minutes as integer string: "360" -> every 360 minutes (6 hours)
        - Hours with suffix: "6h" -> every 6 hours
        - Days with suffix: "1d" -> every day
    """
    expression = expression.strip().lower()

    if expression.endswith("h"):
        hours = int(expression[:-1])
        return IntervalTrigger(hours=hours)
    elif expression.endswith("d"):
        days = int(expression[:-1])
        return IntervalTrigger(days=days)
    elif expression.endswith("m"):
        minutes = int(expression[:-1])
        return IntervalTrigger(minutes=minutes)
    else:
        # Default: interpret as minutes
        minutes = int(expression)
        return IntervalTrigger(minutes=minutes)


async def _execute_scheduled_scan(schedule_id: str):
    """
    Execute a scheduled scan by creating a Scan record and enqueueing the job.

    This function is called by APScheduler when a scheduled scan is triggered.
    """
    logger.info(f"Executing scheduled scan: {schedule_id}")

    async with AsyncSessionLocal() as session:
        # Get the schedule
        result = await session.execute(
            select(ScheduledScan).where(ScheduledScan.id == schedule_id)
        )
        schedule = result.scalar_one_or_none()

        if not schedule:
            logger.error(f"Schedule not found: {schedule_id}")
            return

        if not schedule.enabled:
            logger.info(f"Schedule is disabled, skipping: {schedule_id}")
            return

        # Get account IDs - if empty, use all active accounts
        account_ids = schedule.account_ids
        if not account_ids:
            result = await session.execute(
                select(AWSAccount.id).where(AWSAccount.is_active == True)
            )
            account_ids = [str(row[0]) for row in result.fetchall()]

        # Get regions - if empty, use default regions
        regions = schedule.regions or settings.default_scan_regions

        # Create scan record
        scan = Scan(
            status="QUEUED",
            regions=regions,
            account_ids=account_ids,
            rule_ids=schedule.rule_ids,
            resource_types=[],  # Will be populated by scanner
        )
        session.add(scan)
        await session.flush()

        # Update schedule with last run info
        schedule.last_run_at = datetime.utcnow()
        schedule.last_scan_id = scan.id

        # Update next_run_at from APScheduler
        scheduler = get_scheduler()
        job = scheduler.get_job(f"scheduled_scan_{schedule_id}")
        if job and job.next_run_time:
            schedule.next_run_at = job.next_run_time.replace(tzinfo=None)

        await session.commit()

        # Enqueue scan job to Redis
        await enqueue_scan_job(
            scan_id=str(scan.id),
            account_ids=account_ids,
            regions=regions,
            rule_ids=schedule.rule_ids,
        )

        logger.info(
            f"Scheduled scan triggered: schedule={schedule_id}, "
            f"scan={scan.id}, accounts={len(account_ids)}, regions={len(regions)}"
        )


async def add_schedule(schedule: ScheduledScan) -> None:
    """Add a new schedule to the running scheduler and update next_run_at."""
    scheduler = get_scheduler()
    if scheduler.running and schedule.enabled:
        _add_job_for_schedule(scheduler, schedule)
        logger.info(f"Added schedule to scheduler: {schedule.id}")

        # Persist next_run_at to database
        next_run = _get_next_run_time(scheduler, schedule.id)
        if next_run:
            async with AsyncSessionLocal() as session:
                result = await session.execute(
                    select(ScheduledScan).where(ScheduledScan.id == schedule.id)
                )
                db_schedule = result.scalar_one_or_none()
                if db_schedule:
                    db_schedule.next_run_at = next_run
                    await session.commit()
                    logger.info(f"Set next_run_at for schedule {schedule.id}: {next_run}")


async def update_schedule(schedule: ScheduledScan) -> None:
    """Update an existing schedule in the running scheduler and update next_run_at."""
    scheduler = get_scheduler()
    job_id = f"scheduled_scan_{schedule.id}"

    if not scheduler.running:
        return

    # Remove existing job if present
    try:
        scheduler.remove_job(job_id)
    except JobLookupError:
        pass

    # Re-add if enabled
    if schedule.enabled:
        _add_job_for_schedule(scheduler, schedule)
        logger.info(f"Updated schedule in scheduler: {schedule.id}")
    else:
        logger.info(f"Disabled schedule removed from scheduler: {schedule.id}")

    # Persist next_run_at to database
    next_run = _get_next_run_time(scheduler, schedule.id) if schedule.enabled else None
    async with AsyncSessionLocal() as session:
        result = await session.execute(
            select(ScheduledScan).where(ScheduledScan.id == schedule.id)
        )
        db_schedule = result.scalar_one_or_none()
        if db_schedule:
            db_schedule.next_run_at = next_run  # Will be None if disabled
            await session.commit()
            logger.info(f"Updated next_run_at for schedule {schedule.id}: {next_run}")


async def remove_schedule(schedule_id: UUID) -> None:
    """Remove a schedule from the running scheduler."""
    scheduler = get_scheduler()
    job_id = f"scheduled_scan_{schedule_id}"

    if scheduler.running:
        try:
            scheduler.remove_job(job_id)
            logger.info(f"Removed schedule from scheduler: {schedule_id}")
        except JobLookupError:
            logger.warning(f"Schedule not found in scheduler: {schedule_id}")


async def trigger_schedule_now(schedule_id: UUID, session: AsyncSession) -> UUID:
    """
    Manually trigger a scheduled scan immediately.

    Returns the created scan ID.
    """
    result = await session.execute(
        select(ScheduledScan).where(ScheduledScan.id == schedule_id)
    )
    schedule = result.scalar_one_or_none()

    if not schedule:
        raise ValueError(f"Schedule not found: {schedule_id}")

    # Get account IDs
    account_ids = schedule.account_ids
    if not account_ids:
        result = await session.execute(
            select(AWSAccount.id).where(AWSAccount.is_active == True)
        )
        account_ids = [str(row[0]) for row in result.fetchall()]

    # Get regions
    regions = schedule.regions or settings.default_scan_regions

    # Create scan record
    scan = Scan(
        status="QUEUED",
        regions=regions,
        account_ids=account_ids,
        rule_ids=schedule.rule_ids,
        resource_types=[],
    )
    session.add(scan)
    await session.flush()

    # Update schedule
    schedule.last_run_at = datetime.utcnow()
    schedule.last_scan_id = scan.id

    await session.commit()

    # Enqueue scan job
    await enqueue_scan_job(
        scan_id=str(scan.id),
        account_ids=account_ids,
        regions=regions,
        rule_ids=schedule.rule_ids,
    )

    logger.info(f"Manually triggered scheduled scan: schedule={schedule_id}, scan={scan.id}")
    return scan.id


def get_scheduler_status() -> dict:
    """Get scheduler status for health checks."""
    scheduler = get_scheduler()
    jobs = scheduler.get_jobs() if scheduler.running else []

    return {
        "running": scheduler.running,
        "job_count": len(jobs),
        "jobs": [
            {
                "id": job.id,
                "name": job.name,
                "next_run": job.next_run_time.isoformat() if job.next_run_time else None,
            }
            for job in jobs
        ]
    }


def validate_cron_expression(expression: str) -> bool:
    """Validate a cron expression without adding it to the scheduler."""
    try:
        _parse_cron_expression(expression, "UTC")
        return True
    except (ValueError, Exception):
        return False


def validate_interval_expression(expression: str) -> bool:
    """Validate an interval expression."""
    try:
        _parse_interval_expression(expression)
        return True
    except (ValueError, Exception):
        return False
