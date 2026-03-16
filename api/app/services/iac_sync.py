"""
IaC Sync Service - pulls findings from GitHub Code Scanning API.
"""

from typing import Callable, Optional
from uuid import UUID
from datetime import datetime

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, delete

from app.services.github import GitHubService, CodeScanningAlert
from app.services.iac_config import IaCConfig
from app.models.iac import IaCSync, IaCFinding


def normalize_severity(trivy_severity: str) -> str:
    """Normalize Trivy severity to uppercase."""
    mapping = {
        "CRITICAL": "CRITICAL",
        "HIGH": "HIGH",
        "MEDIUM": "MEDIUM",
        "LOW": "LOW",
        "critical": "CRITICAL",
        "high": "HIGH",
        "medium": "MEDIUM",
        "low": "LOW",
    }
    return mapping.get(trivy_severity, "MEDIUM")


class IaCSyncService:
    """Sync IaC findings from GitHub Code Scanning API."""

    def __init__(self, db: AsyncSession):
        self.db = db
        self.config = IaCConfig.from_env()

    async def sync(
        self, progress_callback: Optional[Callable[[str, dict], None]] = None
    ) -> IaCSync:
        """
        Sync findings from GitHub Code Scanning API.

        Args:
            progress_callback: Optional callback for status updates

        Returns:
            IaCSync record with synced findings
        """
        if not self.config.is_configured():
            raise ValueError(
                "IaC scanning not configured. Check environment variables: "
                "GITHUB_TOKEN, IAC_GITHUB_OWNER, IAC_GITHUB_REPO"
            )

        # Initialize GitHub client (uses GITHUB_TOKEN from env)
        github = GitHubService()

        # Create sync record
        sync = IaCSync(
            status="RUNNING",
            branch=self.config.branch,
            started_at=datetime.utcnow(),
        )
        self.db.add(sync)
        await self.db.commit()
        await self.db.refresh(sync)

        try:
            # Clear all existing findings - each sync is a full refresh of the configured branch
            # This ensures branch switches show correct data
            await self.db.execute(delete(IaCFinding))
            await self.db.commit()

            if progress_callback:
                progress_callback(
                    "Fetching alerts from GitHub...",
                    {"phase": "fetch", "sync_id": str(sync.id)},
                )

            # Fetch ALL alerts (open, dismissed, fixed) to track state changes
            # Try without tool_name filter first to get all alerts
            all_alerts = await github.get_code_scanning_alerts(
                owner=self.config.owner,
                repo=self.config.repo,
                ref=self.config.branch,
                state="all",  # Get all states
                tool_name=None,  # Don't filter by tool - get all scanners
            )

            if progress_callback:
                progress_callback(
                    f"Processing {len(all_alerts)} alerts...",
                    {"phase": "process", "total": len(all_alerts)},
                )

            # Track counts
            new_count = 0
            fixed_count = 0

            # Process each alert
            for alert in all_alerts:
                is_new, is_fixed = await self._upsert_finding(sync.id, alert)
                if is_new:
                    new_count += 1
                if is_fixed:
                    fixed_count += 1

            # Update sync record
            open_alerts = [a for a in all_alerts if a.state == "open"]
            sync.status = "COMPLETED"
            sync.completed_at = datetime.utcnow()
            sync.total_alerts = len(all_alerts)
            sync.open_alerts = len(open_alerts)
            sync.new_alerts = new_count
            sync.fixed_alerts = fixed_count
            sync.commit_sha = all_alerts[0].commit_sha if all_alerts else None

            await self.db.commit()

            if progress_callback:
                progress_callback(
                    f"Sync completed: {len(open_alerts)} open alerts, {new_count} new, {fixed_count} fixed",
                    {
                        "phase": "complete",
                        "open_alerts": len(open_alerts),
                        "new_alerts": new_count,
                        "fixed_alerts": fixed_count,
                    },
                )

            return sync

        except Exception as e:
            sync.status = "FAILED"
            sync.error_message = str(e)[:1000]
            sync.completed_at = datetime.utcnow()
            await self.db.commit()
            raise

    async def _upsert_finding(
        self,
        sync_id: UUID,
        alert: CodeScanningAlert,
    ) -> tuple[bool, bool]:
        """
        Update existing finding or create new one.

        Returns:
            (is_new, is_fixed) - whether this is a new finding and whether it was fixed
        """
        # Check for existing finding by GitHub alert number (unique identifier)
        result = await self.db.execute(
            select(IaCFinding).where(IaCFinding.github_alert_number == alert.number)
        )
        existing = result.scalar_one_or_none()

        is_new = False
        is_fixed = False

        if existing:
            # Track if alert was fixed
            if existing.github_alert_state == "open" and alert.state == "fixed":
                is_fixed = True

            # Update existing finding
            existing.sync_id = sync_id
            existing.github_alert_state = alert.state
            existing.last_seen_at = datetime.utcnow()
            existing.commit_sha = alert.commit_sha
            existing.message = alert.message
            existing.tool_name = alert.tool_name  # Update in case it changed

            if alert.fixed_at:
                existing.fixed_at = alert.fixed_at

            if alert.dismissed_at:
                existing.dismissed_at = alert.dismissed_at
                existing.dismissed_reason = alert.dismissed_reason
        else:
            # Create new finding
            is_new = True
            finding = IaCFinding(
                sync_id=sync_id,
                github_alert_number=alert.number,
                github_alert_url=alert.html_url,
                github_alert_state=alert.state,
                trivy_rule_id=alert.rule_id,
                trivy_rule_description=alert.description,
                trivy_rule_name=alert.rule_name,
                trivy_help_uri=alert.help_uri,
                severity=normalize_severity(alert.severity),
                tool_name=alert.tool_name,
                file_path=alert.file_path,
                start_line=alert.start_line,
                end_line=alert.end_line,
                message=alert.message,
                resource_type=None,  # Trivy AVD IDs don't encode resource type
                commit_sha=alert.commit_sha,
                first_detected_at=datetime.utcnow(),
                last_seen_at=datetime.utcnow(),
                fixed_at=alert.fixed_at,
            )
            self.db.add(finding)

        return is_new, is_fixed

    async def get_last_sync(self) -> Optional[IaCSync]:
        """Get the most recent sync record."""
        result = await self.db.execute(
            select(IaCSync).order_by(IaCSync.created_at.desc()).limit(1)
        )
        return result.scalar_one_or_none()
