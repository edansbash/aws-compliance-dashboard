"""Slack notification service for compliance findings."""
import logging
import os
from typing import List, Optional
import httpx
from sqlalchemy import select

from app.database import AsyncSessionLocal
from app.models.notification_config import NotificationConfig
from app.models.rule import Severity

logger = logging.getLogger(__name__)

# Severity priority for comparison (higher number = more severe)
SEVERITY_PRIORITY = {
    "INFO": 0,
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}

# Slack colors for severities
SEVERITY_COLORS = {
    "CRITICAL": "#dc2626",  # red
    "HIGH": "#ea580c",      # orange
    "MEDIUM": "#ca8a04",    # yellow
    "LOW": "#2563eb",       # blue
    "INFO": "#6b7280",      # gray
}


class SlackNotifier:
    """Handles Slack notifications for compliance findings."""

    def __init__(self, webhook_url: str, min_severity: str = "CRITICAL"):
        """
        Initialize the Slack notifier.

        Args:
            webhook_url: Slack webhook URL
            min_severity: Minimum severity to notify for (CRITICAL, HIGH, MEDIUM, LOW, INFO)
        """
        self.webhook_url = webhook_url
        self.min_severity = min_severity

    def should_notify(self, severity: str) -> bool:
        """Check if the finding severity meets the minimum threshold."""
        finding_priority = SEVERITY_PRIORITY.get(severity, 0)
        min_priority = SEVERITY_PRIORITY.get(self.min_severity, 4)
        return finding_priority >= min_priority

    async def send_finding_notification(
        self,
        finding_type: str,  # "new" or "regression"
        rule_name: str,
        rule_severity: str,
        resource_id: str,
        resource_name: str,
        resource_type: str,
        account_id: str,
        region: str,
        details: Optional[dict] = None,
        jira_ticket_url: Optional[str] = None,
    ) -> bool:
        """
        Send a Slack notification for a finding.

        Args:
            finding_type: Type of finding ("new" or "regression")
            rule_name: Name of the compliance rule
            rule_severity: Severity level of the rule
            resource_id: AWS resource ID
            resource_name: Human-readable resource name
            resource_type: Type of AWS resource
            account_id: AWS account ID
            region: AWS region
            details: Additional finding details
            jira_ticket_url: Optional URL to the JIRA ticket for this finding

        Returns:
            True if notification was sent successfully
        """
        if not self.should_notify(rule_severity):
            return False

        # Build the message (concise format)
        title = "New" if finding_type == "new" else "Regression"
        emoji = ":rotating_light:" if rule_severity == "CRITICAL" else ":warning:"
        color = SEVERITY_COLORS.get(rule_severity, "#6b7280")

        # Build concise message text
        message_lines = [
            f"{emoji} *{rule_severity}* {title}: {rule_name}",
            f"`{resource_name}` · {region} · {account_id}",
        ]

        # Add JIRA ticket link if available
        if jira_ticket_url:
            ticket_key = jira_ticket_url.split("/")[-1]
            message_lines.append(f":ticket: <{jira_ticket_url}|{ticket_key}>")

        blocks = [
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": "\n".join(message_lines)
                }
            },
        ]

        payload = {
            "attachments": [
                {
                    "color": color,
                    "blocks": blocks
                }
            ]
        }

        try:
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    self.webhook_url,
                    json=payload,
                    timeout=10.0
                )
                response.raise_for_status()
                logger.info(f"Sent Slack notification for {finding_type} finding: {rule_name}")
                return True
        except Exception as e:
            logger.error(f"Failed to send Slack notification: {e}")
            return False

    async def send_scan_summary(
        self,
        scan_id: str,
        total_findings: int,
        new_findings: int,
        regressions: int,
        findings_by_severity: dict,
        account_ids: Optional[List[str]] = None,
        regions: Optional[List[str]] = None,
        jira_tickets_created: int = 0,
        jira_ticket_urls: Optional[List[str]] = None,
    ) -> bool:
        """
        Send a summary notification after a scan completes.

        Args:
            scan_id: ID of the completed scan
            total_findings: Total number of failed findings
            new_findings: Number of new findings
            regressions: Number of regression findings
            findings_by_severity: Dict mapping severity to count
            account_ids: List of AWS account IDs that were scanned
            regions: List of AWS regions that were scanned
            jira_tickets_created: Number of JIRA tickets created
            jira_ticket_urls: List of URLs to created JIRA tickets

        Returns:
            True if notification was sent successfully
        """
        # Determine emoji and message based on findings
        if new_findings == 0 and regressions == 0:
            if total_findings == 0:
                emoji = ":white_check_mark:"
                title = "Compliance Scan Complete - All Clear"
            else:
                emoji = ":large_green_circle:"
                title = "Compliance Scan Complete - No New Issues"
        else:
            emoji = ":rotating_light:" if findings_by_severity.get("CRITICAL", 0) > 0 else ":warning:"
            title = "Compliance Scan Complete"

        severity_text = " | ".join(
            f"{sev}: {count}" for sev, count in findings_by_severity.items() if count > 0
        )

        # Format accounts and regions for display
        accounts_text = ", ".join(account_ids) if account_ids else "All"
        regions_text = ", ".join(regions) if regions else "All"

        blocks = [
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"{emoji} *{title}*"
                }
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Accounts:* {accounts_text}"},
                    {"type": "mrkdwn", "text": f"*Regions:* {regions_text}"},
                    {"type": "mrkdwn", "text": f"*Total Failed:* {total_findings}"},
                    {"type": "mrkdwn", "text": f"*New Findings:* {new_findings}"},
                    {"type": "mrkdwn", "text": f"*Regressions:* {regressions}"},
                ]
            },
        ]

        if severity_text:
            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*By Severity:* {severity_text}"
                }
            })

        # Add JIRA ticket info if any were created
        if jira_tickets_created > 0:
            jira_text = f"*JIRA Tickets Created:* {jira_tickets_created}"
            if jira_ticket_urls:
                # Show up to 5 ticket links, one per line
                ticket_links = "\n".join(
                    f"• <{url}|{url.split('/')[-1]}>"
                    for url in jira_ticket_urls[:5]
                )
                jira_text += f"\n{ticket_links}"
                if len(jira_ticket_urls) > 5:
                    jira_text += f"\n_...and {len(jira_ticket_urls) - 5} more_"
            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": jira_text
                }
            })

        # Determine color based on findings
        if total_findings == 0:
            color = "#22c55e"  # green - all clear
        elif findings_by_severity.get("CRITICAL", 0) > 0:
            color = SEVERITY_COLORS["CRITICAL"]
        elif findings_by_severity.get("HIGH", 0) > 0:
            color = SEVERITY_COLORS["HIGH"]
        elif new_findings == 0 and regressions == 0:
            color = "#22c55e"  # green - no new issues
        else:
            color = SEVERITY_COLORS["MEDIUM"]

        payload = {
            "attachments": [
                {
                    "color": color,
                    "blocks": blocks
                }
            ]
        }

        try:
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    self.webhook_url,
                    json=payload,
                    timeout=10.0
                )
                response.raise_for_status()
                logger.info(f"Sent Slack scan summary for scan {scan_id}")
                return True
        except Exception as e:
            logger.error(f"Failed to send Slack scan summary: {e}")
            return False


async def get_slack_config() -> Optional[NotificationConfig]:
    """Get Slack notification configuration from database."""
    async with AsyncSessionLocal() as db:
        result = await db.execute(
            select(NotificationConfig).where(NotificationConfig.config_key == "slack")
        )
        return result.scalar_one_or_none()


async def send_slack_notification(
    finding_type: str,
    rule_name: str,
    rule_severity: str,
    resource_id: str,
    resource_name: str,
    resource_type: str,
    account_id: str,
    region: str,
    details: Optional[dict] = None,
    jira_ticket_url: Optional[str] = None,
) -> bool:
    """
    Send a Slack notification for a finding if configured.

    This is a convenience function that loads config and sends the notification.
    """
    config = await get_slack_config()
    webhook_url = os.environ.get("SLACK_WEBHOOK_URL")

    if not config or not config.is_enabled or not webhook_url:
        return False

    # Check if this notification type is enabled
    if finding_type == "new" and not config.notify_on_new_findings:
        return False
    if finding_type == "regression" and not config.notify_on_regression:
        return False

    notifier = SlackNotifier(
        webhook_url=webhook_url,
        min_severity=config.min_severity
    )

    return await notifier.send_finding_notification(
        finding_type=finding_type,
        rule_name=rule_name,
        rule_severity=rule_severity,
        resource_id=resource_id,
        resource_name=resource_name,
        resource_type=resource_type,
        account_id=account_id,
        region=region,
        details=details,
        jira_ticket_url=jira_ticket_url,
    )
