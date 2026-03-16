"""API endpoints for notification configuration."""
import os
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.notification_config import NotificationConfig

router = APIRouter()


def get_slack_webhook_url() -> Optional[str]:
    """Get Slack webhook URL from environment variable."""
    return os.getenv("SLACK_WEBHOOK_URL")


def get_slack_channel_name() -> Optional[str]:
    """Get Slack channel name from environment variable (display only)."""
    return os.getenv("SLACK_CHANNEL_NAME")


def get_jira_config_from_env() -> dict:
    """Get JIRA configuration from environment variables."""
    return {
        "base_url": os.getenv("JIRA_BASE_URL"),
        "email": os.getenv("JIRA_EMAIL"),
        "api_token": os.getenv("JIRA_API_TOKEN"),
        "project_key": os.getenv("JIRA_PROJECT_KEY"),
        "issue_type": os.getenv("JIRA_ISSUE_TYPE", "Bug"),
        "assignee_email": os.getenv("JIRA_ASSIGNEE_EMAIL"),
    }


def is_jira_configured() -> bool:
    """Check if JIRA is fully configured via environment variables."""
    config = get_jira_config_from_env()
    return all([config["base_url"], config["email"], config["api_token"], config["project_key"]])


class SlackConfigResponse(BaseModel):
    """Response model for Slack configuration."""
    is_enabled: bool
    min_severity: str
    notify_on_new_findings: bool
    notify_on_regression: bool
    notify_on_scan_complete: bool
    webhook_configured: bool  # True if SLACK_WEBHOOK_URL env var is set
    channel_name: Optional[str] = None  # Display only, from SLACK_CHANNEL_NAME env var

    class Config:
        from_attributes = True


class SlackConfigUpdate(BaseModel):
    """Request model for updating Slack configuration (UI-configurable options only)."""
    is_enabled: Optional[bool] = None
    min_severity: Optional[str] = None
    notify_on_new_findings: Optional[bool] = None
    notify_on_regression: Optional[bool] = None
    notify_on_scan_complete: Optional[bool] = None


class TestNotificationRequest(BaseModel):
    """Request model for testing notifications."""
    pass


class TestNotificationResponse(BaseModel):
    """Response model for test notification."""
    success: bool
    message: str


@router.get("/slack", response_model=SlackConfigResponse)
async def get_slack_config(db: AsyncSession = Depends(get_db)):
    """Get current Slack notification configuration.

    Webhook URL is read from SLACK_WEBHOOK_URL environment variable.
    UI-configurable settings (min_severity, triggers) are stored in database.
    """
    webhook_url = get_slack_webhook_url()

    result = await db.execute(
        select(NotificationConfig).where(NotificationConfig.config_key == "slack")
    )
    config = result.scalar_one_or_none()

    channel_name = get_slack_channel_name()

    if not config:
        # Return default config if none exists
        return SlackConfigResponse(
            is_enabled=False,
            min_severity="CRITICAL",
            notify_on_new_findings=True,
            notify_on_regression=True,
            notify_on_scan_complete=True,
            webhook_configured=bool(webhook_url),
            channel_name=channel_name,
        )

    return SlackConfigResponse(
        is_enabled=config.is_enabled,
        min_severity=config.min_severity,
        notify_on_new_findings=config.notify_on_new_findings,
        notify_on_regression=config.notify_on_regression,
        notify_on_scan_complete=config.notify_on_scan_complete,
        webhook_configured=bool(webhook_url),
        channel_name=channel_name,
    )


@router.put("/slack", response_model=SlackConfigResponse)
async def update_slack_config(
    update: SlackConfigUpdate,
    db: AsyncSession = Depends(get_db)
):
    """Update Slack notification configuration (UI-configurable options only).

    Note: Webhook URL is configured via SLACK_WEBHOOK_URL environment variable.
    """
    webhook_url = get_slack_webhook_url()

    # Validate severity if provided
    valid_severities = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    if update.min_severity and update.min_severity not in valid_severities:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid severity. Must be one of: {', '.join(valid_severities)}"
        )

    result = await db.execute(
        select(NotificationConfig).where(NotificationConfig.config_key == "slack")
    )
    config = result.scalar_one_or_none()

    if not config:
        # Create new config
        config = NotificationConfig(
            config_key="slack",
            is_enabled=update.is_enabled if update.is_enabled is not None else False,
            min_severity=update.min_severity or "CRITICAL",
            notify_on_new_findings=update.notify_on_new_findings if update.notify_on_new_findings is not None else True,
            notify_on_regression=update.notify_on_regression if update.notify_on_regression is not None else True,
            notify_on_scan_complete=update.notify_on_scan_complete if update.notify_on_scan_complete is not None else True,
        )
        db.add(config)
    else:
        # Update existing config
        if update.is_enabled is not None:
            config.is_enabled = update.is_enabled
        if update.min_severity is not None:
            config.min_severity = update.min_severity
        if update.notify_on_new_findings is not None:
            config.notify_on_new_findings = update.notify_on_new_findings
        if update.notify_on_regression is not None:
            config.notify_on_regression = update.notify_on_regression
        if update.notify_on_scan_complete is not None:
            config.notify_on_scan_complete = update.notify_on_scan_complete

    await db.commit()
    await db.refresh(config)

    channel_name = get_slack_channel_name()

    return SlackConfigResponse(
        is_enabled=config.is_enabled,
        min_severity=config.min_severity,
        notify_on_new_findings=config.notify_on_new_findings,
        notify_on_regression=config.notify_on_regression,
        notify_on_scan_complete=config.notify_on_scan_complete,
        webhook_configured=bool(webhook_url),
        channel_name=channel_name,
    )


@router.post("/slack/test", response_model=TestNotificationResponse)
async def test_slack_notification(db: AsyncSession = Depends(get_db)):
    """Send a test notification to verify Slack configuration."""
    webhook_url = get_slack_webhook_url()

    if not webhook_url:
        raise HTTPException(
            status_code=400,
            detail="Slack webhook URL not configured. Set SLACK_WEBHOOK_URL environment variable."
        )

    # Get UI-configured settings from database
    result = await db.execute(
        select(NotificationConfig).where(NotificationConfig.config_key == "slack")
    )
    config = result.scalar_one_or_none()
    min_severity = config.min_severity if config else "CRITICAL"

    from app.services.notifications.slack import SlackNotifier

    notifier = SlackNotifier(
        webhook_url=webhook_url,
        min_severity=min_severity
    )

    # Send test notification
    success = await notifier.send_finding_notification(
        finding_type="new",
        rule_name="Test Rule - Slack Integration",
        rule_severity=min_severity,
        resource_id="test-resource-123",
        resource_name="test-resource",
        resource_type="test",
        account_id="123456789012",
        region="us-east-1",
        details={"message": "This is a test notification from AWS Compliance Dashboard"},
    )

    if success:
        return TestNotificationResponse(
            success=True,
            message="Test notification sent successfully"
        )
    else:
        raise HTTPException(
            status_code=500,
            detail="Failed to send test notification. Check webhook URL and try again."
        )


# ==================== JIRA Endpoints ====================
# All JIRA configuration is read from environment variables.
# No UI configuration is available for JIRA.


class JiraConfigResponse(BaseModel):
    """Response model for JIRA configuration (read-only, from environment)."""
    configured: bool  # True if all required env vars are set
    is_enabled: bool  # Same as configured - for frontend compatibility
    base_url: Optional[str] = None
    email: Optional[str] = None
    api_token_configured: bool = False
    project_key: Optional[str] = None
    issue_type: str = "Bug"
    assignee_email: Optional[str] = None

    class Config:
        from_attributes = True


@router.get("/jira", response_model=JiraConfigResponse)
async def get_jira_config_endpoint():
    """Get current JIRA configuration status (from environment variables).

    All JIRA settings are configured via environment variables:
    - JIRA_BASE_URL
    - JIRA_EMAIL
    - JIRA_API_TOKEN
    - JIRA_PROJECT_KEY
    - JIRA_ISSUE_TYPE (optional, defaults to "Bug")
    - JIRA_ASSIGNEE_EMAIL (optional)
    """
    config = get_jira_config_from_env()
    configured = is_jira_configured()

    return JiraConfigResponse(
        configured=configured,
        is_enabled=configured,  # JIRA is "enabled" when it's fully configured
        base_url=config["base_url"],
        email=config["email"],
        api_token_configured=bool(config["api_token"]),
        project_key=config["project_key"],
        issue_type=config["issue_type"],
        assignee_email=config["assignee_email"],
    )


@router.post("/jira/test", response_model=TestNotificationResponse)
async def test_jira_connection():
    """Test the JIRA connection and project access."""
    if not is_jira_configured():
        raise HTTPException(
            status_code=400,
            detail="JIRA not configured. Set JIRA_BASE_URL, JIRA_EMAIL, JIRA_API_TOKEN, and JIRA_PROJECT_KEY environment variables."
        )

    config = get_jira_config_from_env()

    from app.services.notifications.jira import JiraNotifier

    notifier = JiraNotifier(
        base_url=config["base_url"],
        email=config["email"],
        api_token=config["api_token"],
        project_key=config["project_key"],
        issue_type=config["issue_type"],
    )

    success, message = await notifier.test_connection()

    if success:
        return TestNotificationResponse(
            success=True,
            message=message
        )
    else:
        raise HTTPException(
            status_code=400,
            detail=message
        )


@router.get("/jira/custom-fields")
async def get_jira_custom_fields():
    """
    Fetch all custom fields from JIRA.

    Use this to find the field IDs for custom fields like:
    - AWS Account
    - AWS Region
    - AWS Finding ID
    etc.
    """
    if not is_jira_configured():
        raise HTTPException(
            status_code=400,
            detail="JIRA not configured. Set JIRA_BASE_URL, JIRA_EMAIL, JIRA_API_TOKEN, and JIRA_PROJECT_KEY environment variables."
        )

    config = get_jira_config_from_env()

    from app.services.notifications.jira import JiraNotifier

    notifier = JiraNotifier(
        base_url=config["base_url"],
        email=config["email"],
        api_token=config["api_token"],
        project_key=config["project_key"],
    )

    fields = await notifier.get_custom_fields()

    # Filter to show AWS-related fields prominently
    aws_fields = [f for f in fields if "aws" in f["name"].lower()]
    other_fields = [f for f in fields if "aws" not in f["name"].lower()]

    return {
        "aws_fields": aws_fields,
        "other_fields": other_fields,
        "total": len(fields),
    }


@router.get("/jira/boards")
async def get_jira_boards():
    """Fetch boards for the configured JIRA project."""
    if not is_jira_configured():
        raise HTTPException(
            status_code=400,
            detail="JIRA not configured. Set JIRA_BASE_URL, JIRA_EMAIL, JIRA_API_TOKEN, and JIRA_PROJECT_KEY environment variables."
        )

    config = get_jira_config_from_env()

    from app.services.notifications.jira import JiraNotifier

    notifier = JiraNotifier(
        base_url=config["base_url"],
        email=config["email"],
        api_token=config["api_token"],
        project_key=config["project_key"],
    )

    boards = await notifier.get_boards()

    return {
        "project_key": config["project_key"],
        "boards": boards,
    }
