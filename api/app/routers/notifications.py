"""API endpoints for notification configuration.

Uses unified integration_settings table. Design principles:
- Credentials (API tokens, URLs) -> Always from env vars (never in DB)
- is_enabled -> UI toggle, stored in DB
- Behavioral settings (min_severity, notify flags) -> Env vars override DB settings
"""
import os
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.integration import IntegrationSetting
from app.services.integration_config import (
    get_slack_config as get_slack_config_service,
    get_jira_config as get_jira_config_service,
    update_integration_settings,
)

router = APIRouter()


# ==================== Slack Endpoints ====================


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


class TestNotificationResponse(BaseModel):
    """Response model for test notification."""
    success: bool
    message: str


@router.get("/slack", response_model=SlackConfigResponse)
async def get_slack_config():
    """Get current Slack notification configuration.

    Credentials from env vars, behavioral settings from env > DB > defaults.
    """
    config = await get_slack_config_service()

    return SlackConfigResponse(
        is_enabled=config.is_enabled,
        min_severity=config.min_severity,
        notify_on_new_findings=config.notify_on_new_findings,
        notify_on_regression=config.notify_on_regression,
        notify_on_scan_complete=config.notify_on_scan_complete,
        webhook_configured=config.is_configured,
        channel_name=config.channel_name,
    )


@router.put("/slack", response_model=SlackConfigResponse)
async def update_slack_config(
    update: SlackConfigUpdate,
    db: AsyncSession = Depends(get_db)
):
    """Update Slack notification configuration (UI-configurable options only).

    Note: Webhook URL is configured via SLACK_WEBHOOK_URL environment variable.
    Settings changed here are stored in DB but can be overridden by env vars.
    """
    # Validate severity if provided
    valid_severities = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    if update.min_severity and update.min_severity not in valid_severities:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid severity. Must be one of: {', '.join(valid_severities)}"
        )

    # Build settings dict from update
    settings_update = {}
    if update.min_severity is not None:
        settings_update["min_severity"] = update.min_severity
    if update.notify_on_new_findings is not None:
        settings_update["notify_on_new_findings"] = update.notify_on_new_findings
    if update.notify_on_regression is not None:
        settings_update["notify_on_regression"] = update.notify_on_regression
    if update.notify_on_scan_complete is not None:
        settings_update["notify_on_scan_complete"] = update.notify_on_scan_complete

    # Update integration settings
    await update_integration_settings(
        db=db,
        integration_type="slack",
        is_enabled=update.is_enabled,
        settings=settings_update if settings_update else None
    )

    # Return updated config (re-fetch to apply env > DB logic)
    config = await get_slack_config_service()

    return SlackConfigResponse(
        is_enabled=config.is_enabled,
        min_severity=config.min_severity,
        notify_on_new_findings=config.notify_on_new_findings,
        notify_on_regression=config.notify_on_regression,
        notify_on_scan_complete=config.notify_on_scan_complete,
        webhook_configured=config.is_configured,
        channel_name=config.channel_name,
    )


@router.post("/slack/test", response_model=TestNotificationResponse)
async def test_slack_notification():
    """Send a test notification to verify Slack configuration."""
    config = await get_slack_config_service()

    if not config.is_configured:
        raise HTTPException(
            status_code=400,
            detail="Slack webhook URL not configured. Set SLACK_WEBHOOK_URL environment variable."
        )

    from app.services.notifications.slack import SlackNotifier

    notifier = SlackNotifier(
        webhook_url=config.webhook_url,
        min_severity=config.min_severity
    )

    # Send test notification
    success = await notifier.send_finding_notification(
        finding_type="new",
        rule_name="Test Rule - Slack Integration",
        rule_severity=config.min_severity,
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


class JiraConfigResponse(BaseModel):
    """Response model for JIRA configuration."""
    configured: bool  # True if all required env vars are set
    is_enabled: bool  # UI toggle from DB
    base_url: Optional[str] = None
    email: Optional[str] = None
    api_token_configured: bool = False
    project_key: Optional[str] = None
    issue_type: str = "Bug"
    min_severity: str = "CRITICAL"
    notify_on_new_findings: bool = True
    notify_on_regression: bool = True
    assignee_email: Optional[str] = None

    class Config:
        from_attributes = True


class JiraConfigUpdate(BaseModel):
    """Request model for updating JIRA configuration (UI-configurable options only)."""
    is_enabled: Optional[bool] = None
    min_severity: Optional[str] = None
    notify_on_new_findings: Optional[bool] = None
    notify_on_regression: Optional[bool] = None


@router.get("/jira", response_model=JiraConfigResponse)
async def get_jira_config_endpoint():
    """Get current JIRA configuration status.

    Credentials from env vars, behavioral settings from env > DB > defaults.

    Environment variables:
    - JIRA_BASE_URL
    - JIRA_EMAIL
    - JIRA_API_TOKEN
    - JIRA_PROJECT_KEY
    - JIRA_ISSUE_TYPE (optional, defaults to "Bug")
    - JIRA_MIN_SEVERITY (optional, overrides DB setting)
    - JIRA_ASSIGNEE_EMAIL (optional)
    """
    config = await get_jira_config_service()

    return JiraConfigResponse(
        configured=config.is_configured,
        is_enabled=config.is_enabled,
        base_url=config.base_url,
        email=config.email,
        api_token_configured=bool(config.api_token),
        project_key=config.project_key,
        issue_type=config.issue_type,
        min_severity=config.min_severity,
        notify_on_new_findings=config.notify_on_new_findings,
        notify_on_regression=config.notify_on_regression,
        assignee_email=config.assignee_email,
    )


@router.put("/jira", response_model=JiraConfigResponse)
async def update_jira_config(
    update: JiraConfigUpdate,
    db: AsyncSession = Depends(get_db)
):
    """Update JIRA notification configuration (UI-configurable options only).

    Credentials are always from env vars. Settings here can be overridden by env vars.
    """
    # Validate severity if provided
    valid_severities = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    if update.min_severity and update.min_severity not in valid_severities:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid severity. Must be one of: {', '.join(valid_severities)}"
        )

    # Build settings dict from update
    settings_update = {}
    if update.min_severity is not None:
        settings_update["min_severity"] = update.min_severity
    if update.notify_on_new_findings is not None:
        settings_update["notify_on_new_findings"] = update.notify_on_new_findings
    if update.notify_on_regression is not None:
        settings_update["notify_on_regression"] = update.notify_on_regression

    # Update integration settings
    await update_integration_settings(
        db=db,
        integration_type="jira",
        is_enabled=update.is_enabled,
        settings=settings_update if settings_update else None
    )

    # Return updated config
    config = await get_jira_config_service()

    return JiraConfigResponse(
        configured=config.is_configured,
        is_enabled=config.is_enabled,
        base_url=config.base_url,
        email=config.email,
        api_token_configured=bool(config.api_token),
        project_key=config.project_key,
        issue_type=config.issue_type,
        min_severity=config.min_severity,
        notify_on_new_findings=config.notify_on_new_findings,
        notify_on_regression=config.notify_on_regression,
        assignee_email=config.assignee_email,
    )


@router.post("/jira/test", response_model=TestNotificationResponse)
async def test_jira_connection():
    """Test the JIRA connection and project access."""
    config = await get_jira_config_service()

    if not config.is_configured:
        raise HTTPException(
            status_code=400,
            detail="JIRA not configured. Set JIRA_BASE_URL, JIRA_EMAIL, JIRA_API_TOKEN, and JIRA_PROJECT_KEY environment variables."
        )

    from app.services.notifications.jira import JiraNotifier

    notifier = JiraNotifier(
        base_url=config.base_url,
        email=config.email,
        api_token=config.api_token,
        project_key=config.project_key,
        issue_type=config.issue_type,
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
    """Fetch all custom fields from JIRA."""
    config = await get_jira_config_service()

    if not config.is_configured:
        raise HTTPException(
            status_code=400,
            detail="JIRA not configured. Set JIRA_BASE_URL, JIRA_EMAIL, JIRA_API_TOKEN, and JIRA_PROJECT_KEY environment variables."
        )

    from app.services.notifications.jira import JiraNotifier

    notifier = JiraNotifier(
        base_url=config.base_url,
        email=config.email,
        api_token=config.api_token,
        project_key=config.project_key,
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
    config = await get_jira_config_service()

    if not config.is_configured:
        raise HTTPException(
            status_code=400,
            detail="JIRA not configured. Set JIRA_BASE_URL, JIRA_EMAIL, JIRA_API_TOKEN, and JIRA_PROJECT_KEY environment variables."
        )

    from app.services.notifications.jira import JiraNotifier

    notifier = JiraNotifier(
        base_url=config.base_url,
        email=config.email,
        api_token=config.api_token,
        project_key=config.project_key,
    )

    boards = await notifier.get_boards()

    return {
        "project_key": config.project_key,
        "boards": boards,
    }
