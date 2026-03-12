"""API endpoints for notification configuration."""
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.notification_config import NotificationConfig
from app.models.jira_config import JiraConfig

router = APIRouter()


class SlackConfigResponse(BaseModel):
    """Response model for Slack configuration."""
    is_enabled: bool
    min_severity: str
    notify_on_new_findings: bool
    notify_on_regression: bool
    notify_on_scan_complete: bool
    webhook_configured: bool  # Don't expose actual webhook URL

    class Config:
        from_attributes = True


class SlackConfigUpdate(BaseModel):
    """Request model for updating Slack configuration."""
    webhook_url: Optional[str] = None
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
    """Get current Slack notification configuration."""
    result = await db.execute(
        select(NotificationConfig).where(NotificationConfig.config_key == "slack")
    )
    config = result.scalar_one_or_none()

    if not config:
        # Return default config if none exists
        return SlackConfigResponse(
            is_enabled=False,
            min_severity="CRITICAL",
            notify_on_new_findings=True,
            notify_on_regression=True,
            notify_on_scan_complete=True,
            webhook_configured=False,
        )

    return SlackConfigResponse(
        is_enabled=config.is_enabled,
        min_severity=config.min_severity,
        notify_on_new_findings=config.notify_on_new_findings,
        notify_on_regression=config.notify_on_regression,
        notify_on_scan_complete=config.notify_on_scan_complete,
        webhook_configured=bool(config.webhook_url),
    )


@router.put("/slack", response_model=SlackConfigResponse)
async def update_slack_config(
    update: SlackConfigUpdate,
    db: AsyncSession = Depends(get_db)
):
    """Update Slack notification configuration."""
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
            webhook_url=update.webhook_url,
            is_enabled=update.is_enabled if update.is_enabled is not None else False,
            min_severity=update.min_severity or "CRITICAL",
            notify_on_new_findings=update.notify_on_new_findings if update.notify_on_new_findings is not None else True,
            notify_on_regression=update.notify_on_regression if update.notify_on_regression is not None else True,
            notify_on_scan_complete=update.notify_on_scan_complete if update.notify_on_scan_complete is not None else True,
        )
        db.add(config)
    else:
        # Update existing config
        if update.webhook_url is not None:
            config.webhook_url = update.webhook_url
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

    return SlackConfigResponse(
        is_enabled=config.is_enabled,
        min_severity=config.min_severity,
        notify_on_new_findings=config.notify_on_new_findings,
        notify_on_regression=config.notify_on_regression,
        notify_on_scan_complete=config.notify_on_scan_complete,
        webhook_configured=bool(config.webhook_url),
    )


@router.post("/slack/test", response_model=TestNotificationResponse)
async def test_slack_notification(db: AsyncSession = Depends(get_db)):
    """Send a test notification to verify Slack configuration."""
    result = await db.execute(
        select(NotificationConfig).where(NotificationConfig.config_key == "slack")
    )
    config = result.scalar_one_or_none()

    if not config or not config.webhook_url:
        raise HTTPException(
            status_code=400,
            detail="Slack webhook URL not configured"
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
    is_enabled: bool
    min_severity: str
    notify_on_new_findings: bool
    notify_on_regression: bool
    base_url_configured: bool
    base_url: Optional[str]  # Actual URL for building ticket links
    email_configured: bool
    api_token_configured: bool
    project_key: Optional[str]
    issue_type: str

    class Config:
        from_attributes = True


class JiraConfigUpdate(BaseModel):
    """Request model for updating JIRA configuration."""
    base_url: Optional[str] = None
    email: Optional[str] = None
    api_token: Optional[str] = None
    project_key: Optional[str] = None
    issue_type: Optional[str] = None
    is_enabled: Optional[bool] = None
    min_severity: Optional[str] = None
    notify_on_new_findings: Optional[bool] = None
    notify_on_regression: Optional[bool] = None


@router.get("/jira", response_model=JiraConfigResponse)
async def get_jira_config(db: AsyncSession = Depends(get_db)):
    """Get current JIRA notification configuration."""
    result = await db.execute(
        select(JiraConfig).where(JiraConfig.config_key == "jira")
    )
    config = result.scalar_one_or_none()

    if not config:
        # Return default config if none exists
        return JiraConfigResponse(
            is_enabled=False,
            min_severity="CRITICAL",
            notify_on_new_findings=True,
            notify_on_regression=True,
            base_url_configured=False,
            base_url=None,
            email_configured=False,
            api_token_configured=False,
            project_key=None,
            issue_type="Bug",
        )

    return JiraConfigResponse(
        is_enabled=config.is_enabled,
        min_severity=config.min_severity,
        notify_on_new_findings=config.notify_on_new_findings,
        notify_on_regression=config.notify_on_regression,
        base_url_configured=bool(config.base_url),
        base_url=config.base_url,
        email_configured=bool(config.email),
        api_token_configured=bool(config.api_token),
        project_key=config.project_key,
        issue_type=config.issue_type or "Security Issue",
    )


@router.put("/jira", response_model=JiraConfigResponse)
async def update_jira_config(
    update: JiraConfigUpdate,
    db: AsyncSession = Depends(get_db)
):
    """Update JIRA notification configuration."""
    # Validate severity if provided
    valid_severities = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    if update.min_severity and update.min_severity not in valid_severities:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid severity. Must be one of: {', '.join(valid_severities)}"
        )

    result = await db.execute(
        select(JiraConfig).where(JiraConfig.config_key == "jira")
    )
    config = result.scalar_one_or_none()

    if not config:
        # Create new config
        config = JiraConfig(
            config_key="jira",
            base_url=update.base_url,
            email=update.email,
            api_token=update.api_token,
            project_key=update.project_key,
            issue_type=update.issue_type or "Security Issue",
            is_enabled=update.is_enabled if update.is_enabled is not None else False,
            min_severity=update.min_severity or "CRITICAL",
            notify_on_new_findings=update.notify_on_new_findings if update.notify_on_new_findings is not None else True,
            notify_on_regression=update.notify_on_regression if update.notify_on_regression is not None else True,
        )
        db.add(config)
    else:
        # Update existing config
        if update.base_url is not None:
            config.base_url = update.base_url
        if update.email is not None:
            config.email = update.email
        if update.api_token is not None:
            config.api_token = update.api_token
        if update.project_key is not None:
            config.project_key = update.project_key
        if update.issue_type is not None:
            config.issue_type = update.issue_type
        if update.is_enabled is not None:
            config.is_enabled = update.is_enabled
        if update.min_severity is not None:
            config.min_severity = update.min_severity
        if update.notify_on_new_findings is not None:
            config.notify_on_new_findings = update.notify_on_new_findings
        if update.notify_on_regression is not None:
            config.notify_on_regression = update.notify_on_regression

    await db.commit()
    await db.refresh(config)

    return JiraConfigResponse(
        is_enabled=config.is_enabled,
        min_severity=config.min_severity,
        notify_on_new_findings=config.notify_on_new_findings,
        notify_on_regression=config.notify_on_regression,
        base_url_configured=bool(config.base_url),
        base_url=config.base_url,
        email_configured=bool(config.email),
        api_token_configured=bool(config.api_token),
        project_key=config.project_key,
        issue_type=config.issue_type or "Security Issue",
    )


@router.post("/jira/test", response_model=TestNotificationResponse)
async def test_jira_connection(db: AsyncSession = Depends(get_db)):
    """Test the JIRA connection and project access."""
    result = await db.execute(
        select(JiraConfig).where(JiraConfig.config_key == "jira")
    )
    config = result.scalar_one_or_none()

    if not config:
        raise HTTPException(
            status_code=400,
            detail="JIRA not configured"
        )

    if not all([config.base_url, config.email, config.api_token, config.project_key]):
        raise HTTPException(
            status_code=400,
            detail="JIRA configuration incomplete. Please provide base URL, email, API token, and project key."
        )

    from app.services.notifications.jira import JiraNotifier

    notifier = JiraNotifier(
        base_url=config.base_url,
        email=config.email,
        api_token=config.api_token,
        project_key=config.project_key,
        issue_type=config.issue_type or "Security Issue",
        min_severity=config.min_severity,
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
async def get_jira_custom_fields(db: AsyncSession = Depends(get_db)):
    """
    Fetch all custom fields from JIRA.

    Use this to find the field IDs for custom fields like:
    - AWS Account
    - AWS Region
    - AWS Finding ID
    etc.
    """
    from app.services.notifications.jira import get_jira_config, JiraNotifier

    config = await get_jira_config()

    if not config:
        raise HTTPException(
            status_code=400,
            detail="JIRA not configured"
        )

    if not all([config.base_url, config.email, config.api_token, config.project_key]):
        raise HTTPException(
            status_code=400,
            detail="JIRA configuration incomplete"
        )

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
async def get_jira_boards(db: AsyncSession = Depends(get_db)):
    """Fetch boards for the configured JIRA project."""
    from app.services.notifications.jira import get_jira_config, JiraNotifier

    config = await get_jira_config()

    if not config:
        raise HTTPException(
            status_code=400,
            detail="JIRA not configured"
        )

    if not all([config.base_url, config.email, config.api_token, config.project_key]):
        raise HTTPException(
            status_code=400,
            detail="JIRA configuration incomplete"
        )

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
