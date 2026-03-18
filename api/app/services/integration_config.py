"""
Unified integration configuration service.

Design principles:
- Credentials (API tokens, URLs) -> Always from env vars (never in DB)
- is_enabled -> UI toggle, stored in DB
- Behavioral settings (min_severity, notify flags) -> Env vars override DB settings

Priority for behavioral settings: ENV VAR > DB > DEFAULT
"""

import os
import logging
from dataclasses import dataclass, field
from typing import Optional, Dict, Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import AsyncSessionLocal
from app.models.integration import IntegrationSetting

logger = logging.getLogger(__name__)


# Default settings for each integration
DEFAULT_SETTINGS = {
    "slack": {
        "min_severity": "CRITICAL",
        "notify_on_new_findings": True,
        "notify_on_regression": True,
        "notify_on_scan_complete": True,
    },
    "jira": {
        "min_severity": "CRITICAL",
        "notify_on_new_findings": True,
        "notify_on_regression": True,
    },
    "iac": {},
}


@dataclass
class SlackConfig:
    """Slack integration configuration."""
    # Credentials (env only)
    webhook_url: Optional[str] = None
    channel_name: Optional[str] = None

    # State (DB)
    is_enabled: bool = False

    # Behavioral settings (env > DB > default)
    min_severity: str = "CRITICAL"
    notify_on_new_findings: bool = True
    notify_on_regression: bool = True
    notify_on_scan_complete: bool = True

    @property
    def is_configured(self) -> bool:
        """Check if Slack has required credentials configured."""
        return bool(self.webhook_url)


@dataclass
class JiraConfig:
    """JIRA integration configuration."""
    # Credentials (env only)
    base_url: Optional[str] = None
    email: Optional[str] = None
    api_token: Optional[str] = None
    project_key: Optional[str] = None
    issue_type: str = "Bug"
    assignee_email: Optional[str] = None

    # State (DB)
    is_enabled: bool = False

    # Behavioral settings (env > DB > default)
    min_severity: str = "CRITICAL"
    notify_on_new_findings: bool = True
    notify_on_regression: bool = True

    @property
    def is_configured(self) -> bool:
        """Check if JIRA has required credentials configured."""
        return all([self.base_url, self.email, self.api_token, self.project_key])


@dataclass
class IaCConfig:
    """IaC/GitHub integration configuration."""
    # Credentials (env only)
    github_token: Optional[str] = None
    github_owner: Optional[str] = None
    github_repo: Optional[str] = None
    github_branch: str = "main"

    # State (DB)
    is_enabled: bool = False

    @property
    def is_configured(self) -> bool:
        """Check if IaC has required credentials configured."""
        return all([self.github_token, self.github_owner, self.github_repo])


def _parse_bool(value: Optional[str], default: bool) -> bool:
    """Parse a string to boolean, with default fallback."""
    if value is None:
        return default
    return value.lower() in ("true", "1", "yes")


async def get_integration_setting(integration_type: str) -> Optional[IntegrationSetting]:
    """Get integration setting from database."""
    async with AsyncSessionLocal() as db:
        result = await db.execute(
            select(IntegrationSetting).where(
                IntegrationSetting.integration_type == integration_type
            )
        )
        return result.scalar_one_or_none()


async def get_slack_config() -> SlackConfig:
    """
    Get Slack configuration with env > DB > default priority.

    Returns:
        SlackConfig with merged settings
    """
    # Get DB settings
    db_setting = await get_integration_setting("slack")
    db_settings = db_setting.settings if db_setting and db_setting.settings else {}
    defaults = DEFAULT_SETTINGS["slack"]

    # Build config: credentials from env, is_enabled from DB, behavioral from env > DB > default
    config = SlackConfig(
        # Credentials (env only)
        webhook_url=os.environ.get("SLACK_WEBHOOK_URL"),
        channel_name=os.environ.get("SLACK_CHANNEL_NAME"),

        # State (DB only)
        is_enabled=db_setting.is_enabled if db_setting else False,

        # Behavioral settings: env > DB > default
        min_severity=os.environ.get(
            "SLACK_MIN_SEVERITY",
            db_settings.get("min_severity", defaults["min_severity"])
        ),
        notify_on_new_findings=_parse_bool(
            os.environ.get("SLACK_NOTIFY_NEW"),
            db_settings.get("notify_on_new_findings", defaults["notify_on_new_findings"])
        ),
        notify_on_regression=_parse_bool(
            os.environ.get("SLACK_NOTIFY_REGRESSION"),
            db_settings.get("notify_on_regression", defaults["notify_on_regression"])
        ),
        notify_on_scan_complete=_parse_bool(
            os.environ.get("SLACK_NOTIFY_SCAN_COMPLETE"),
            db_settings.get("notify_on_scan_complete", defaults["notify_on_scan_complete"])
        ),
    )

    logger.debug(f"Slack config: is_enabled={config.is_enabled}, min_severity={config.min_severity}")
    return config


async def get_jira_config() -> JiraConfig:
    """
    Get JIRA configuration with env > DB > default priority.

    Returns:
        JiraConfig with merged settings
    """
    # Get DB settings
    db_setting = await get_integration_setting("jira")
    db_settings = db_setting.settings if db_setting and db_setting.settings else {}
    defaults = DEFAULT_SETTINGS["jira"]

    # Build config: credentials from env, is_enabled from DB, behavioral from env > DB > default
    config = JiraConfig(
        # Credentials (env only)
        base_url=os.environ.get("JIRA_BASE_URL"),
        email=os.environ.get("JIRA_EMAIL"),
        api_token=os.environ.get("JIRA_API_TOKEN"),
        project_key=os.environ.get("JIRA_PROJECT_KEY"),
        issue_type=os.environ.get("JIRA_ISSUE_TYPE", "Bug"),
        assignee_email=os.environ.get("JIRA_ASSIGNEE_EMAIL"),

        # State (DB only)
        is_enabled=db_setting.is_enabled if db_setting else False,

        # Behavioral settings: env > DB > default
        min_severity=os.environ.get(
            "JIRA_MIN_SEVERITY",
            db_settings.get("min_severity", defaults["min_severity"])
        ),
        notify_on_new_findings=_parse_bool(
            os.environ.get("JIRA_NOTIFY_NEW"),
            db_settings.get("notify_on_new_findings", defaults["notify_on_new_findings"])
        ),
        notify_on_regression=_parse_bool(
            os.environ.get("JIRA_NOTIFY_REGRESSION"),
            db_settings.get("notify_on_regression", defaults["notify_on_regression"])
        ),
    )

    logger.debug(f"JIRA config: is_enabled={config.is_enabled}, min_severity={config.min_severity}")
    return config


async def get_iac_config() -> IaCConfig:
    """
    Get IaC/GitHub configuration.

    Returns:
        IaCConfig with merged settings
    """
    # Get DB settings
    db_setting = await get_integration_setting("iac")

    config = IaCConfig(
        # Credentials (env only)
        github_token=os.environ.get("GITHUB_TOKEN"),
        github_owner=os.environ.get("IAC_GITHUB_OWNER"),
        github_repo=os.environ.get("IAC_GITHUB_REPO"),
        github_branch=os.environ.get("IAC_GITHUB_BRANCH", "main"),

        # State (DB only)
        is_enabled=db_setting.is_enabled if db_setting else False,
    )

    logger.debug(f"IaC config: is_enabled={config.is_enabled}, is_configured={config.is_configured}")
    return config


async def update_integration_settings(
    db: AsyncSession,
    integration_type: str,
    is_enabled: Optional[bool] = None,
    settings: Optional[Dict[str, Any]] = None
) -> IntegrationSetting:
    """
    Update integration settings in database.

    Args:
        db: Database session
        integration_type: Type of integration (slack, jira, iac)
        is_enabled: Optional new enabled state
        settings: Optional new settings dict (will be merged with existing)

    Returns:
        Updated IntegrationSetting
    """
    result = await db.execute(
        select(IntegrationSetting).where(
            IntegrationSetting.integration_type == integration_type
        )
    )
    setting = result.scalar_one_or_none()

    if not setting:
        raise ValueError(f"Integration '{integration_type}' not found")

    if is_enabled is not None:
        setting.is_enabled = is_enabled

    if settings is not None:
        # Merge settings
        current = setting.settings or {}
        current.update(settings)
        setting.settings = current

    await db.commit()
    await db.refresh(setting)

    return setting
