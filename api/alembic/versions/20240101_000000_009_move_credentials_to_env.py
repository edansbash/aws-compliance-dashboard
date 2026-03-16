"""Move integration credentials to environment variables

This migration:
1. Drops webhook_url from notification_configs (now SLACK_WEBHOOK_URL env var)
2. Drops jira_configs table (all JIRA config now from env vars)

Revision ID: 009
Revises: 008
Create Date: 2024-01-01 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID


# revision identifiers, used by Alembic.
revision = '009'
down_revision = '008'
branch_labels = None
depends_on = None


def upgrade():
    # Drop webhook_url column from notification_configs
    # (webhook URL is now configured via SLACK_WEBHOOK_URL env var)
    op.drop_column('notification_configs', 'webhook_url')

    # Drop jira_configs table
    # (all JIRA config is now from environment variables)
    op.drop_table('jira_configs')


def downgrade():
    # Recreate jira_configs table
    op.create_table(
        'jira_configs',
        sa.Column('id', UUID(as_uuid=True), primary_key=True),
        sa.Column('config_key', sa.String(50), unique=True, nullable=False),
        sa.Column('base_url', sa.Text, nullable=True),
        sa.Column('email', sa.Text, nullable=True),
        sa.Column('api_token', sa.Text, nullable=True),
        sa.Column('project_key', sa.String(50), nullable=True),
        sa.Column('issue_type', sa.String(100), server_default='Security Issue'),
        sa.Column('is_enabled', sa.Boolean, server_default='false'),
        sa.Column('min_severity', sa.String(20), server_default='CRITICAL'),
        sa.Column('notify_on_new_findings', sa.Boolean, server_default='true'),
        sa.Column('notify_on_regression', sa.Boolean, server_default='true'),
        sa.Column('created_at', sa.DateTime, nullable=False),
        sa.Column('updated_at', sa.DateTime, nullable=False),
    )

    # Re-add webhook_url column to notification_configs
    op.add_column(
        'notification_configs',
        sa.Column('webhook_url', sa.Text, nullable=True)
    )
