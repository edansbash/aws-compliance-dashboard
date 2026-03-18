"""Unify integration settings - merge notification_configs into integration_settings

Adds a JSONB settings column to integration_settings and migrates data from
notification_configs table, then drops the old table.

Revision ID: 013
Revises: 012
Create Date: 2024-01-01 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB


# revision identifiers, used by Alembic.
revision = '013'
down_revision = '012'
branch_labels = None
depends_on = None


def upgrade():
    # Add settings JSONB column to integration_settings
    op.add_column(
        'integration_settings',
        sa.Column('settings', JSONB, nullable=False, server_default='{}')
    )

    # Migrate data from notification_configs to integration_settings
    # For slack, copy over the settings
    op.execute("""
        UPDATE integration_settings
        SET settings = (
            SELECT jsonb_build_object(
                'min_severity', nc.min_severity,
                'notify_on_new_findings', nc.notify_on_new_findings,
                'notify_on_regression', nc.notify_on_regression,
                'notify_on_scan_complete', nc.notify_on_scan_complete
            )
            FROM notification_configs nc
            WHERE nc.config_key = 'slack'
        ),
        updated_at = NOW()
        WHERE integration_type = 'slack'
        AND EXISTS (SELECT 1 FROM notification_configs WHERE config_key = 'slack')
    """)

    # Set default settings for jira
    op.execute("""
        UPDATE integration_settings
        SET settings = jsonb_build_object(
            'min_severity', 'CRITICAL',
            'notify_on_new_findings', true,
            'notify_on_regression', true
        ),
        updated_at = NOW()
        WHERE integration_type = 'jira'
        AND settings = '{}'::jsonb
    """)

    # Set default settings for iac (empty for now)
    op.execute("""
        UPDATE integration_settings
        SET settings = '{}'::jsonb,
        updated_at = NOW()
        WHERE integration_type = 'iac'
        AND settings = '{}'::jsonb
    """)

    # Drop the old notification_configs table
    op.drop_table('notification_configs')


def downgrade():
    # Recreate notification_configs table
    op.create_table(
        'notification_configs',
        sa.Column('id', sa.UUID(), primary_key=True),
        sa.Column('config_key', sa.String(50), unique=True, nullable=False),
        sa.Column('is_enabled', sa.Boolean, default=False),
        sa.Column('min_severity', sa.String(20), default='CRITICAL'),
        sa.Column('notify_on_new_findings', sa.Boolean, default=True),
        sa.Column('notify_on_regression', sa.Boolean, default=True),
        sa.Column('notify_on_scan_complete', sa.Boolean, default=True),
        sa.Column('created_at', sa.DateTime, nullable=False),
        sa.Column('updated_at', sa.DateTime, nullable=False),
    )

    # Migrate slack settings back
    op.execute("""
        INSERT INTO notification_configs (id, config_key, is_enabled, min_severity,
            notify_on_new_findings, notify_on_regression, notify_on_scan_complete,
            created_at, updated_at)
        SELECT
            gen_random_uuid(),
            'slack',
            is_enabled,
            COALESCE(settings->>'min_severity', 'CRITICAL'),
            COALESCE((settings->>'notify_on_new_findings')::boolean, true),
            COALESCE((settings->>'notify_on_regression')::boolean, true),
            COALESCE((settings->>'notify_on_scan_complete')::boolean, true),
            created_at,
            updated_at
        FROM integration_settings
        WHERE integration_type = 'slack'
    """)

    # Remove settings column
    op.drop_column('integration_settings', 'settings')
