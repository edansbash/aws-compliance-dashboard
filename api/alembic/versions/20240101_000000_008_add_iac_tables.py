"""Add IaC (Infrastructure as Code) tables for Terraform scanning

Revision ID: 008
Revises: 007
Create Date: 2024-01-01 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID


# revision identifiers, used by Alembic.
revision = '008'
down_revision = '007'
branch_labels = None
depends_on = None


def upgrade():
    # Create iac_syncs table
    op.create_table(
        'iac_syncs',
        sa.Column('id', UUID(as_uuid=True), primary_key=True),
        sa.Column('status', sa.String(20), nullable=False, server_default='RUNNING'),
        sa.Column('commit_sha', sa.String(40), nullable=True),
        sa.Column('branch', sa.String(100), nullable=True),
        sa.Column('started_at', sa.DateTime, nullable=True),
        sa.Column('completed_at', sa.DateTime, nullable=True),
        sa.Column('total_alerts', sa.Integer, server_default='0'),
        sa.Column('open_alerts', sa.Integer, server_default='0'),
        sa.Column('new_alerts', sa.Integer, server_default='0'),
        sa.Column('fixed_alerts', sa.Integer, server_default='0'),
        sa.Column('error_message', sa.String(1000), nullable=True),
        sa.Column('created_at', sa.DateTime, nullable=False),
    )

    # Create iac_findings table
    op.create_table(
        'iac_findings',
        sa.Column('id', UUID(as_uuid=True), primary_key=True),
        sa.Column('sync_id', UUID(as_uuid=True), sa.ForeignKey('iac_syncs.id', ondelete='SET NULL'), nullable=True),
        # GitHub Alert (source of truth)
        sa.Column('github_alert_number', sa.Integer, nullable=False, unique=True),
        sa.Column('github_alert_url', sa.String(500), nullable=False),
        sa.Column('github_alert_state', sa.String(20), nullable=False),
        # Trivy Rule
        sa.Column('trivy_rule_id', sa.String(100), nullable=False),
        sa.Column('trivy_rule_description', sa.Text, nullable=True),
        sa.Column('severity', sa.String(20), nullable=False),
        # Code Location
        sa.Column('file_path', sa.String(500), nullable=False),
        sa.Column('start_line', sa.Integer, nullable=True),
        sa.Column('end_line', sa.Integer, nullable=True),
        # Details
        sa.Column('message', sa.Text, nullable=True),
        sa.Column('resource_type', sa.String(100), nullable=True),
        # Tracking
        sa.Column('commit_sha', sa.String(40), nullable=True),
        sa.Column('first_detected_at', sa.DateTime, nullable=False),
        sa.Column('last_seen_at', sa.DateTime, nullable=False),
        sa.Column('dismissed_at', sa.DateTime, nullable=True),
        sa.Column('dismissed_reason', sa.String(100), nullable=True),
        sa.Column('created_at', sa.DateTime, nullable=False),
    )

    # Create indexes for common queries
    op.create_index('idx_iac_findings_state', 'iac_findings', ['github_alert_state'])
    op.create_index('idx_iac_findings_severity', 'iac_findings', ['severity'])
    op.create_index('idx_iac_findings_rule', 'iac_findings', ['trivy_rule_id'])


def downgrade():
    op.drop_index('idx_iac_findings_rule', 'iac_findings')
    op.drop_index('idx_iac_findings_severity', 'iac_findings')
    op.drop_index('idx_iac_findings_state', 'iac_findings')
    op.drop_table('iac_findings')
    op.drop_table('iac_syncs')
