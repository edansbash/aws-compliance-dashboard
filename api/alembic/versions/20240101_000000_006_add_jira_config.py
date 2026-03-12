"""Add JIRA configuration table

Revision ID: 006
Revises: 005
Create Date: 2024-01-01 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID


# revision identifiers, used by Alembic.
revision = '006'
down_revision = '005'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        'jira_configs',
        sa.Column('id', UUID(as_uuid=True), primary_key=True),
        sa.Column('config_key', sa.String(50), unique=True, nullable=False),
        sa.Column('base_url', sa.Text, nullable=True),
        sa.Column('email', sa.Text, nullable=True),
        sa.Column('api_token', sa.Text, nullable=True),
        sa.Column('project_key', sa.String(50), nullable=True),
        sa.Column('issue_type', sa.String(100), default='Security Issue'),
        sa.Column('is_enabled', sa.Boolean, default=False),
        sa.Column('min_severity', sa.String(20), default='CRITICAL'),
        sa.Column('notify_on_new_findings', sa.Boolean, default=True),
        sa.Column('notify_on_regression', sa.Boolean, default=True),
        sa.Column('created_at', sa.DateTime, nullable=False),
        sa.Column('updated_at', sa.DateTime, nullable=False),
    )


def downgrade():
    op.drop_table('jira_configs')
