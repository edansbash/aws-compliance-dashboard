"""Add scheduled_scans table

Revision ID: 003
Revises: 002
Create Date: 2024-01-01 00:00:00.000003

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = '003'
down_revision: Union[str, None] = '002'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'scheduled_scans',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('name', sa.String(255), nullable=False),
        sa.Column('description', sa.Text, nullable=True),
        sa.Column('account_ids', postgresql.JSONB, nullable=False, server_default='[]'),
        sa.Column('regions', postgresql.JSONB, nullable=False, server_default='[]'),
        sa.Column('rule_ids', postgresql.JSONB, nullable=True),
        sa.Column('schedule_type', sa.String(20), nullable=False, server_default='cron'),
        sa.Column('schedule_expression', sa.String(100), nullable=False),
        sa.Column('timezone', sa.String(50), nullable=False, server_default='UTC'),
        sa.Column('enabled', sa.Boolean, nullable=False, server_default='true'),
        sa.Column('last_run_at', sa.DateTime, nullable=True),
        sa.Column('next_run_at', sa.DateTime, nullable=True),
        sa.Column('last_scan_id', postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column('created_by', sa.String(255), nullable=True),
        sa.Column('created_at', sa.DateTime, nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime, nullable=False, server_default=sa.func.now()),
    )

    # Create index on enabled for faster lookups
    op.create_index('ix_scheduled_scans_enabled', 'scheduled_scans', ['enabled'])


def downgrade() -> None:
    op.drop_index('ix_scheduled_scans_enabled', table_name='scheduled_scans')
    op.drop_table('scheduled_scans')
