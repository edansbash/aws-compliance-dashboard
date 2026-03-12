"""Add resource_types to scans table

Revision ID: 002
Revises: 001
Create Date: 2024-01-01 00:00:00.000002

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = '002'
down_revision: Union[str, None] = '001'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        'scans',
        sa.Column('resource_types', postgresql.JSONB, nullable=False, server_default='[]')
    )


def downgrade() -> None:
    op.drop_column('scans', 'resource_types')
