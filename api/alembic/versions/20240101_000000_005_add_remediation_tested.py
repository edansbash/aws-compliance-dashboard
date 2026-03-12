"""Add remediation_tested to rules

Revision ID: 005
Revises: 004
Create Date: 2024-01-01 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '005'
down_revision = '004'
branch_labels = None
depends_on = None


def upgrade():
    op.execute("""
        ALTER TABLE rules
        ADD COLUMN IF NOT EXISTS remediation_tested BOOLEAN DEFAULT FALSE
    """)


def downgrade():
    op.drop_column('rules', 'remediation_tested')
