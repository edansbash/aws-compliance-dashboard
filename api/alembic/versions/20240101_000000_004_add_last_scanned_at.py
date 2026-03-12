"""Add last_scanned_at to findings

Revision ID: 004
Revises: 003
Create Date: 2024-01-01 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '004'
down_revision = '003'
branch_labels = None
depends_on = None


def upgrade():
    # Column already exists from manual migration, just making it official
    op.execute("""
        ALTER TABLE findings
        ADD COLUMN IF NOT EXISTS last_scanned_at TIMESTAMP
    """)


def downgrade():
    op.drop_column('findings', 'last_scanned_at')
