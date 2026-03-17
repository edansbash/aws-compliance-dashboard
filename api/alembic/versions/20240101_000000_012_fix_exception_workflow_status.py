"""Fix workflow_status for EXCEPTION findings

Revision ID: 012
Revises: 011
Create Date: 2024-01-01 00:00:00.000000

"""
from alembic import op


# revision identifiers, used by Alembic.
revision = '012'
down_revision = '011'
branch_labels = None
depends_on = None


def upgrade():
    # Update all findings with EXCEPTION status to have RESOLVED workflow_status
    # This fixes inconsistency where some EXCEPTION findings had IGNORED workflow_status
    op.execute("""
        UPDATE findings
        SET workflow_status = 'RESOLVED',
            workflow_updated_at = NOW()
        WHERE status = 'EXCEPTION'
        AND workflow_status != 'RESOLVED'
    """)


def downgrade():
    # No downgrade - this is a data fix
    pass
