"""Add jira_ticket_key to findings

Revision ID: 007
Revises: 006
Create Date: 2024-01-01 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '007'
down_revision = '006'
branch_labels = None
depends_on = None


def upgrade():
    op.execute("""
        ALTER TABLE findings
        ADD COLUMN IF NOT EXISTS jira_ticket_key VARCHAR(50) DEFAULT NULL
    """)
    # Add index for faster lookups
    op.execute("""
        CREATE INDEX IF NOT EXISTS ix_findings_jira_ticket_key
        ON findings (jira_ticket_key)
        WHERE jira_ticket_key IS NOT NULL
    """)


def downgrade():
    op.drop_index('ix_findings_jira_ticket_key', 'findings')
    op.drop_column('findings', 'jira_ticket_key')
