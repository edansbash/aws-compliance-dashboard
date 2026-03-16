"""Add additional fields to iac_findings table

Revision ID: 010
Revises: 009
Create Date: 2024-01-01 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '010'
down_revision = '009'
branch_labels = None
depends_on = None


def upgrade():
    # Add new columns to iac_findings table
    op.add_column('iac_findings', sa.Column('trivy_rule_name', sa.String(100), nullable=True))
    op.add_column('iac_findings', sa.Column('trivy_help_uri', sa.String(500), nullable=True))
    op.add_column('iac_findings', sa.Column('tool_name', sa.String(50), nullable=True))
    op.add_column('iac_findings', sa.Column('fixed_at', sa.DateTime, nullable=True))


def downgrade():
    op.drop_column('iac_findings', 'fixed_at')
    op.drop_column('iac_findings', 'tool_name')
    op.drop_column('iac_findings', 'trivy_help_uri')
    op.drop_column('iac_findings', 'trivy_rule_name')
