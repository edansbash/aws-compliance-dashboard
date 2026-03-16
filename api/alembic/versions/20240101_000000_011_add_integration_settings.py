"""Add integration_settings table for managing integration enabled state

Revision ID: 011
Revises: 010
Create Date: 2024-01-01 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID
import uuid


# revision identifiers, used by Alembic.
revision = '011'
down_revision = '010'
branch_labels = None
depends_on = None


def upgrade():
    # Create integration_settings table
    op.create_table(
        'integration_settings',
        sa.Column('id', UUID(as_uuid=True), primary_key=True, default=uuid.uuid4),
        sa.Column('integration_type', sa.String(50), nullable=False, unique=True),
        sa.Column('is_enabled', sa.Boolean, nullable=False, server_default='true'),
        sa.Column('created_at', sa.DateTime, nullable=False),
        sa.Column('updated_at', sa.DateTime, nullable=False),
    )

    # Insert default settings for each integration (all enabled by default)
    op.execute("""
        INSERT INTO integration_settings (id, integration_type, is_enabled, created_at, updated_at)
        VALUES
            (gen_random_uuid(), 'slack', true, NOW(), NOW()),
            (gen_random_uuid(), 'jira', true, NOW(), NOW()),
            (gen_random_uuid(), 'iac', true, NOW(), NOW())
    """)


def downgrade():
    op.drop_table('integration_settings')
