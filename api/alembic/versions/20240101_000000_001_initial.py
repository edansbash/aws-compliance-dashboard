"""Initial migration

Revision ID: 001
Revises:
Create Date: 2024-01-01 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = '001'
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # AWS Accounts table
    op.create_table(
        'aws_accounts',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('account_id', sa.String(12), nullable=False, unique=True),
        sa.Column('name', sa.String(255), nullable=False),
        sa.Column('role_arn', sa.String(255), nullable=True),
        sa.Column('external_id', sa.String(255), nullable=True),
        sa.Column('is_active', sa.Boolean(), default=True),
        sa.Column('created_at', sa.DateTime(), server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(), server_default=sa.func.now(), onupdate=sa.func.now()),
    )
    op.create_index('ix_aws_accounts_account_id', 'aws_accounts', ['account_id'])

    # Rules table
    op.create_table(
        'rules',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('rule_id', sa.String(100), nullable=False, unique=True),
        sa.Column('name', sa.String(255), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('resource_type', sa.String(100), nullable=False),
        sa.Column('severity', sa.String(20), nullable=False),
        sa.Column('is_enabled', sa.Boolean(), default=True),
        sa.Column('has_remediation', sa.Boolean(), default=False),
        sa.Column('created_at', sa.DateTime(), server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(), server_default=sa.func.now(), onupdate=sa.func.now()),
    )
    op.create_index('ix_rules_rule_id', 'rules', ['rule_id'])
    op.create_index('ix_rules_resource_type', 'rules', ['resource_type'])

    # Scans table
    op.create_table(
        'scans',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('status', sa.String(20), nullable=False, default='pending'),
        sa.Column('account_ids', postgresql.JSONB(), nullable=False, server_default='[]'),
        sa.Column('regions', postgresql.JSONB(), nullable=False, server_default='[]'),
        sa.Column('rule_ids', postgresql.JSONB(), nullable=True),
        sa.Column('total_resources', sa.Integer(), default=0),
        sa.Column('total_findings', sa.Integer(), default=0),
        sa.Column('started_at', sa.DateTime(), nullable=True),
        sa.Column('completed_at', sa.DateTime(), nullable=True),
        sa.Column('error_message', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(), server_default=sa.func.now()),
    )
    op.create_index('ix_scans_status', 'scans', ['status'])
    op.create_index('ix_scans_created_at', 'scans', ['created_at'])

    # Findings table
    op.create_table(
        'findings',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('scan_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('scans.id'), nullable=False),
        sa.Column('rule_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('rules.id'), nullable=False),
        sa.Column('resource_id', sa.String(500), nullable=False),
        sa.Column('resource_name', sa.String(255), nullable=True),
        sa.Column('resource_type', sa.String(100), nullable=False),
        sa.Column('account_id', sa.String(12), nullable=False),
        sa.Column('region', sa.String(50), nullable=False),
        sa.Column('status', sa.String(20), nullable=False),
        sa.Column('workflow_status', sa.String(20), default='open'),
        sa.Column('workflow_notes', sa.Text(), nullable=True),
        sa.Column('workflow_updated_by', sa.String(255), nullable=True),
        sa.Column('workflow_updated_at', sa.DateTime(), nullable=True),
        sa.Column('details', postgresql.JSONB(), nullable=True),
        sa.Column('created_at', sa.DateTime(), server_default=sa.func.now()),
    )
    op.create_index('ix_findings_scan_id', 'findings', ['scan_id'])
    op.create_index('ix_findings_rule_id', 'findings', ['rule_id'])
    op.create_index('ix_findings_resource_id', 'findings', ['resource_id'])
    op.create_index('ix_findings_account_id', 'findings', ['account_id'])
    op.create_index('ix_findings_status', 'findings', ['status'])
    op.create_index('ix_findings_workflow_status', 'findings', ['workflow_status'])

    # Compliance Exceptions table
    op.create_table(
        'compliance_exceptions',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('rule_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('rules.id'), nullable=False),
        sa.Column('scope', sa.String(20), nullable=False),
        sa.Column('resource_id', sa.String(500), nullable=True),
        sa.Column('account_id', sa.String(12), nullable=True),
        sa.Column('justification', sa.Text(), nullable=False),
        sa.Column('created_by', sa.String(255), nullable=False),
        sa.Column('expires_at', sa.DateTime(), nullable=True),
        sa.Column('created_at', sa.DateTime(), server_default=sa.func.now()),
    )
    op.create_index('ix_compliance_exceptions_rule_id', 'compliance_exceptions', ['rule_id'])
    op.create_index('ix_compliance_exceptions_scope', 'compliance_exceptions', ['scope'])
    op.create_index('ix_compliance_exceptions_resource_id', 'compliance_exceptions', ['resource_id'])

    # Remediation Jobs table
    op.create_table(
        'remediation_jobs',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('finding_ids', postgresql.JSONB(), nullable=False, server_default='[]'),
        sa.Column('status', sa.String(20), nullable=False, server_default='RUNNING'),
        sa.Column('confirmed_by', sa.String(255), nullable=False),
        sa.Column('started_at', sa.DateTime(), server_default=sa.func.now()),
        sa.Column('completed_at', sa.DateTime(), nullable=True),
        sa.Column('successful_count', sa.Integer(), server_default='0'),
        sa.Column('failed_count', sa.Integer(), server_default='0'),
        sa.Column('skipped_count', sa.Integer(), server_default='0'),
        sa.Column('created_at', sa.DateTime(), server_default=sa.func.now()),
    )
    op.create_index('ix_remediation_jobs_status', 'remediation_jobs', ['status'])

    # Remediation Logs table
    op.create_table(
        'remediation_logs',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('job_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('remediation_jobs.id', ondelete='CASCADE'), nullable=False),
        sa.Column('resource_id', sa.String(500), nullable=True),
        sa.Column('level', sa.String(20), nullable=False, server_default='INFO'),
        sa.Column('message', sa.Text(), nullable=False),
        sa.Column('details', postgresql.JSONB(), nullable=True),
        sa.Column('created_at', sa.DateTime(), server_default=sa.func.now()),
    )
    op.create_index('ix_remediation_logs_job_id', 'remediation_logs', ['job_id'])

    # Audit Logs table
    op.create_table(
        'audit_logs',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('action', sa.String(50), nullable=False),
        sa.Column('resource_id', sa.String(500), nullable=True),
        sa.Column('resource_type', sa.String(100), nullable=True),
        sa.Column('account_id', sa.String(12), nullable=True),
        sa.Column('region', sa.String(50), nullable=True),
        sa.Column('rule_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('rules.id', ondelete='SET NULL'), nullable=True),
        sa.Column('performed_by', sa.String(255), nullable=False),
        sa.Column('job_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('remediation_jobs.id', ondelete='SET NULL'), nullable=True),
        sa.Column('before_state', postgresql.JSONB(), nullable=True),
        sa.Column('after_state', postgresql.JSONB(), nullable=True),
        sa.Column('details', postgresql.JSONB(), nullable=True),
        sa.Column('created_at', sa.DateTime(), server_default=sa.func.now()),
    )
    op.create_index('ix_audit_logs_action', 'audit_logs', ['action'])
    op.create_index('ix_audit_logs_resource_type', 'audit_logs', ['resource_type'])
    op.create_index('ix_audit_logs_created_at', 'audit_logs', ['created_at'])


def downgrade() -> None:
    op.drop_table('audit_logs')
    op.drop_table('remediation_logs')
    op.drop_table('remediation_jobs')
    op.drop_table('compliance_exceptions')
    op.drop_table('findings')
    op.drop_table('scans')
    op.drop_table('rules')
    op.drop_table('aws_accounts')
