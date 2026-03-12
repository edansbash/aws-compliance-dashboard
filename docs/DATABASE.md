# Database Schema

This document describes the PostgreSQL database schema for the AWS Compliance Dashboard.

## Entity Relationship Diagram

```
┌─────────────────┐       ┌─────────────────┐
│   aws_accounts  │       │     rules       │
├─────────────────┤       ├─────────────────┤
│ id (PK)         │       │ id (PK)         │
│ account_id      │       │ rule_id (unique)│
│ name            │       │ name            │
│ role_arn        │       │ description     │
│ external_id     │       │ resource_type   │
│ is_active       │       │ severity        │
│ created_at      │       │ is_enabled      │
│ updated_at      │       │ created_at      │
└────────┬────────┘       └────────┬────────┘
         │                         │
         │    ┌─────────────────┐  │
         │    │     scans       │  │
         │    ├─────────────────┤  │
         │    │ id (PK)         │  │
         └───▶│ account_id (FK) │  │
              │ status          │  │
              │ regions         │  │
              │ started_at      │  │
              │ completed_at    │  │
              │ total_resources │  │
              │ total_findings  │  │
              └────────┬────────┘  │
                       │           │
         ┌─────────────┘           │
         ▼                         │
┌─────────────────┐                │
│    findings     │                │
├─────────────────┤                │
│ id (PK)         │                │
│ scan_id (FK)    │◀───────────────┘
│ rule_id (FK)    │
│ resource_id     │
│ resource_name   │
│ resource_type   │
│ account_id      │
│ region          │
│ status          │
│ details (JSON)  │
│ created_at      │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│   exceptions    │
├─────────────────┤
│ id (PK)         │
│ finding_id (FK) │  -- nullable, for resource-specific
│ rule_id (FK)    │  -- for rule-wide exceptions
│ resource_id     │  -- nullable
│ account_id      │  -- nullable, for account-wide
│ scope           │  -- 'resource', 'rule', 'account'
│ justification   │
│ created_by      │
│ expires_at      │  -- nullable
│ created_at      │
└─────────────────┘
```

---

## Tables

### aws_accounts

Stores AWS account configurations for scanning.

| Column | Type | Description |
|--------|------|-------------|
| id | UUID | Primary key |
| account_id | VARCHAR(12) | AWS Account ID |
| name | VARCHAR | Friendly name |
| role_arn | VARCHAR | IAM role ARN for cross-account access |
| external_id | VARCHAR | External ID for role assumption |
| is_active | BOOLEAN | Whether to include in scans |
| created_at | TIMESTAMP | Creation timestamp |
| updated_at | TIMESTAMP | Last update timestamp |

### rules

Registry of compliance rules (synced from code).

| Column | Type | Description |
|--------|------|-------------|
| id | UUID | Primary key |
| rule_id | VARCHAR | Unique rule identifier (e.g., "S3_VERSIONING") |
| name | VARCHAR | Human-readable name |
| description | TEXT | Full description of what rule checks |
| resource_type | VARCHAR | AWS resource type (e.g., "AWS::S3::Bucket") |
| severity | ENUM | CRITICAL, HIGH, MEDIUM, LOW, INFO |
| is_enabled | BOOLEAN | Whether rule is active |
| has_remediation | BOOLEAN | Whether rule has auto-remediation capability |
| remediation_tested | BOOLEAN | Whether remediation has been verified in production |
| created_at | TIMESTAMP | Creation timestamp |

### scans

Scan execution records.

| Column | Type | Description |
|--------|------|-------------|
| id | UUID | Primary key |
| account_id | UUID | FK to aws_accounts |
| status | ENUM | QUEUED, RUNNING, COMPLETED, FAILED |
| regions | JSONB | Array of regions scanned |
| started_at | TIMESTAMP | Scan start time |
| completed_at | TIMESTAMP | Scan completion time |
| total_resources | INTEGER | Count of resources scanned |
| total_findings | INTEGER | Count of findings generated |

### findings

Individual compliance findings.

| Column | Type | Description |
|--------|------|-------------|
| id | UUID | Primary key |
| scan_id | UUID | FK to scans |
| rule_id | UUID | FK to rules |
| resource_id | VARCHAR | AWS resource ARN or ID |
| resource_name | VARCHAR | Human-readable resource name |
| resource_type | VARCHAR | AWS resource type |
| account_id | VARCHAR(12) | AWS account ID |
| region | VARCHAR | AWS region |
| status | ENUM | FAIL, PASS, ERROR, EXCEPTION |
| workflow_status | ENUM | OPEN, ACKNOWLEDGED, PLANNED, IN_PROGRESS, RESOLVED |
| workflow_updated_by | VARCHAR | User who last updated workflow status |
| workflow_updated_at | TIMESTAMP | When workflow status was last updated |
| workflow_notes | TEXT | Optional notes about remediation progress |
| details | JSONB | Additional finding details |
| created_at | TIMESTAMP | Finding creation time |
| last_scanned_at | TIMESTAMP | Last time resource was scanned |
| jira_ticket_key | VARCHAR(50) | Associated JIRA ticket key (indexed) |

### exceptions

Exception records for ignored findings.

| Column | Type | Description |
|--------|------|-------------|
| id | UUID | Primary key |
| finding_id | UUID | FK to findings (nullable) |
| rule_id | UUID | FK to rules |
| resource_id | VARCHAR | Specific resource (nullable) |
| account_id | VARCHAR(12) | Specific account (nullable) |
| scope | ENUM | RESOURCE, RULE, ACCOUNT |
| justification | TEXT | Required explanation |
| created_by | VARCHAR | User who created exception |
| expires_at | TIMESTAMP | Optional expiration |
| created_at | TIMESTAMP | Creation timestamp |

### remediation_jobs

Tracks remediation job execution. One job per finding for granular tracking.

| Column | Type | Description |
|--------|------|-------------|
| id | UUID | Primary key |
| status | ENUM | QUEUED, RUNNING, COMPLETED, FAILED, CANCELLED |
| finding_id | UUID | FK to findings (one job per finding) |
| batch_id | UUID | Groups related jobs from same request |
| confirmed_by | VARCHAR | User who confirmed execution |
| started_at | TIMESTAMP | Execution start time |
| completed_at | TIMESTAMP | Execution completion time |
| error_message | TEXT | Error details if failed |
| created_at | TIMESTAMP | Job creation time |

### remediation_logs

Real-time logs for remediation execution.

| Column | Type | Description |
|--------|------|-------------|
| id | UUID | Primary key |
| job_id | UUID | FK to remediation_jobs |
| resource_id | VARCHAR | Resource being remediated |
| level | ENUM | DEBUG, INFO, WARN, ERROR, SUCCESS |
| message | TEXT | Log message |
| details | JSONB | Additional structured data |
| created_at | TIMESTAMP | Log timestamp |

### audit_logs

Comprehensive audit trail for all resource modifications.

| Column | Type | Description |
|--------|------|-------------|
| id | UUID | Primary key |
| action | VARCHAR(50) | Action type (see Audit Events below) |
| resource_id | VARCHAR | AWS resource ARN/ID affected |
| resource_type | VARCHAR | AWS resource type |
| account_id | VARCHAR(12) | AWS account ID |
| region | VARCHAR | AWS region |
| rule_id | UUID | FK to rules (nullable) |
| performed_by | VARCHAR | User who performed action |
| job_id | UUID | FK to remediation_jobs (nullable) |
| before_state | JSONB | Resource state before change |
| after_state | JSONB | Resource state after change |
| details | JSONB | Additional context |
| created_at | TIMESTAMP | When action occurred |

### scheduled_scans

Configuration for recurring compliance scans.

| Column | Type | Description |
|--------|------|-------------|
| id | UUID | Primary key |
| name | VARCHAR | Schedule name |
| description | TEXT | Optional description |
| account_ids | JSONB | Array of account UUIDs to scan |
| regions | JSONB | Array of regions to scan |
| rule_ids | JSONB | Optional array of rule UUIDs (null = all) |
| schedule_type | ENUM | CRON, INTERVAL |
| schedule_expression | VARCHAR | Cron expression or interval in minutes |
| timezone | VARCHAR | Timezone for cron (default: UTC) |
| enabled | BOOLEAN | Whether schedule is active |
| last_run_at | TIMESTAMP | Last execution time |
| next_run_at | TIMESTAMP | Next scheduled execution |
| last_scan_id | UUID | ID of most recent scan |
| created_by | VARCHAR | User who created schedule |
| created_at | TIMESTAMP | Creation timestamp |
| updated_at | TIMESTAMP | Last update timestamp |

### compliance_packs

Rule groupings for compliance frameworks (SOC2, CIS, HIPAA, etc.).

| Column | Type | Description |
|--------|------|-------------|
| id | UUID | Primary key |
| name | VARCHAR | Pack name (e.g., "SOC2", "CIS AWS") |
| description | TEXT | Description of compliance framework |
| is_enabled | BOOLEAN | Whether pack is active |
| created_at | TIMESTAMP | Creation timestamp |
| updated_at | TIMESTAMP | Last update timestamp |

### compliance_pack_rules

Many-to-many relationship between packs and rules.

| Column | Type | Description |
|--------|------|-------------|
| compliance_pack_id | UUID | FK to compliance_packs |
| rule_id | UUID | FK to rules |

### notification_configs

Slack notification configuration.

| Column | Type | Description |
|--------|------|-------------|
| id | UUID | Primary key |
| config_key | VARCHAR | Config identifier (e.g., "slack") |
| webhook_url | TEXT | Slack webhook URL |
| is_enabled | BOOLEAN | Whether notifications are active |
| min_severity | VARCHAR | Minimum severity to notify |
| notify_on_new_findings | BOOLEAN | Notify on new findings |
| notify_on_regression | BOOLEAN | Notify on regressions |
| notify_on_scan_complete | BOOLEAN | Notify on scan completion |
| created_at | TIMESTAMP | Creation timestamp |
| updated_at | TIMESTAMP | Last update timestamp |

### jira_configs

JIRA ticket integration configuration.

| Column | Type | Description |
|--------|------|-------------|
| id | UUID | Primary key |
| config_key | VARCHAR | Config identifier (e.g., "jira") |
| base_url | TEXT | JIRA instance URL |
| email | TEXT | JIRA account email |
| api_token | TEXT | JIRA API token (encrypted) |
| project_key | VARCHAR | JIRA project key |
| issue_type | VARCHAR | Issue type for tickets |
| is_enabled | BOOLEAN | Whether integration is active |
| min_severity | VARCHAR | Minimum severity to create tickets |
| notify_on_new_findings | BOOLEAN | Create tickets for new findings |
| notify_on_regression | BOOLEAN | Create tickets for regressions |
| created_at | TIMESTAMP | Creation timestamp |
| updated_at | TIMESTAMP | Last update timestamp |

### reports

Generated compliance reports.

| Column | Type | Description |
|--------|------|-------------|
| id | UUID | Primary key |
| report_type | ENUM | DASHBOARD_PDF, FINDINGS_EXCEL, EXECUTIVE_SUMMARY |
| format | ENUM | PDF, EXCEL, CSV |
| status | ENUM | PENDING, GENERATING, COMPLETED, FAILED |
| scan_id | UUID | FK to scans (nullable) |
| filters | JSONB | Applied filters |
| file_path | VARCHAR | Path to generated file |
| file_size | INTEGER | File size in bytes |
| error_message | VARCHAR | Error details if failed |
| created_at | TIMESTAMP | Creation timestamp |
| completed_at | TIMESTAMP | Completion timestamp |

---

## Enums

### FindingStatus
- `PASS` - Resource is compliant
- `FAIL` - Resource is non-compliant
- `ERROR` - Rule evaluation failed
- `EXCEPTION` - Non-compliant but has active exception

### WorkflowStatus
- `OPEN` - New finding, not yet reviewed
- `ACKNOWLEDGED` - Reviewed by user
- `PLANNED` - Remediation planned
- `IN_PROGRESS` - Remediation in progress
- `RESOLVED` - Issue fixed or resource deleted

### ScanStatus
- `QUEUED` - Job in Redis queue
- `RUNNING` - Worker actively processing
- `COMPLETED` - All scans successful
- `FAILED` - Error or cancellation

### RemediationStatus
- `QUEUED` - Job in Redis queue waiting for worker
- `RUNNING` - Currently executing
- `COMPLETED` - Successfully completed
- `FAILED` - Execution failed
- `CANCELLED` - Cancelled by user

### Severity
- `CRITICAL` - Immediate action required
- `HIGH` - High priority fix
- `MEDIUM` - Standard priority
- `LOW` - Low priority
- `INFO` - Informational only

### LogLevel
- `DEBUG` - Debug information
- `INFO` - General information
- `WARN` - Warning
- `ERROR` - Error occurred
- `SUCCESS` - Operation succeeded

---

## Audit Events

| Action | Description |
|--------|-------------|
| SCAN_STARTED | A compliance scan was initiated |
| SCAN_COMPLETED | A compliance scan finished successfully |
| FINDING_ACKNOWLEDGED | Finding workflow status changed to ACKNOWLEDGED |
| FINDING_RESOLVED | Finding workflow status changed to RESOLVED |
| EXCEPTION_CREATED | Exception was created for a resource/rule |
| EXCEPTION_DELETED | Exception was removed |
| REMEDIATION_STARTED | Remediation job started executing |
| REMEDIATION_COMPLETED | Remediation job completed successfully |
| REMEDIATION_FAILED | Remediation job failed |
| ACCOUNT_ADDED | AWS account was added |
| ACCOUNT_REMOVED | AWS account was removed |

---

## Indexes

Key indexes for performance:

- `findings.jira_ticket_key` - Fast JIRA ticket lookups
- `findings(rule_id, resource_id, account_id, region)` - Upsert lookups
- `exceptions(rule_id, resource_id, account_id)` - Exception matching
- `audit_logs(action, created_at)` - Audit log filtering

---

## Migrations

Database migrations are managed with Alembic:

```bash
# Run migrations
docker compose exec api alembic upgrade head

# Create new migration
docker compose exec api alembic revision --autogenerate -m "description"

# Rollback one migration
docker compose exec api alembic downgrade -1
```
