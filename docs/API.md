# API Reference

This document describes the REST API endpoints for the AWS Compliance Dashboard.

**Base URL**: `/api/v1`

## Endpoints

### Health & System

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | /health | Health check (DB, AWS connectivity) |
| GET | /search | Global search across findings |

### Accounts

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | /accounts | List all AWS accounts |
| POST | /accounts | Add new AWS account |
| GET | /accounts/{id} | Get account details |
| PUT | /accounts/{id} | Update account |
| DELETE | /accounts/{id} | Remove account |
| POST | /accounts/{id}/test | Test account connectivity |

### Scans

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | /scans | List scan history |
| POST | /scans | Trigger new scan |
| GET | /scans/{id} | Get scan details |
| GET | /scans/{id}/findings | Get findings for scan |
| GET | /scans/{id}/status/stream | Stream scan progress via SSE |
| POST | /scans/{id}/cancel | Cancel running scan |
| DELETE | /scans/{id} | Delete scan and findings |

### Findings

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | /findings | List findings (with filters) |
| GET | /findings/{id} | Get finding details |
| PATCH | /findings/{id}/workflow | Update workflow status |
| POST | /findings/{id}/rescan | Rescan single resource to verify fix |
| GET | /findings/summary | Aggregated compliance summary |

### Rules

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | /rules | List all rules |
| POST | /rules/sync | Sync rules from code to database |
| GET | /rules/{id} | Get rule details |
| PUT | /rules/{id} | Update rule (enable/disable) |
| GET | /rules/{id}/findings | Get findings for rule |

### Exceptions

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | /exceptions | List all exceptions |
| POST | /exceptions | Create exception (single) |
| POST | /exceptions/bulk | Create exceptions for multiple findings |
| GET | /exceptions/{id} | Get exception details |
| DELETE | /exceptions/{id} | Remove exception |

### Remediation

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | /remediation | List remediation jobs |
| POST | /remediation/preview | Preview planned changes |
| POST | /remediation | Create and queue remediation jobs |
| GET | /remediation/{id} | Get job details |
| GET | /remediation/{id}/logs | Get execution logs |
| GET | /remediation/{id}/logs/stream | Stream logs via SSE |
| GET | /remediation/batch/{batch_id} | Get all jobs in a batch |

### Audit Logs

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | /audit-logs | List audit logs (with filters) |
| GET | /audit-logs/{id} | Get audit log details |
| GET | /audit-logs/export | Export audit logs to CSV |

### Configuration

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | /config/regions | Get configured regions |
| PUT | /config/regions | Update scan regions |

### Scheduled Scans

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | /schedules | List all scheduled scans |
| POST | /schedules | Create scheduled scan |
| GET | /schedules/{id} | Get schedule details |
| PUT | /schedules/{id} | Update schedule |
| DELETE | /schedules/{id} | Delete schedule |
| POST | /schedules/{id}/trigger | Trigger immediate scan |

### Compliance Packs

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | /compliance-packs | List all compliance packs |
| POST | /compliance-packs | Create compliance pack |
| GET | /compliance-packs/{id} | Get pack details with rules |
| PUT | /compliance-packs/{id} | Update pack |
| DELETE | /compliance-packs/{id} | Delete pack |
| POST | /compliance-packs/{id}/enable | Enable pack and its rules |
| POST | /compliance-packs/{id}/disable | Disable pack and its rules |

### Notifications (Slack)

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | /notifications/slack | Get Slack config |
| PUT | /notifications/slack | Update Slack config |
| POST | /notifications/slack/test | Send test notification |

### Notifications (JIRA)

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | /notifications/jira | Get JIRA config |
| PUT | /notifications/jira | Update JIRA config |
| POST | /notifications/jira/test | Test JIRA connection |

### Reports

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | /reports | List generated reports |
| POST | /reports | Generate new report |
| GET | /reports/{id} | Get report details |
| GET | /reports/{id}/download | Download report file |
| DELETE | /reports/{id} | Delete report |

---

## Request/Response Examples

### Health Check

```http
GET /api/v1/health
```

Response:
```json
{
  "status": "healthy",
  "version": "1.0.0",
  "checks": {
    "database": "ok",
    "aws_credentials": "ok"
  },
  "timestamp": "2024-01-15T10:00:00Z"
}
```

### Global Search

```http
GET /api/v1/search?q=prod-bucket&type=findings&page=1&per_page=20
```

Response:
```json
{
  "items": [
    {
      "type": "finding",
      "id": "finding-uuid",
      "resource_name": "prod-bucket-logs",
      "resource_id": "arn:aws:s3:::prod-bucket-logs",
      "account_id": "123456789012",
      "region": "us-east-1",
      "status": "FAIL",
      "rule_name": "S3 Bucket Versioning"
    }
  ],
  "total": 3,
  "page": 1,
  "per_page": 20
}
```

### Create Scan

```http
POST /api/v1/scans
Content-Type: application/json

{
  "account_ids": ["uuid-1", "uuid-2"],
  "regions": ["us-east-1", "us-west-2"],
  "rule_ids": ["uuid-1"]
}
```

All fields are optional:
- `account_ids`: Omit to scan all active accounts
- `regions`: Omit to use default regions
- `rule_ids`: Omit to run all enabled rules

Response:
```json
{
  "id": "scan-uuid",
  "status": "PENDING",
  "accounts": [...],
  "regions": ["us-east-1", "us-west-2"],
  "rules": [...],
  "resource_types": ["AWS::S3::Bucket"],
  "started_at": null,
  "created_at": "2024-01-15T10:00:00Z"
}
```

**Rule-Specific Scanning**: When `rule_ids` is provided, the scan only fetches resources relevant to those rules:
- S3 rules only → only S3 buckets scanned
- EC2 rules only → only EC2 instances scanned
- Both → both resource types scanned

### List Findings with Filters

```http
GET /api/v1/findings?status=FAIL&severity=HIGH&account_id=123456789012&workflow_status=OPEN&page=1&per_page=20
```

Response:
```json
{
  "items": [
    {
      "id": "finding-uuid",
      "rule": {
        "id": "rule-uuid",
        "rule_id": "S3_VERSIONING",
        "name": "S3 Bucket Versioning",
        "severity": "MEDIUM"
      },
      "resource_id": "arn:aws:s3:::my-bucket",
      "resource_name": "my-bucket",
      "resource_type": "AWS::S3::Bucket",
      "account_id": "123456789012",
      "region": "us-east-1",
      "status": "FAIL",
      "workflow_status": "OPEN",
      "workflow_notes": null,
      "details": {
        "versioning_status": "Disabled"
      },
      "created_at": "2024-01-15T10:05:00Z"
    }
  ],
  "total": 150,
  "page": 1,
  "per_page": 20,
  "pages": 8
}
```

### Update Finding Workflow Status

```http
PATCH /api/v1/findings/{id}/workflow
Content-Type: application/json

{
  "workflow_status": "IN_PROGRESS",
  "notes": "Ticket JIRA-123 created, fix scheduled for next sprint"
}
```

Response:
```json
{
  "id": "finding-uuid",
  "workflow_status": "IN_PROGRESS",
  "workflow_updated_by": "user@example.com",
  "workflow_updated_at": "2024-01-15T10:30:00Z",
  "workflow_notes": "Ticket JIRA-123 created, fix scheduled for next sprint"
}
```

### Rescan Single Resource

```http
POST /api/v1/findings/{id}/rescan
```

Response:
```json
{
  "finding_id": "finding-uuid",
  "previous_status": "FAIL",
  "new_status": "PASS",
  "resource_id": "arn:aws:s3:::my-bucket",
  "message": "Resource now compliant",
  "scanned_at": "2024-01-15T10:35:00Z"
}
```

### Create Exception

```http
POST /api/v1/exceptions
Content-Type: application/json

{
  "scope": "resource",
  "rule_id": "rule-uuid",
  "resource_id": "arn:aws:s3:::my-bucket",
  "justification": "This bucket contains only public marketing assets",
  "expires_at": "2024-06-01T00:00:00Z"
}
```

### Bulk Create Exceptions

```http
POST /api/v1/exceptions/bulk
Content-Type: application/json

{
  "finding_ids": ["uuid-1", "uuid-2", "uuid-3"],
  "justification": "Development account - non-production workloads",
  "expires_at": "2024-06-01T00:00:00Z"
}
```

Response:
```json
{
  "created": 3,
  "exceptions": [
    {"id": "exc-uuid-1", "finding_id": "uuid-1"},
    {"id": "exc-uuid-2", "finding_id": "uuid-2"},
    {"id": "exc-uuid-3", "finding_id": "uuid-3"}
  ]
}
```

---

## Pagination

All list endpoints support pagination:

| Parameter | Default | Description |
|-----------|---------|-------------|
| page | 1 | Page number |
| per_page | 20 | Items per page (max 100) |

Response includes:
```json
{
  "items": [...],
  "total": 150,
  "page": 1,
  "per_page": 20,
  "pages": 8
}
```

---

## Error Responses

All errors follow this format:

```json
{
  "detail": "Error message describing what went wrong"
}
```

Common HTTP status codes:
- `400` - Bad request (validation error)
- `404` - Resource not found
- `422` - Unprocessable entity
- `500` - Internal server error
