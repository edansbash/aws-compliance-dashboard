# AWS Compliance Dashboard

A local Docker Compose application for scanning AWS resources across single or multi-account environments against custom compliance rules. Provides a dashboard for viewing compliance status, managing rule exceptions, and remediating non-compliant resources.

## Features

- **100+ Compliance Rules** covering 18+ AWS services including S3, EC2, IAM, VPC, RDS, CloudTrail, SQS, SNS, Security Groups, Redshift, ELBv2, KMS, ACM, and SES
- **Compliance Packs** for grouping rules (SOC2, CIS, HIPAA, etc.)
- **Exception Management** with justifications and expiration dates
- **Automated Remediation** with real-time log streaming, color-coded output, and before/after state preview
- **Multi-Account Support** for scanning across AWS accounts via IAM role assumption
- **Scheduled Scans** with cron or interval-based recurring compliance checks
- **Audit Logging** for tracking scans, workflow changes, exceptions, and remediations
- **Real-time Scan Updates** via Server-Sent Events (SSE) for live progress monitoring
- **Slack Notifications** on scan completion with finding summaries
- **JIRA Integration** for automatic ticket creation with AWS Security Hub custom fields
- **IaC Scanning** via GitHub integration to sync Trivy/tfsec results from GitHub Code Scanning API
- **Resource Tags** displayed in findings for Terraform-managed resources and other metadata
- **Reports** for compliance report generation and export

## Tech Stack

- **Frontend**: React, TypeScript, Vite, TailwindCSS
- **Backend**: Python FastAPI
- **Database**: PostgreSQL
- **Cache/Queue**: Redis (job queues, caching, real-time streaming)
- **Infrastructure**: Docker Compose

## Prerequisites

- Docker and Docker Compose
- AWS credentials with read access to resources you want to scan

## Local Development Setup

### 1. Clone the repository

```bash
git clone https://github.com/ebashcobaltix/aws-compliance-dashboard.git
cd aws-compliance-dashboard
```

### 2. Configure AWS credentials

Copy the example environment file and add your AWS credentials:

```bash
cp .env.example .env
```

Edit `.env` and fill in your AWS credentials:

```env
AWS_ACCESS_KEY_ID=your_access_key
AWS_SECRET_ACCESS_KEY=your_secret_key
AWS_SESSION_TOKEN=optional_session_token
AWS_DEFAULT_REGION=us-east-1
```

### 3. Start the application

```bash
docker compose up -d
```

This will start:
- **Frontend** at http://localhost:5173
- **API** at http://localhost:8000
- **Worker** for background scan and remediation jobs
- **PostgreSQL** database
- **Redis** for job queues, caching, and real-time log streaming

### 4. Run database migrations

```bash
docker compose exec api alembic upgrade head
```

### 5. Sync compliance rules

Open http://localhost:5173 and navigate to the Scans page, or call the API directly:

```bash
curl -X POST http://localhost:8000/api/v1/rules/sync
```

## Common Commands

```bash
# Start all services
docker compose up -d

# View logs
docker compose logs -f

# View logs for specific service
docker compose logs -f api
docker compose logs -f frontend

# Rebuild after code changes
docker compose up -d --build

# Stop all services
docker compose down

# Stop and remove volumes (reset database)
docker compose down -v

# Run database migrations
docker compose exec api alembic upgrade head
```

## API Documentation

Once the API is running, view the interactive API docs at http://localhost:8000/docs (Swagger UI).

## Project Structure

```
aws-compliance-dashboard/
├── docker-compose.yml
├── frontend/                 # React frontend
│   ├── src/
│   │   ├── components/       # Reusable UI components (JsonDiff, etc.)
│   │   ├── pages/            # 14 page components
│   │   ├── hooks/            # Custom React hooks (useScanStatus for SSE)
│   │   ├── services/         # API client
│   │   └── types/            # TypeScript type definitions
│   └── Dockerfile
├── api/                      # FastAPI backend
│   ├── app/
│   │   ├── routers/          # 13 API endpoint modules
│   │   ├── services/         # Business logic
│   │   │   ├── rules/        # 100+ compliance rules (18 rule files)
│   │   │   ├── fetchers/     # 16 AWS resource fetchers
│   │   │   └── notifications/ # Slack and JIRA integrations
│   │   ├── models/           # 13 SQLAlchemy models
│   │   ├── schemas/          # Pydantic schemas
│   │   └── worker.py         # Background job worker
│   ├── alembic/              # Database migrations
│   └── Dockerfile
├── DESIGN.md                 # Architecture documentation
└── README.md
```

## Default Scan Regions

By default, scans run against US regions:
- us-east-1
- us-east-2
- us-west-1
- us-west-2

You can configure this in the scan settings.

## Compliance Rules Coverage

The dashboard includes 100+ compliance rules across 18+ AWS services:

| Service | Rules | Examples |
|---------|-------|----------|
| Security Groups | 17 | Unrestricted SSH/RDP, wide open ingress/egress |
| IAM | 25+ | Wildcard policies, unused credentials, overly permissive trust |
| S3 | 9 | Versioning, encryption, MFA delete, public access |
| RDS | 8 | Encryption, backup retention, public access |
| VPC | 5 | Flow logs, default security groups |
| EC2/EBS | 5 | Public IPs, EBS encryption, public AMIs |
| CloudTrail | 4 | Multi-region, log encryption, CloudWatch integration |
| SQS | 8 | Encryption, public access, dead letter queues |
| SNS | 7 | Encryption, public access, HTTPS enforcement |
| Redshift | 5 | Encryption, public access, audit logging |
| ELBv2 | 5 | Access logs, deletion protection, SSL policies |
| KMS | 1 | Key rotation |
| ACM | 1 | Certificate expiration |
| SES | 3 | DKIM, identity verification |

**20 rules include automated remediation** for common fixes like enabling encryption, versioning, and disabling public access.

For detailed architecture documentation on the scanner and remediation systems, see [DESIGN.md](DESIGN.md).

## Adding AWS Accounts

1. Navigate to **Accounts** in the dashboard
2. Click **Add Account**
3. Enter the AWS account ID and a friendly name
4. For cross-account access, configure an IAM role with appropriate permissions

## Running a Scan

1. Navigate to **Scans** in the dashboard
2. Click **New Scan**
3. Select the accounts and regions to scan
4. Click **Start Scan**

Scans run in the background. View progress on the Scans page.

## Remediation

1. Navigate to a finding detail page
2. Click **Remediate** to preview the planned changes
3. Review the before/after state
4. Click **Confirm & Execute** to apply the fix
5. Watch real-time logs as the remediation executes

Remediation logs are color-coded:
- **Green**: Success messages
- **Red**: Error messages
- **Yellow**: Warnings
- **Blue**: Info messages

## Audit Logs

All significant actions are logged to the Audit Logs page:

| Action | Description |
|--------|-------------|
| SCAN_STARTED | A compliance scan was initiated |
| SCAN_COMPLETED | A scan finished successfully |
| FINDING_ACKNOWLEDGED | Finding marked as acknowledged |
| FINDING_RESOLVED | Finding marked as resolved |
| EXCEPTION_CREATED | Exception created for a resource |
| EXCEPTION_DELETED | Exception was removed |
| REMEDIATION_STARTED | Remediation job started |
| REMEDIATION_COMPLETED | Remediation completed successfully |
| REMEDIATION_FAILED | Remediation failed with error |

Audit logs can be filtered by action type and exported to CSV.

## Slack Notifications

To enable Slack notifications for scan completions:

1. Create a Slack webhook URL in your workspace
2. Add to your `.env` file:
   ```env
   SLACK_WEBHOOK_URL=https://hooks.slack.com/services/...
   ```
3. Restart the application

Notifications include:
- Total findings count by severity
- New findings since last scan
- Regressions (previously passing resources now failing)

## JIRA Integration

Automatic JIRA ticket lifecycle management for compliance findings with AWS Security Hub custom fields.

### Setup

1. Generate an API token at https://id.atlassian.com/manage-profile/security/api-tokens
2. Add to `.env`:
   ```env
   JIRA_BASE_URL=https://yourcompany.atlassian.net
   JIRA_EMAIL=your-email@company.com
   JIRA_API_TOKEN=your-api-token
   JIRA_PROJECT_KEY=CORE
   JIRA_ISSUE_TYPE=AWS Security Hub V2 Finding
   JIRA_ASSIGNEE_EMAIL=assignee@company.com  # Optional: auto-assign new tickets
   ```
3. Restart: `docker compose up -d --build`
4. Enable in **Settings** and configure minimum severity

### Ticket Lifecycle

| Event | Action | AWS Finding Status |
|-------|--------|-------------------|
| New finding | Create ticket | NEW |
| Regression (no ticket) | Create ticket | REGRESSION |
| Regression (has ticket) | Reopen to Intake | REGRESSION |
| Remediation succeeds | Close ticket | RESOLVED |
| Rescan passes | Close ticket | RESOLVED |
| Exception created | Close ticket | EXCEPTION |
| Exception deleted | Reopen ticket | FAIL |

Tickets include severity-based due dates (Critical: 15d, High: 30d, Medium: 60d, Low: 90d) and labels for filtering (`finding-{id}`, `rule-{id}`, `severity-{level}`).

### UI Integration

JIRA ticket links displayed on Finding Detail page, Rule Findings table, and in Slack notifications.

## IaC Scanning (GitHub Integration)

Sync Trivy/tfsec security scan results from GitHub Code Scanning API to track infrastructure-as-code misconfigurations alongside runtime findings.

> **Note**: IaC findings are tracked separately from runtime AWS findings and do not count toward the AWS compliance score.

### Prerequisites

1. **Trivy** running in your GitHub Actions workflow with SARIF output uploaded to GitHub Code Scanning
2. **GitHub Code Scanning** enabled for your repository
3. A **GitHub Personal Access Token** with `security_events:read` permission

### Setup

1. Generate a Personal Access Token at https://github.com/settings/tokens with `security_events:read` scope
2. Add to `.env`:
   ```env
   GITHUB_TOKEN=ghp_your_personal_access_token
   IAC_GITHUB_OWNER=YourOrg
   IAC_GITHUB_REPO=your-iac-repo
   IAC_GITHUB_BRANCH=main
   ```
3. Restart: `docker compose up -d --build`
4. Navigate to **Settings** and enable the IaC integration

### Example GitHub Actions Workflow

```yaml
name: Trivy IaC Scan

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  trivy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Run Trivy vulnerability scanner
        uses: aquasecurity/trivy-action@master
        with:
          scan-type: 'config'
          scan-ref: '.'
          format: 'sarif'
          output: 'trivy-results.sarif'
          severity: 'CRITICAL,HIGH,MEDIUM,LOW'

      - name: Upload Trivy scan results to GitHub Security
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: 'trivy-results.sarif'
```

### Syncing Findings

IaC findings are synced manually:

1. Navigate to **Settings** → **IaC Scanning**
2. Click **Trigger Manual Sync**
3. View findings on the **IaC** page

### IaC Finding States

| State | Description |
|-------|-------------|
| Open | Active security issue in the codebase |
| Fixed | Issue was resolved (code changed) |
| Dismissed | Alert dismissed in GitHub (false positive, won't fix, etc.) |

### What's Synced

Each IaC finding includes:
- File path and line number
- Severity (Critical, High, Medium, Low)
- Rule ID and description
- Link to GitHub alert
- Trivy rule documentation link
- Fixed/dismissed timestamps

## License

Private - Cobaltix
