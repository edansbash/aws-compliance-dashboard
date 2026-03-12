# AWS Compliance Dashboard - Design Document

## 1. Overview

### 1.1 Purpose

The AWS Compliance Dashboard is a self-hosted application for scanning AWS resources against custom compliance rules. It provides visibility into compliance status across single or multi-account AWS environments, allows users to manage exceptions, and supports automated remediation of non-compliant resources.

### 1.2 Goals

- Scan AWS resources across multiple accounts and regions
- Evaluate resources against 100+ customizable compliance rules
- Display compliance findings in a clear dashboard interface
- Allow exceptions with documented justification and expiration
- Automated remediation with real-time progress streaming
- JIRA integration for ticket lifecycle management
- Slack notifications for scan completions and regressions

### 1.3 Non-Goals

- Real-time continuous monitoring (batch scans only)
- Multi-tenant SaaS deployment
- Custom rule authoring via UI (rules defined in code)

---

## 2. Architecture

### 2.1 High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              Docker Compose                                 │
│                                                                             │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────────────┐              │
│  │  Frontend   │───▶│    API      │───▶│     PostgreSQL      │              │
│  │  (React)    │    │  (FastAPI)  │    │     Port 5432       │              │
│  │  Port 3000  │    │  Port 8000  │    └─────────────────────┘              │
│  └─────────────┘    └──────┬──────┘                                         │
│                            │                                                │
│                            ▼                                                │
│                     ┌─────────────┐                                         │
│                     │    Redis    │◀──────────────────────┐                 │
│                     │  Port 6379  │                       │                 │
│                     │             │                       │                 │
│                     │ • Cache     │                       │                 │
│                     │ • Job Queue │                       │                 │
│                     └──────┬──────┘                       │                 │
│                            │                              │                 │
│                            │ (pull jobs)                  │                 │
│                            ▼                              │                 │
│                     ┌─────────────┐                       │                 │
│                     │   Worker    │───────────────────────┘                 │
│                     │  (Python)   │     (update status)                     │
│                     │             │                                         │
│                     │ • Scan Jobs │                                         │
│                     │ • Remediate │                                         │
│                     └──────┬──────┘                                         │
│                            │                                                │
│                            ▼                                                │
│                     ┌─────────────┐                                         │
│                     │  AWS APIs   │                                         │
│                     │ (External)  │                                         │
│                     └─────────────┘                                         │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 2.2 Component Responsibilities

**Frontend (React)**
- Dashboard views for compliance status
- Scan management (trigger, view history)
- Exception management with justification
- Resource detail views
- Account/region configuration

**API (FastAPI)**
- REST API for all frontend operations
- Job queue management (enqueue scan/remediation jobs)
- Exception and finding management
- Real-time job status via Redis pub/sub

**Worker (Python)**
- Pulls jobs from Redis queues
- Executes scan jobs (AWS resource scanning via boto3)
- Executes remediation jobs (AWS resource modifications)
- Updates job status and results in PostgreSQL
- Publishes real-time progress updates to Redis

**Redis**
- **Caching**: API response caching, session data, frequently accessed data
- **Job Queues**: Two queues for async job processing
  - `scan_jobs`: Compliance scan execution queue
  - `remediation_jobs`: Resource remediation execution queue
- **Pub/Sub**: Real-time job status updates to API/frontend

**Database (PostgreSQL)**
- Persist scan results and history
- Store exceptions with audit trail
- Account and rule configuration
- Finding status tracking

---

## 3. Data Model

See [docs/DATABASE.md](docs/DATABASE.md) for complete database schema documentation including:
- Entity relationship diagram
- All table definitions with column types
- Enum values (FindingStatus, WorkflowStatus, Severity, etc.)
- Audit event types
- Index recommendations
- Migration commands

---

## 4. API Reference

See [docs/API.md](docs/API.md) for complete API documentation including:
- All REST endpoints organized by resource
- Request/response examples
- Pagination details
- Error response format

---

## 5. Rule Engine

### 5.1 Rule Definition

Rules are Python classes inheriting from `ComplianceRule` (see `api/app/services/rules/base.py`).

**Class Attributes:**

| Attribute | Type | Description |
|-----------|------|-------------|
| `rule_id` | str | Unique identifier (e.g., `S3_VERSIONING`) |
| `name` | str | Human-readable name |
| `description` | str | Full description |
| `resource_type` | str | AWS resource type (CloudFormation format) |
| `severity` | Severity | CRITICAL, HIGH, MEDIUM, LOW, INFO |
| `has_remediation` | bool | Whether auto-remediation is implemented |
| `supports_prefetch` | bool | Uses optimized batch evaluation |

**Methods:**

| Method | Purpose |
|--------|---------|
| `evaluate_resources(resources, session, region)` | Evaluate pre-fetched resources (preferred) |
| `evaluate(session, region)` | Legacy: fetches own resources |
| `remediate(session, resource_id, region, details)` | Fix non-compliant resource |
| `get_remediation_description()` | Human-readable action description |
| `get_expected_state(current_details)` | Preview state after remediation |

**RuleResult** dataclass: `(resource_id, resource_name, status, details)` where status is PASS, FAIL, or ERROR.

### 5.2 Rule Registry

Rules are registered in `api/app/services/rules/__init__.py`. The registry maps `rule_id` strings to rule classes and is synced to the database via `POST /api/v1/rules/sync`.

---

## 6. Frontend Design

### 6.1 Pages

1. **Dashboard** (`/`)
   - Compliance score summary (% passing)
   - Findings by severity chart
   - Recent scans list
   - **Filters**: Account, Region, Time Range (last 24h, 7d, 30d, custom)
   - Quick actions (trigger scan)

2. **Findings** (`/findings`)
   - Filterable table of all findings
   - Filters: status, severity, account, region, rule, workflow status
   - **Global search bar** (searches resource name, ID, account)
   - Bulk actions (create exceptions, remediate, update workflow status)
   - Export to CSV

3. **Finding Detail** (`/findings/:id`)
   - Full finding details
   - Resource metadata
   - Rule information
   - **Workflow status** with dropdown (Open → Acknowledged → In Progress → Resolved)
   - **Notes field** for tracking remediation progress
   - Create exception button
   - Remediate button
   - **Rescan button** to verify fix

4. **Scans** (`/scans`)
   - Scan history table
   - Scan status and progress
   - Trigger new scan form (with rule selection for targeted scans)
   - Scan detail drill-down

5. **New Scan** (`/scans/new`)
   - Account selection (multi-select or all)
   - Region selection (checkboxes, US regions default)
   - Rule selection (checkboxes, allows single-rule targeted scans)
   - Preview of resource types to be scanned

6. **Rules** (`/rules`)
   - List of all rules
   - Enable/disable toggle
   - Severity indicators
   - Finding counts per rule
   - "Scan Now" button per rule (quick single-rule scan)

7. **Exceptions** (`/exceptions`)
   - List of active exceptions
   - Filter by scope, rule, account
   - View/delete exceptions

8. **Remediation** (`/remediation`)
   - List of remediation jobs
   - Job status and progress
   - Create new remediation job from findings

9. **Remediation Job Detail** (`/remediation/:id`)
   - Job status
   - Real-time execution logs
   - Resource status (success/failed/skipped)
   - Before/after state for each resource

10. **Audit Logs** (`/audit-logs`)
    - Filterable list of all audit events
    - Filters: action type, date range, account, resource
    - Expandable rows showing before/after state
    - Export to CSV

11. **Accounts** (`/accounts`)
    - List configured AWS accounts
    - Add/edit/remove accounts
    - Test connectivity

12. **Settings** (`/settings`)
    - Default scan regions
    - Scan scheduling (future)

### 6.2 Dashboard Wireframe

```
┌─────────────────────────────────────────────────────────────────────────┐
│  AWS Compliance Dashboard                              [Trigger Scan]   │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  Filters: [All Accounts ▼] [All Regions ▼] [Last 7 days ▼] [🔍 Search] │
│                                                                         │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌─────────────┐ │
│  │ Compliance   │  │  Critical    │  │    High      │  │   Medium    │ │
│  │    78%       │  │     12       │  │     34       │  │     89      │ │
│  │   ████████░░ │  │  ▲ +3        │  │  ▼ -5        │  │  ─ 0        │ │
│  └──────────────┘  └──────────────┘  └──────────────┘  └─────────────┘ │
│                                                                         │
│  ┌─────────────────────────────────┐  ┌───────────────────────────────┐│
│  │ Findings by Resource Type       │  │ Recent Scans                  ││
│  │ ┌─────────────────────────────┐ │  │ ┌───────────────────────────┐ ││
│  │ │ S3 Buckets    ████████░ 45  │ │  │ │ Jan 15, 10:00  ✓ Complete │ ││
│  │ │ EC2 Instances ██████░░░ 32  │ │  │ │ Jan 14, 10:00  ✓ Complete │ ││
│  │ │ IAM Roles     ███░░░░░░ 18  │ │  │ │ Jan 13, 10:00  ✓ Complete │ ││
│  │ │ RDS Instances ██░░░░░░░ 12  │ │  │ │ Jan 12, 10:00  ✗ Failed   │ ││
│  │ └─────────────────────────────┘ │  │ └───────────────────────────┘ ││
│  └─────────────────────────────────┘  └───────────────────────────────┘│
│                                                                         │
│  ┌─────────────────────────────────────────────────────────────────────┐│
│  │ Critical Findings                                      [View All →] ││
│  │ ┌───────────────────────────────────────────────────────────────┐   ││
│  │ │ Resource          │ Rule              │ Account    │ Workflow │   ││
│  │ ├───────────────────┼───────────────────┼────────────┼──────────┤   ││
│  │ │ prod-db-server    │ EC2 No Public IP  │ 1234...012 │ Open     │   ││
│  │ │ customer-data     │ S3 Encryption     │ 1234...012 │ Ack'd    │   ││
│  │ │ admin-role        │ IAM No Wildcards  │ 9876...321 │ In Prog  │   ││
│  │ └───────────────────┴───────────────────┴────────────┴──────────┘   ││
│  └─────────────────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────────────────┘
```

### 6.3 Findings Table Columns

| Column | Description |
|--------|-------------|
| Status | PASS/FAIL/EXCEPTION indicator |
| Workflow | OPEN/ACKNOWLEDGED/IN_PROGRESS/RESOLVED badge |
| Severity | CRITICAL/HIGH/MEDIUM/LOW/INFO badge |
| Resource Name | Human-readable resource name |
| Resource ID | AWS ARN or resource ID |
| Account | AWS account ID |
| Region | AWS region |
| Rule | Rule name |
| Discovered | Timestamp of finding |
| Actions | View, Create Exception, Remediate, Rescan |

---

## 7. Exception Management

### 7.1 Exception Scopes

1. **Resource Exception**: Ignore a specific resource for a specific rule
   - Example: Ignore S3 versioning check for `marketing-assets` bucket

2. **Rule Exception**: Disable a rule entirely
   - Example: Disable public IP check for all EC2 instances

3. **Account Exception**: Ignore a rule for an entire account
   - Example: Ignore all findings for development account

### 7.2 Exception Workflow

```
┌─────────────┐     ┌─────────────────┐     ┌─────────────────┐
│  Finding    │────▶│  Create         │────▶│   Exception     │
│  Displayed  │     │  Exception      │     │   Active        │
└─────────────┘     │  (with reason)  │     └────────┬────────┘
                    └─────────────────┘              │
                                                     ▼
                    ┌─────────────────┐     ┌─────────────────┐
                    │  Exception      │◀────│   Finding       │
                    │  Expired/       │     │   Marked as     │
                    │  Removed        │     │   EXCEPTION     │
                    └─────────────────┘     └─────────────────┘
```

### 7.3 Exception Application

During scan evaluation, exceptions are checked:

```python
async def apply_exceptions(finding: Finding) -> Finding:
    """Check if finding matches any active exception."""

    # Check resource-specific exception
    if await has_resource_exception(finding.rule_id, finding.resource_id):
        finding.status = "EXCEPTION"
        return finding

    # Check account-wide exception
    if await has_account_exception(finding.rule_id, finding.account_id):
        finding.status = "EXCEPTION"
        return finding

    # Check rule-wide exception
    if await has_rule_exception(finding.rule_id):
        finding.status = "EXCEPTION"
        return finding

    return finding
```

---

## 8. Multi-Account Support

### 8.1 Cross-Account Access

The application supports scanning multiple AWS accounts using IAM role assumption:

```
┌─────────────────────┐         ┌─────────────────────┐
│  Management Account │         │   Target Account    │
│  (Dashboard runs)   │         │   (Being scanned)   │
│                     │         │                     │
│  ┌───────────────┐  │ assume  │  ┌───────────────┐  │
│  │ Dashboard     │──┼────────▶│  │ Scanner Role  │  │
│  │ Credentials   │  │  role   │  │ (ReadOnly)    │  │
│  └───────────────┘  │         │  └───────────────┘  │
└─────────────────────┘         └─────────────────────┘
```

### 8.2 Required IAM Permissions

Target account role needs read permissions for scanned services:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "ComplianceScannerRead",
      "Effect": "Allow",
      "Action": [
        "s3:GetBucketVersioning",
        "s3:GetBucketLocation",
        "s3:ListAllMyBuckets",
        "ec2:DescribeInstances",
        "ec2:DescribeSecurityGroups",
        "ec2:DescribeVpcs"
      ],
      "Resource": "*"
    }
  ]
}
```

Trust policy:
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::MANAGEMENT_ACCOUNT:root"
      },
      "Action": "sts:AssumeRole",
      "Condition": {
        "StringEquals": {
          "sts:ExternalId": "compliance-dashboard-external-id"
        }
      }
    }
  ]
}
```

---

## 9. Scanning Process

### 9.1 Scan Lifecycle

```
┌─────────┐    ┌─────────┐    ┌───────────┐    ┌───────────┐
│ QUEUED  │───▶│ RUNNING │───▶│ COMPLETED │    │  FAILED   │
└─────────┘    └────┬────┘    └───────────┘    └───────────┘
                    │                                ▲
                    └────────────────────────────────┘
                           (on error)
```

- **QUEUED**: Job enqueued to Redis, waiting for worker to pick it up
- **RUNNING**: Worker is actively scanning AWS resources
- **COMPLETED**: Scan finished successfully
- **FAILED**: Scan encountered an error or was cancelled

### 9.2 Scan Execution Flow

```python
async def execute_scan(scan_id: UUID):
    """Execute a compliance scan."""
    scan = await get_scan(scan_id)
    await update_scan_status(scan_id, "RUNNING")

    try:
        total_resources = 0
        total_findings = 0

        # Get rules to evaluate (either specified rules or all enabled)
        if scan.rule_ids:
            rules = [get_rule(rid) for rid in scan.rule_ids]
        else:
            rules = get_enabled_rules()

        # Group rules by resource type for efficient scanning
        rules_by_resource_type = group_rules_by_resource_type(rules)

        for account in scan.accounts:
            session = await assume_role(account)

            for region in scan.regions:
                # Only scan resource types needed for selected rules
                for resource_type, type_rules in rules_by_resource_type.items():
                    # Fetch resources once per type
                    resources = await fetch_resources(session, region, resource_type)

                    for rule in type_rules:
                        results = await rule.evaluate_resources(session, region, resources)

                        for result in results:
                            total_resources += 1

                            finding = await create_finding(
                                scan_id=scan_id,
                                rule_id=rule.id,
                                result=result,
                                account_id=account.account_id,
                                region=region
                            )

                            # Apply exceptions
                            finding = await apply_exceptions(finding)

                            if finding.status == "FAIL":
                                total_findings += 1

        await update_scan(scan_id,
            status="COMPLETED",
            total_resources=total_resources,
            total_findings=total_findings
        )

    except Exception as e:
        await update_scan(scan_id, status="FAILED", error=str(e))
        raise


def group_rules_by_resource_type(rules: List[ComplianceRule]) -> Dict[str, List[ComplianceRule]]:
    """Group rules by their resource type for efficient scanning."""
    grouped = {}
    for rule in rules:
        if rule.resource_type not in grouped:
            grouped[rule.resource_type] = []
        grouped[rule.resource_type].append(rule)
    return grouped
```

**Optimization**: When scanning for specific rules, the scanner only fetches resources of the types needed by those rules. This means:
- Selecting only S3 rules → only S3 API calls are made
- Selecting only EC2 rules → only EC2 API calls are made
- Selecting both → both API calls are made, but resources are fetched once per type

### 9.3 Scanner Implementation Details

This section provides implementation details for engineers who need to understand, debug, or extend the scanner.

#### Key Files

| Component | Location | Purpose |
|-----------|----------|---------|
| Scan API | `api/app/routers/scans.py` | Creates scan records, enqueues jobs |
| Job Queue | `api/app/services/job_queue.py` | Redis-based FIFO queue for async processing |
| Worker | `api/app/worker.py` | Background process that executes scan jobs |
| Scanner | `api/app/services/scanner.py` | Core scan execution logic |
| Fetchers | `api/app/services/fetchers/` | AWS resource fetching (one per service) |
| Rules | `api/app/services/rules/` | Compliance evaluation logic |
| Publisher | `api/app/services/job_publisher.py` | Real-time status updates via Redis pub/sub |

#### Resource Fetching Architecture

The scanner uses a **prefetch optimization** to minimize AWS API calls. Instead of each rule fetching its own resources (N API calls per rule), resources are fetched once per type and shared across rules:

```python
for resource_type in unique_resource_types:
    resources = fetcher.fetch_with_cache(session, region)  # Cached!

    for rule in rules_for_this_type:
        results = rule.evaluate_resources(resources)  # No API call
```

**Fetcher components** (`api/app/services/fetchers/base.py`):

- **`FetchedResource`**: Dataclass containing:
  - `resource_id`: AWS ARN or unique ID
  - `resource_name`: Human-readable name
  - `resource_type`: CloudFormation type (e.g., `AWS::S3::Bucket`)
  - `region`, `account_id`: Location info
  - `raw_data`: Original AWS API response
  - `attributes`: Processed attributes for rule evaluation

- **`ResourceCache`**: In-memory cache keyed by `(account_id, region, resource_type)`. Prevents duplicate fetches during a single scan.

- **`ResourceFetcher`**: Abstract base class. Each AWS service implements one (16+ fetchers total).

#### Finding Upsert Logic

The scanner uses upsert semantics to track compliance changes over time:

```python
existing = query(Finding).filter_by(rule_id, resource_id, account_id, region)

if existing:
    # Update existing finding
    if existing.status == PASS and new_status == FAIL:
        # REGRESSION: Reset workflow to OPEN, notify, create JIRA ticket
    elif existing.status == FAIL and new_status == PASS:
        # FIXED: Mark workflow as RESOLVED, close JIRA ticket
else:
    # Create new finding
    if status == FAIL:
        # NEW FAILURE: Notify via Slack, create JIRA ticket
```

#### Exception Checking

Before marking a finding as `FAIL`, the scanner checks for active exceptions in priority order:

1. **Resource-specific exception**: rule + resource_id
2. **Account-wide exception**: rule + account_id
3. **Rule-wide exception**: rule only

If any active exception matches, the finding status becomes `EXCEPTION` instead of `FAIL`.

#### Real-Time Updates

The scanner publishes progress via Redis pub/sub for SSE streaming:

```python
# In scanner.py - publish progress
progress_callback(f"Scanning {region}...", {"current": 5, "total": 10})

# In job_publisher.py - Redis pub/sub
await redis.publish("channel:job_status", {
    "entity_id": scan_id,
    "status": "RUNNING",
    "progress": {"current": 5, "total": 10}
})

# Frontend subscribes via SSE endpoint
GET /api/v1/scans/{scan_id}/status/stream
```

#### Adding a New Rule

1. Create rule class in `api/app/services/rules/`:
   ```python
   class MyNewRule(ComplianceRule):
       rule_id = "MY_NEW_RULE"
       name = "My New Compliance Check"
       resource_type = "AWS::Service::Resource"
       severity = Severity.MEDIUM
       supports_prefetch = True

       async def evaluate_resources(self, resources, session, region):
           results = []
           for r in resources:
               status = "PASS" if r.attributes.get("compliant") else "FAIL"
               results.append(RuleResult(r.resource_id, r.resource_name, status, {}))
           return results
   ```

2. Register in `api/app/services/rules/__init__.py`:
   ```python
   RULE_REGISTRY[MyNewRule.rule_id] = MyNewRule
   ```

3. Ensure a fetcher exists for the resource type (or create one)

4. Sync rules: `POST /api/v1/rules/sync`

#### Adding a New Fetcher

1. Create fetcher in `api/app/services/fetchers/`:
   ```python
   class MyServiceFetcher(ResourceFetcher):
       resource_types = ["AWS::MyService::Resource"]

       async def fetch(self, session, region, account_id) -> List[FetchedResource]:
           client = session.client("myservice", region_name=region)
           resources = client.describe_resources()
           return [
               FetchedResource(
                   resource_id=r["Arn"],
                   resource_name=r["Name"],
                   resource_type="AWS::MyService::Resource",
                   region=region,
                   account_id=account_id,
                   raw_data=r,
                   attributes={"key": r["Value"]}
               )
               for r in resources
           ]
   ```

2. Register in `api/app/services/fetchers/__init__.py`:
   ```python
   FETCHER_REGISTRY["AWS::MyService::Resource"] = MyServiceFetcher
   ```

---

## 10. Worker & Job Queue Architecture

### 10.1 Overview

Long-running operations (scans and remediations) are offloaded from the API to a dedicated Worker process. This keeps the API responsive and allows for:
- Independent scaling of job processing
- Better fault isolation (worker crash doesn't affect API)
- Retry handling for failed jobs
- Progress tracking and real-time updates

### 10.2 Queue Structure

Redis serves as both the job queue and pub/sub mechanism:

```
┌─────────────────────────────────────────────────────────────────────┐
│                           Redis                                      │
│                                                                      │
│  Queues (List-based)                                                │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │ scan_jobs       │ [job1, job2, job3, ...]                   │   │
│  │ remediation_jobs│ [job1, job2, ...]                         │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                                                                      │
│  Pub/Sub Channels                                                    │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │ job_status      │ Real-time status updates                  │   │
│  │ job_logs        │ Real-time log streaming                   │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                                                                      │
│  Cache Keys                                                          │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │ cache:findings:summary:{account_id}                         │   │
│  │ cache:rules:list                                            │   │
│  │ cache:scan:{scan_id}:status                                 │   │
│  └─────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────┘
```

### 10.3 Job Flow

```
┌──────────┐    ┌──────────┐    ┌──────────┐    ┌──────────┐
│  API     │───▶│  Redis   │───▶│  Worker  │───▶│   AWS    │
│          │    │  Queue   │    │          │    │   APIs   │
└──────────┘    └──────────┘    └────┬─────┘    └──────────┘
                                     │
                                     ▼
                               ┌──────────┐
                               │PostgreSQL│
                               │ (results)│
                               └──────────┘
```

1. **API enqueues job**: Creates job record in PostgreSQL, pushes job ID to Redis queue
2. **Worker pulls job**: Uses BRPOP for blocking pop from queue
3. **Worker executes**: Performs AWS operations, updates progress
4. **Worker publishes updates**: Sends real-time updates via Redis pub/sub
5. **Worker saves results**: Persists findings/results to PostgreSQL
6. **API streams updates**: Subscribes to pub/sub channels for SSE to frontend

### 10.4 Key Files

| Component | Location | Purpose |
|-----------|----------|---------|
| Worker | `api/app/worker.py` | Main loop pulling jobs from Redis queues |
| Job Queue | `api/app/services/job_queue.py` | Enqueue scan/remediation jobs |
| Job Publisher | `api/app/services/job_publisher.py` | Pub/sub status updates |

**Job payloads** contain: `job_id`, `job_type` (scan/remediation), entity IDs, and `created_at`. The worker uses Redis `BRPOP` for blocking queue consumption.

### 10.5 Caching Strategy

Redis caching is used to reduce database load and improve API response times:

| Cache Key Pattern | TTL | Description |
|-------------------|-----|-------------|
| `cache:findings:summary:{account_id}` | 5 min | Dashboard summary statistics |
| `cache:rules:list` | 10 min | List of all compliance rules |
| `cache:scan:{scan_id}:status` | 1 min | Current scan status |
| `cache:accounts:list` | 10 min | List of configured AWS accounts |

Cache invalidation occurs when:
- A scan completes (invalidates findings summary)
- Rules are enabled/disabled (invalidates rules list)
- Accounts are added/removed (invalidates accounts list)

---

## 11. Remediation

### 11.1 Remediation Modes

1. **Single Resource**: Fix one specific resource
2. **Bulk Remediation**: Fix all resources failing a specific rule

### 11.2 Remediation Workflow

The remediation process uses a simplified confirmation modal workflow:

```
┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│   Select     │────▶│   Preview    │────▶│   Execute    │
│   Findings   │     │   Modal      │     │   & Monitor  │
└──────────────┘     └──────────────┘     └──────────────┘
                            │                     │
                            ▼                     ▼
                     ┌──────────────┐     ┌──────────────┐
                     │  Shows what  │     │  Real-time   │
                     │  will change │     │  Logs in UI  │
                     │  [Confirm]   │     │              │
                     └──────────────┘     └──────────────┘
```

**Flow**:
1. User selects findings to remediate
2. Frontend calls `/preview` endpoint to get planned changes
3. Confirmation modal shows before/after for each resource
4. User clicks "Confirm & Execute"
5. Frontend creates remediation job which executes immediately
6. Real-time logs stream to UI

### 11.3 Remediation Job States

```
┌─────────┐    ┌─────────┐    ┌───────────┐    ┌───────────┐
│ QUEUED  │───▶│ RUNNING │───▶│ COMPLETED │    │  FAILED   │
└─────────┘    └────┬────┘    └───────────┘    └───────────┘
                    │                               ▲
                    └───────────────────────────────┘
                               (on error)
```

- **QUEUED**: Job enqueued to Redis, waiting for worker
- **RUNNING**: Worker is actively executing remediations
- **COMPLETED**: All remediations finished (may include skipped items)
- **FAILED**: One or more remediations failed
- **CANCELLED**: User cancelled the job

### 11.4 Remediation API

See [docs/API.md](docs/API.md#remediation) for complete endpoint documentation including preview, job creation, and SSE log streaming.

**Key concept - Hybrid Logging**: Remediation logs are written to both PostgreSQL (audit trail) and Redis pub/sub (real-time SSE streaming).

### 11.5 Remediation Implementation Details

This section provides implementation details for engineers who need to understand, debug, or extend the remediation system.

#### Key Files

| Component | Location | Purpose |
|-----------|----------|---------|
| Remediation API | `api/app/routers/remediation.py` | Preview, create jobs, stream logs |
| Worker | `api/app/worker.py` | Executes remediation jobs from queue |
| Rule.remediate() | `api/app/services/rules/*.py` | AWS API calls to fix resources |
| RemediationJob | `api/app/models/remediation.py` | Job tracking model |
| RemediationLog | `api/app/models/remediation.py` | Execution log entries |
| JIRA Service | `api/app/services/notifications/jira.py` | Ticket lifecycle management |

#### Real-Time Log Streaming

Remediation logs use a **dual-write pattern** for both persistence and real-time streaming:

```python
async def log_remediation(job_id, level, message, resource_id, details):
    # 1. Persist to PostgreSQL (audit trail, historical queries)
    db.add(RemediationLog(job_id, level, message, resource_id, details))

    # 2. Publish to Redis (real-time SSE streaming)
    await publish_job_log(job_id, level, message, resource_id, details)
```

**SSE Endpoint**: `GET /api/v1/remediation/{job_id}/logs/stream`
- Sends existing logs from DB first (catches late joiners)
- Subscribes to Redis pub/sub for new logs
- Terminates when job reaches terminal state (COMPLETED/FAILED/CANCELLED)
- Supports `?use_pubsub=false` fallback for DB polling mode

#### Execution Flow

The `execute_remediation()` function in `routers/remediation.py`:

```python
async def execute_remediation(job_id):
    # 1. Load job with finding and rule relationships
    job = await get_job_with_relations(job_id)

    # 2. Update status to RUNNING, create audit log
    job.status = "RUNNING"
    audit_log("REMEDIATION_STARTED", ...)

    # 3. Get AWS session (handles cross-account via role assumption)
    session = await get_aws_session(finding.account_id)

    # 4. Execute rule-specific remediation
    rule_instance = RULE_REGISTRY[rule.rule_id]()
    success = await rule_instance.remediate(
        session, finding.resource_id, finding.region, finding.details
    )

    # 5. Update finding status
    finding.status = "PASS"
    finding.workflow_status = "RESOLVED"

    # 6. Complete job, create audit log
    job.status = "COMPLETED"
    audit_log("REMEDIATION_COMPLETED", ...)

    # 7. Close JIRA ticket if exists
    if finding.jira_ticket_key:
        await resolve_jira_ticket_for_remediation(finding, job.confirmed_by)

    # 8. Invalidate caches so frontend sees new state
    await invalidate_finding_caches()
```

#### Adding Remediation to a Rule

1. Set `has_remediation = True` on the rule class

2. Implement `remediate()`:
   ```python
   async def remediate(self, session, resource_id, region, finding_details=None) -> bool:
       client = session.client("service", region_name=region)
       client.fix_the_thing(ResourceId=parse_id(resource_id))
       return True
   ```

3. Implement preview methods for the confirmation modal:
   ```python
   @classmethod
   def get_remediation_description(cls) -> str:
       return "Description shown in confirmation modal"

   @classmethod
   def get_expected_state(cls, current_details: dict) -> dict:
       return {**current_details, "fixed_attribute": "new_value"}
   ```

4. Test thoroughly—remediations modify production AWS resources!

#### Error Handling

All errors are caught and logged:
- Job status set to `FAILED`
- `error_message` stored (truncated to 1000 chars)
- Audit log entry created with full error details
- Finding status remains `FAIL` (unchanged)
- JIRA ticket remains open

#### Security Considerations

- **Confirmation Required**: Jobs only execute after explicit user confirmation
- **Audit Trail**: All remediations logged with `performed_by` user identity
- **Cross-Account**: Uses IAM role assumption with external IDs
- **No Secrets in Logs**: AWS credentials never appear in logs

---

## 12. Audit Logging

### 12.1 Purpose

The audit log provides a complete, immutable record of all changes made to AWS resources through the compliance dashboard. This is essential for:

- Compliance reporting and evidence
- Troubleshooting and rollback investigation
- Security incident analysis
- Change management tracking

### 12.2 Audit Events

| Action | Description | Captured Data |
|--------|-------------|---------------|
| SCAN_STARTED | A compliance scan was initiated | scan_id, account_ids, regions, rule_count |
| SCAN_COMPLETED | A compliance scan finished successfully | scan_id, total_resources, total_findings, duration |
| FINDING_ACKNOWLEDGED | Finding workflow status changed to ACKNOWLEDGED | finding_id, resource_id, status, notes |
| FINDING_RESOLVED | Finding workflow status changed to RESOLVED | finding_id, resource_id, status, notes |
| EXCEPTION_CREATED | Exception was created for a resource/rule | exception_id, scope, justification, affected_findings |
| EXCEPTION_DELETED | Exception was removed | exception_id, scope, justification |
| REMEDIATION_STARTED | Remediation job started executing | job_id, finding_id, resource_name |
| REMEDIATION_COMPLETED | Remediation job completed successfully | job_id, finding_id, resource_name, duration |
| REMEDIATION_FAILED | Remediation job failed | job_id, finding_id, resource_name, error, duration |
| ACCOUNT_ADDED | AWS account was added | account_id, name, role_arn |
| ACCOUNT_REMOVED | AWS account was removed | account_id, name |

### 12.3 Audit Log API

See [docs/API.md](docs/API.md#audit-logs) for endpoint documentation. Supports filtering by action, resource_id, account_id, date range, and pagination.

---

## 13. Notifications

### 13.1 Slack Integration

Slack notifications are sent on scan completion to keep teams informed of compliance status.

**Configuration** (environment variables):
```env
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/...
```

**Notification Events**:
- Scan completion with finding summary
- New findings (configurable by severity)
- Regressions (previously passing resources now failing)

**Notification Content**:
- Total findings by severity (CRITICAL, HIGH, MEDIUM, LOW)
- New findings since last scan
- Regression count
- JIRA ticket links (if JIRA integration enabled)

**Key File**: `api/app/services/notifications/slack.py`

### 13.2 JIRA Integration

Automatic JIRA ticket lifecycle management for compliance findings with AWS Security Hub custom fields.

**Configuration** (environment variables):
```env
JIRA_BASE_URL=https://yourcompany.atlassian.net
JIRA_EMAIL=your-email@company.com
JIRA_API_TOKEN=your-api-token
JIRA_PROJECT_KEY=CORE
JIRA_ISSUE_TYPE=AWS Security Hub V2 Finding
JIRA_ASSIGNEE_EMAIL=assignee@company.com  # Optional
```

**Key File**: `api/app/services/notifications/jira.py`

#### Ticket Lifecycle

| Event | JIRA Action |
|-------|-------------|
| New finding | Create ticket with severity-based due date |
| Regression (no ticket) | Create new ticket |
| Regression (has ticket) | Reopen existing ticket |
| Remediation succeeds | Add comment, close ticket |
| Rescan passes | Add comment, close ticket |
| Exception created | Add comment, close ticket |
| Exception deleted | Reopen ticket |

#### Severity to Due Date Mapping

| Severity | Due Date |
|----------|----------|
| CRITICAL | 15 days |
| HIGH | 30 days |
| MEDIUM | 60 days |
| LOW | 90 days |
| INFO | 120 days |

#### AWS Security Hub Custom Fields

The JIRA integration populates AWS Security Hub-compatible custom fields:

- `aws_account`: AWS account ID
- `aws_region`: AWS region
- `aws_finding_id`: Internal finding UUID
- `aws_compliance_status`: PASS/FAIL/EXCEPTION
- `aws_finding_status`: NEW/REGRESSION/RESOLVED
- `aws_finding_modified_at`: Last status change timestamp
- `aws_finding_last_seen_at`: Last scan timestamp

#### Ticket Labels

Tickets are labeled for easy filtering:
- `finding-{uuid}`: Unique finding identifier
- `rule-{rule_id}`: Rule that generated the finding
- `severity-{level}`: Severity level (critical, high, etc.)

#### Remediation Integration

When remediation succeeds, the JIRA ticket is automatically closed with a comment documenting the fix (resource, action, performer, timestamp) and AWS custom fields are updated to `RESOLVED`.

---

## 14. Docker Compose Configuration

See [docker-compose.yml](docker-compose.yml) for the complete configuration.

**Services:**

| Service | Port | Description |
|---------|------|-------------|
| frontend | 3000 | React app (Vite) |
| api | 8000 | FastAPI server |
| worker | - | Background job processor |
| redis | 6379 | Job queue + cache + pub/sub |
| db | 5432 | PostgreSQL database |

**Required environment variables**: `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN` (or mount `~/.aws` credentials).

---

## 15. Default Scan Regions

US regions scanned by default:

| Region Code | Region Name |
|-------------|-------------|
| us-east-1 | US East (N. Virginia) |
| us-east-2 | US East (Ohio) |
| us-west-1 | US West (N. California) |
| us-west-2 | US West (Oregon) |

Configurable via API or environment variable.

---

## 16. Security Considerations

1. **Credential Storage**: AWS credentials passed via environment variables or mounted files, never stored in database

2. **Least Privilege**: Scanner roles should have read-only permissions where possible

3. **Audit Trail**: All exception creations logged with user and timestamp

4. **Input Validation**: All API inputs validated using Pydantic models

5. **No Secrets in Logs**: Ensure AWS credentials and sensitive data not logged

---