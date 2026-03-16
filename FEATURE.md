# Feature: Terraform Infrastructure-as-Code Compliance Scanning

## 1. Overview

### 1.1 Purpose

Extend the AWS Compliance Dashboard to surface **pre-deployment compliance issues** from Terraform code stored in GitHub repositories. This enables **shift-left security** by catching misconfigurations before infrastructure is deployed.

### 1.2 Goals

- Pull IaC scan results from GitHub Code Scanning API (via **Trivy** GitHub Actions)
- Display IaC findings in a **separate dedicated tab** (not mixed with runtime findings)
- Track pre-deployment compliance posture independently from runtime compliance
- Simple configuration via environment variables (single repository: `KineticEye/iac`)
- Link IaC findings to GitHub Security alerts for remediation workflow

### 1.3 Key Distinction: IaC vs Runtime Findings

| Aspect | IaC Findings | Runtime Findings |
|--------|--------------|------------------|
| **Source** | Trivy scanning Terraform code | boto3 scanning live AWS |
| **Status** | Pre-deployment (may not exist in AWS yet) | Deployed resources |
| **Compliance Score** | Separate "IaC Compliance Score" | Separate "Runtime Compliance Score" |
| **Location** | Separate `/iac` tab in dashboard | Main dashboard |
| **Remediation** | Fix in Terraform code | Fix in AWS (auto-remediate) |

### 1.4 Non-Goals

- Supporting other IaC formats (CloudFormation, Pulumi, CDK) in initial release
- Auto-remediation of Terraform code (read-only scanning)
- Terraform plan analysis (only static .tf file analysis)
- Mixing IaC findings with runtime findings in compliance scores

### 1.5 Target Repository

Initial integration with: `https://github.com/KineticEye/iac`

---

## 2. Architecture

### 2.1 Hybrid Approach

This feature uses a **hybrid architecture**:

1. **GitHub Actions** runs Trivy on every push/PR, uploads SARIF results to GitHub Security tab
2. **Dashboard** pulls findings from GitHub Code Scanning API into a **separate IaC section**

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                            GitHub (Per Repository)                           │
│                                                                              │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐  │
│  │  PR/Push    │───▶│   GitHub    │───▶│  Run Trivy  │───▶│  Upload     │  │
│  │  Event      │    │   Actions   │    │  (SARIF)    │    │  to Security│  │
│  └─────────────┘    └─────────────┘    └─────────────┘    └──────┬──────┘  │
│                                                                   │         │
│                            ┌──────────────────────────────────────┘         │
│                            ▼                                                │
│                     ┌─────────────┐                                         │
│                     │  Security   │  ◀── PR Annotations                     │
│                     │  Tab/Alerts │  ◀── Block failing PRs                  │
│                     └──────┬──────┘                                         │
└────────────────────────────┼────────────────────────────────────────────────┘
                             │
                             │ Code Scanning API
                             │ GET /repos/{owner}/{repo}/code-scanning/alerts
                             ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                           Compliance Dashboard                               │
│                                                                              │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │  Main Dashboard (Runtime)  │  IaC Tab (Pre-deployment) ◀── SEPARATE │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                                                              │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────────────┐              │
│  │  Frontend   │───▶│    API      │───▶│     PostgreSQL      │              │
│  │  (React)    │    │  (FastAPI)  │    │                     │              │
│  │             │    │             │    │  + iac_syncs        │              │
│  │ + /iac tab  │    │ + IaC Router│    │  + iac_findings     │              │
│  └─────────────┘    └──────┬──────┘    │                     │              │
│                            │           └─────────────────────┘              │
│                            ▼                                                │
│                     ┌─────────────┐                                         │
│                     │   Worker    │                                         │
│                     │             │                                         │
│                     │ + Sync Job  │────▶ Pulls alerts from GitHub           │
│                     └─────────────┘                                         │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 2.2 Why Hybrid?

| Benefit | Description |
|---------|-------------|
| **PR Blocking** | GitHub Actions blocks non-compliant PRs before merge |
| **Developer Feedback** | Developers see issues directly in PR annotations |
| **No Infrastructure** | No need to run Trivy ourselves - GitHub does it |
| **Separate Compliance** | IaC score doesn't affect runtime compliance score |
| **Trivy Maturity** | 100+ built-in misconfig checks, handles modules/variables |

### 2.3 Component Responsibilities

**New Components:**

| Component | Location | Purpose |
|-----------|----------|---------|
| IaC Router | `api/app/routers/iac.py` | REST API for IaC repos, syncs, findings |
| GitHub Service | `api/app/services/github.py` | Code Scanning API integration |
| Trivy Rule Mapper | `api/app/services/trivy_mapper.py` | Map Trivy rule IDs for display |
| IaC Sync Worker | `api/app/services/iac_sync.py` | Pull findings from GitHub periodically |

### 2.4 Authentication

GitHub authentication is configured via **environment variables only** (not stored in DB):

```env
# .env file
GITHUB_TOKEN=ghp_xxxxxxxxxxxxxxxxxxxx   # Personal Access Token
# OR
GITHUB_APP_ID=123456                     # GitHub App ID
GITHUB_APP_PRIVATE_KEY_PATH=/path/to/key.pem
```

This keeps secrets out of the database and follows the same pattern as AWS credentials.

### 2.5 Data Flow

```
┌──────────────┐    ┌──────────────┐    ┌──────────────┐    ┌──────────────┐
│  Developer   │───▶│  Push/PR     │───▶│  GitHub      │───▶│  Trivy       │
│  commits     │    │  to GitHub   │    │  Actions     │    │  scan        │
└──────────────┘    └──────────────┘    └──────────────┘    └──────┬───────┘
                                                                   │
                    ┌──────────────────────────────────────────────┘
                    │
                    ▼
┌──────────────┐    ┌──────────────┐    ┌──────────────┐    ┌──────────────┐
│  SARIF       │───▶│  GitHub      │───▶│  Dashboard   │───▶│  Store in    │
│  Upload      │    │  Security    │    │  pulls via   │    │  iac_findings│
└──────────────┘    │  Alerts      │    │  API         │    └──────────────┘
                    └──────────────┘    └──────────────┘
```

---

## 3. Data Model

**Important**: These tables are completely separate from runtime findings. IaC findings represent **pre-deployment misconfigurations** and do NOT count toward the main compliance score.

### 3.1 Configuration (via .env)

Since there's only **one IaC repository**, configuration is in `.env` (not in DB):

```env
# .env file - IaC Repository Configuration
GITHUB_TOKEN=ghp_xxxxxxxxxxxxxxxxxxxx      # GitHub PAT with security_events:read
IAC_GITHUB_OWNER=KineticEye                # GitHub org/user
IAC_GITHUB_REPO=iac                        # Repository name
IAC_GITHUB_BRANCH=main                     # Branch to sync (default: main)
IAC_SYNC_ENABLED=true                      # Enable/disable sync
IAC_SYNC_INTERVAL_MINUTES=15               # Auto-sync interval (0 = manual only)
```

### 3.2 New Tables

#### `iac_syncs` - Sync History

Tracks when findings were pulled from GitHub Code Scanning API:

```sql
CREATE TABLE iac_syncs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    status VARCHAR(20) NOT NULL DEFAULT 'RUNNING', -- RUNNING, COMPLETED, FAILED
    commit_sha VARCHAR(40),                        -- Latest commit at sync time
    branch VARCHAR(100),
    started_at TIMESTAMP,
    completed_at TIMESTAMP,
    total_alerts INTEGER DEFAULT 0,                -- Alerts fetched from GitHub
    open_alerts INTEGER DEFAULT 0,                 -- Currently open alerts
    new_alerts INTEGER DEFAULT 0,                  -- New since last sync
    fixed_alerts INTEGER DEFAULT 0,                -- Fixed since last sync
    error_message VARCHAR(1000),
    created_at TIMESTAMP DEFAULT NOW()
);
```

#### `iac_findings` - Pre-deployment Misconfigurations

```sql
CREATE TABLE iac_findings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    sync_id UUID REFERENCES iac_syncs(id) ON DELETE SET NULL,  -- Last sync that saw this

    -- GitHub Alert Info (source of truth)
    github_alert_number INTEGER NOT NULL UNIQUE,   -- Alert number in GitHub (unique identifier)
    github_alert_url VARCHAR(500) NOT NULL,        -- Direct link to alert
    github_alert_state VARCHAR(20) NOT NULL,       -- open, dismissed, fixed

    -- Trivy Rule Info
    trivy_rule_id VARCHAR(100) NOT NULL,           -- e.g., "AVD-AWS-0086"
    trivy_rule_description TEXT,                   -- Rule description from Trivy
    severity VARCHAR(20) NOT NULL,                 -- CRITICAL, HIGH, MEDIUM, LOW

    -- Location in code
    file_path VARCHAR(500) NOT NULL,               -- e.g., "modules/storage/main.tf"
    start_line INTEGER,                            -- Line where issue starts
    end_line INTEGER,                              -- Line where issue ends

    -- Finding details
    message TEXT,                                  -- Specific finding message
    resource_type VARCHAR(100),                    -- e.g., "aws_s3_bucket" (if parseable)

    -- Tracking
    commit_sha VARCHAR(40),
    first_detected_at TIMESTAMP DEFAULT NOW(),
    last_seen_at TIMESTAMP DEFAULT NOW(),
    dismissed_at TIMESTAMP,
    dismissed_reason VARCHAR(100),                 -- false_positive, wont_fix, used_in_tests

    created_at TIMESTAMP DEFAULT NOW()
);

-- Indexes
CREATE INDEX idx_iac_findings_state ON iac_findings(github_alert_state);
CREATE INDEX idx_iac_findings_severity ON iac_findings(severity);
CREATE INDEX idx_iac_findings_rule ON iac_findings(trivy_rule_id);
```

### 3.3 Entity Relationships

```
┌─────────────┐       ┌─────────────┐
│  iac_syncs  │──────<│iac_findings │
│  (history)  │  1:N  │  (alerts)   │
└─────────────┘       └─────────────┘

Note: No relationship to runtime tables. IaC is completely separate.
Repository config is in .env (single repo).
```

### 3.4 SQLAlchemy Models

```python
# api/app/models/iac.py

import uuid
from datetime import datetime
from sqlalchemy import String, DateTime, Integer, Text, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.dialects.postgresql import UUID
from app.database import Base


class IaCSync(Base):
    """
    Sync record - tracks when findings were pulled from GitHub.

    Each sync fetches all current alerts and updates iac_findings.
    """
    __tablename__ = "iac_syncs"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    status: Mapped[str] = mapped_column(String(20), default="RUNNING")  # RUNNING, COMPLETED, FAILED
    commit_sha: Mapped[str | None] = mapped_column(String(40), nullable=True)
    branch: Mapped[str | None] = mapped_column(String(100), nullable=True)
    started_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    total_alerts: Mapped[int] = mapped_column(Integer, default=0)
    open_alerts: Mapped[int] = mapped_column(Integer, default=0)
    new_alerts: Mapped[int] = mapped_column(Integer, default=0)
    fixed_alerts: Mapped[int] = mapped_column(Integer, default=0)
    error_message: Mapped[str | None] = mapped_column(String(1000), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class IaCFinding(Base):
    """
    Pre-deployment misconfiguration from Trivy via GitHub Code Scanning.

    NOTE: These are NOT runtime findings. They represent issues in
    Terraform code that may or may not be deployed to AWS yet.
    They do NOT count toward the main compliance score.
    """
    __tablename__ = "iac_findings"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    sync_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("iac_syncs.id", ondelete="SET NULL"), nullable=True
    )

    # GitHub Alert (source of truth - unique identifier)
    github_alert_number: Mapped[int] = mapped_column(Integer, nullable=False, unique=True)
    github_alert_url: Mapped[str] = mapped_column(String(500), nullable=False)
    github_alert_state: Mapped[str] = mapped_column(String(20), nullable=False)  # open, dismissed, fixed

    # Trivy Rule
    trivy_rule_id: Mapped[str] = mapped_column(String(100), nullable=False)
    trivy_rule_description: Mapped[str | None] = mapped_column(Text, nullable=True)
    severity: Mapped[str] = mapped_column(String(20), nullable=False)  # CRITICAL, HIGH, MEDIUM, LOW

    # Code Location
    file_path: Mapped[str] = mapped_column(String(500), nullable=False)
    start_line: Mapped[int | None] = mapped_column(Integer, nullable=True)
    end_line: Mapped[int | None] = mapped_column(Integer, nullable=True)

    # Details
    message: Mapped[str | None] = mapped_column(Text, nullable=True)
    resource_type: Mapped[str | None] = mapped_column(String(100), nullable=True)

    # Tracking
    commit_sha: Mapped[str | None] = mapped_column(String(40), nullable=True)
    first_detected_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    dismissed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    dismissed_reason: Mapped[str | None] = mapped_column(String(100), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
```

---

## 4. GitHub Actions Workflow (Already Configured)

The Trivy workflow is already enabled on `KineticEye/iac` and results appear in the Security tab.

### 4.1 Trivy GitHub Action (Reference)

For reference, this is the typical Trivy workflow at `.github/workflows/trivy.yml`:

```yaml
name: Trivy IaC Scan

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  trivy:
    name: Trivy Config Scan
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write

    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      - name: Run Trivy vulnerability scanner
        uses: aquasecurity/trivy-action@master
        with:
          scan-type: 'config'
          scan-ref: '.'
          format: 'sarif'
          output: 'trivy-results.sarif'
          severity: 'CRITICAL,HIGH,MEDIUM'

      - name: Upload Trivy scan results to GitHub Security tab
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: 'trivy-results.sarif'
```

### 4.2 Trivy Built-in Checks

Trivy includes 100+ misconfig checks for Terraform. Examples:

| Rule ID | Description | Severity |
|---------|-------------|----------|
| AVD-AWS-0086 | S3 bucket without versioning | MEDIUM |
| AVD-AWS-0088 | S3 bucket without encryption | HIGH |
| AVD-AWS-0089 | S3 bucket with public access | CRITICAL |
| AVD-AWS-0107 | Security group allows all ingress | CRITICAL |
| AVD-AWS-0080 | RDS instance without encryption | HIGH |
| AVD-AWS-0176 | CloudTrail not enabled | HIGH |

Full list: https://avd.aquasec.com/misconfig/aws/

### 4.3 PR Blocking (Optional)

To block PRs with high/critical findings:

1. **Settings → Branches → Branch protection rules**
2. Enable **Require status checks to pass**
3. Add **Trivy Config Scan** to required checks

---

## 5. Trivy Rule Reference

### 5.1 Trivy Built-in Checks

Trivy uses the **AVD (Aqua Vulnerability Database)** format for rule IDs. These rules are automatically applied when scanning Terraform.

| AVD Rule ID | Description | Severity |
|-------------|-------------|----------|
| AVD-AWS-0086 | S3 bucket should have versioning enabled | MEDIUM |
| AVD-AWS-0088 | S3 bucket encryption should be enabled | HIGH |
| AVD-AWS-0089 | S3 bucket should block public access | CRITICAL |
| AVD-AWS-0090 | S3 bucket should have logging enabled | MEDIUM |
| AVD-AWS-0107 | Security group allows unrestricted ingress | CRITICAL |
| AVD-AWS-0080 | RDS instance should have encryption enabled | HIGH |
| AVD-AWS-0176 | CloudTrail should be enabled in all regions | HIGH |
| AVD-AWS-0065 | IAM policy should not allow wildcard actions | HIGH |
| AVD-AWS-0057 | KMS key rotation should be enabled | MEDIUM |

Full list: https://avd.aquasec.com/misconfig/aws/

### 5.2 Rule Display Strategy

Trivy rules are displayed directly without mapping to internal rules:

| Field | Source |
|-------|--------|
| `trivy_rule_id` | Trivy's AVD ID (e.g., `AVD-AWS-0086`) |
| `trivy_rule_description` | Description from Trivy |
| `severity` | CRITICAL, HIGH, MEDIUM, LOW from Trivy |

**Rationale**: Trivy has 100+ well-documented misconfig rules. Mapping them to internal rules would be redundant and create maintenance burden. Instead, we display Trivy's rule information directly.

### 5.3 Severity Mapping

Trivy severities map directly:

```python
# api/app/services/trivy_mapper.py

def normalize_severity(trivy_severity: str) -> str:
    """Normalize Trivy severity to uppercase."""
    mapping = {
        "CRITICAL": "CRITICAL",
        "HIGH": "HIGH",
        "MEDIUM": "MEDIUM",
        "LOW": "LOW",
        "critical": "CRITICAL",
        "high": "HIGH",
        "medium": "MEDIUM",
        "low": "LOW",
    }
    return mapping.get(trivy_severity, "MEDIUM")
```

---

## 6. GitHub Code Scanning API Integration

### 6.1 GitHub Service

```python
# api/app/services/github.py

import os
import httpx
from typing import List, Optional
from dataclasses import dataclass
from datetime import datetime

@dataclass
class CodeScanningAlert:
    """GitHub Code Scanning alert from Trivy."""
    number: int                    # Alert number in repo
    rule_id: str                   # Trivy rule ID (AVD-AWS-xxxx)
    severity: str                  # critical, high, medium, low
    state: str                     # open, dismissed, fixed
    description: str               # Rule description
    message: str                   # Specific finding message
    file_path: str                 # e.g., "modules/s3/main.tf"
    start_line: int                # Line number
    end_line: int
    commit_sha: str                # Commit where detected
    html_url: str                  # Link to alert in GitHub
    created_at: datetime
    dismissed_at: Optional[datetime]
    dismissed_reason: Optional[str]


class GitHubService:
    """Service for interacting with GitHub Code Scanning API."""

    def __init__(self, token: str = None):
        # Use provided token or fall back to env var
        self.token = token or os.getenv("GITHUB_TOKEN")
        if not self.token:
            raise ValueError("GITHUB_TOKEN environment variable is required")

        self.base_url = "https://api.github.com"
        self.headers = {
            "Authorization": f"Bearer {self.token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28"
        }

    async def get_code_scanning_alerts(
        self,
        owner: str,
        repo: str,
        ref: Optional[str] = None,  # Branch name
        state: str = "open",        # open, dismissed, fixed
        tool_name: str = "trivy"    # Trivy uploads as "trivy"
    ) -> List[CodeScanningAlert]:
        """
        Fetch code scanning alerts from GitHub.

        API: GET /repos/{owner}/{repo}/code-scanning/alerts
        Docs: https://docs.github.com/en/rest/code-scanning/code-scanning
        """
        async with httpx.AsyncClient() as client:
            params = {
                "state": state,
                "tool_name": tool_name,
                "per_page": 100
            }
            if ref:
                params["ref"] = ref

            alerts = []
            page = 1

            while True:
                params["page"] = page
                response = await client.get(
                    f"{self.base_url}/repos/{owner}/{repo}/code-scanning/alerts",
                    headers=self.headers,
                    params=params
                )
                response.raise_for_status()

                data = response.json()
                if not data:
                    break

                for alert in data:
                    alerts.append(self._parse_alert(alert))

                page += 1

            return alerts

    async def get_alert_instances(
        self,
        owner: str,
        repo: str,
        alert_number: int
    ) -> List[dict]:
        """Get all instances of a specific alert across branches."""
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{self.base_url}/repos/{owner}/{repo}/code-scanning/alerts/{alert_number}/instances",
                headers=self.headers
            )
            response.raise_for_status()
            return response.json()

    def _parse_alert(self, data: dict) -> CodeScanningAlert:
        """Parse GitHub API response into CodeScanningAlert."""
        location = data.get("most_recent_instance", {}).get("location", {})

        return CodeScanningAlert(
            number=data["number"],
            rule_id=data["rule"]["id"],
            severity=data["rule"]["severity"] or "medium",
            state=data["state"],
            description=data["rule"]["description"],
            message=data.get("most_recent_instance", {}).get("message", {}).get("text", ""),
            file_path=location.get("path", ""),
            start_line=location.get("start_line", 0),
            end_line=location.get("end_line", 0),
            commit_sha=data.get("most_recent_instance", {}).get("commit_sha", ""),
            html_url=data["html_url"],
            created_at=datetime.fromisoformat(data["created_at"].replace("Z", "+00:00")),
            dismissed_at=datetime.fromisoformat(data["dismissed_at"].replace("Z", "+00:00")) if data.get("dismissed_at") else None,
            dismissed_reason=data.get("dismissed_reason")
        )


    async def get_repo_info(self, owner: str, repo: str) -> dict:
        """Get repository information."""
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{self.base_url}/repos/{owner}/{repo}",
                headers=self.headers
            )
            response.raise_for_status()
            return response.json()
```

### 6.2 Token Requirements

The GitHub token needs these permissions:

| Scope | Permission | Required For |
|-------|------------|--------------|
| `security_events` | read | Reading code scanning alerts |
| `repo` | read | Private repositories |
| `metadata` | read | Repository info |

For GitHub Apps, use the `security_events: read` permission.

**Note**: Public repos with GitHub Advanced Security don't require special permissions. Private repos require GitHub Advanced Security license.

---

## 7. IaC Sync Worker

### 7.1 Configuration

Repository configuration comes from environment variables (see Section 3.1):

```python
# api/app/services/iac_config.py

import os
from dataclasses import dataclass

@dataclass
class IaCConfig:
    """IaC repository configuration from environment."""
    github_token: str
    owner: str
    repo: str
    branch: str
    sync_enabled: bool
    sync_interval_minutes: int

    @classmethod
    def from_env(cls) -> "IaCConfig":
        """Load configuration from environment variables."""
        return cls(
            github_token=os.getenv("GITHUB_TOKEN", ""),
            owner=os.getenv("IAC_GITHUB_OWNER", ""),
            repo=os.getenv("IAC_GITHUB_REPO", ""),
            branch=os.getenv("IAC_GITHUB_BRANCH", "main"),
            sync_enabled=os.getenv("IAC_SYNC_ENABLED", "true").lower() == "true",
            sync_interval_minutes=int(os.getenv("IAC_SYNC_INTERVAL_MINUTES", "15")),
        )

    def is_configured(self) -> bool:
        """Check if IaC scanning is configured."""
        return bool(self.github_token and self.owner and self.repo)
```

### 7.2 Sync Implementation

```python
# api/app/services/iac_sync.py

import os
from typing import List
from uuid import UUID
from datetime import datetime

from app.services.github import GitHubService, CodeScanningAlert
from app.services.iac_config import IaCConfig
from app.services.trivy_mapper import normalize_severity
from app.models.iac import IaCSync, IaCFinding

class IaCSyncService:
    """Sync IaC findings from GitHub Code Scanning API."""

    def __init__(self, db_session):
        self.db = db_session
        self.config = IaCConfig.from_env()

    async def sync(self, progress_callback=None) -> IaCSync:
        """
        Sync findings from GitHub Code Scanning API.

        Args:
            progress_callback: Optional callback for status updates

        Returns:
            IaCSync record with synced findings
        """
        if not self.config.is_configured():
            raise ValueError("IaC scanning not configured. Check environment variables.")

        # Initialize GitHub client (uses GITHUB_TOKEN from env)
        github = GitHubService()

        # Create sync record
        sync = IaCSync(
            status="RUNNING",
            branch=self.config.branch,
            started_at=datetime.utcnow()
        )
        self.db.add(sync)
        await self.db.commit()

        try:
            if progress_callback:
                progress_callback("Fetching alerts from GitHub...", {"phase": "fetch"})

            # Fetch ALL alerts (open, dismissed, fixed) to track state changes
            all_alerts = await github.get_code_scanning_alerts(
                owner=self.config.owner,
                repo=self.config.repo,
                ref=self.config.branch,
                state="all",          # Get all states
                tool_name="trivy"     # Trivy uploads as "trivy"
            )

            if progress_callback:
                progress_callback(f"Processing {len(all_alerts)} alerts...", {"phase": "process"})

            # Track counts
            new_count = 0
            fixed_count = 0

            # Process each alert
            for alert in all_alerts:
                is_new, is_fixed = await self._upsert_finding(sync.id, alert)
                if is_new:
                    new_count += 1
                if is_fixed:
                    fixed_count += 1

            # Update sync record
            open_alerts = [a for a in all_alerts if a.state == "open"]
            sync.status = "COMPLETED"
            sync.completed_at = datetime.utcnow()
            sync.total_alerts = len(all_alerts)
            sync.open_alerts = len(open_alerts)
            sync.new_alerts = new_count
            sync.fixed_alerts = fixed_count
            sync.commit_sha = all_alerts[0].commit_sha if all_alerts else None

            await self.db.commit()
            return sync

        except Exception as e:
            sync.status = "FAILED"
            sync.error_message = str(e)[:1000]
            sync.completed_at = datetime.utcnow()
            await self.db.commit()
            raise

    async def _upsert_finding(
        self,
        sync_id: UUID,
        alert: CodeScanningAlert
    ) -> tuple[bool, bool]:
        """
        Update existing finding or create new one.

        Returns:
            (is_new, is_fixed) - whether this is a new finding and whether it was fixed
        """
        # Check for existing finding by GitHub alert number (unique identifier)
        existing = await self.db.query(IaCFinding).filter(
            IaCFinding.github_alert_number == alert.number
        ).first()

        is_new = False
        is_fixed = False

        if existing:
            # Track if alert was fixed
            if existing.github_alert_state == "open" and alert.state == "fixed":
                is_fixed = True

            # Update existing finding
            existing.sync_id = sync_id
            existing.github_alert_state = alert.state
            existing.last_seen_at = datetime.utcnow()
            existing.commit_sha = alert.commit_sha
            existing.message = alert.message

            if alert.dismissed_at:
                existing.dismissed_at = alert.dismissed_at
                existing.dismissed_reason = alert.dismissed_reason
        else:
            # Create new finding
            is_new = True
            finding = IaCFinding(
                sync_id=sync_id,
                github_alert_number=alert.number,
                github_alert_url=alert.html_url,
                github_alert_state=alert.state,
                trivy_rule_id=alert.rule_id,
                trivy_rule_description=alert.description,
                severity=normalize_severity(alert.severity),
                file_path=alert.file_path,
                start_line=alert.start_line,
                end_line=alert.end_line,
                message=alert.message,
                resource_type=self._extract_resource_type(alert.rule_id),
                commit_sha=alert.commit_sha,
                first_detected_at=datetime.utcnow(),
                last_seen_at=datetime.utcnow(),
            )
            self.db.add(finding)

        return is_new, is_fixed

    def _extract_resource_type(self, rule_id: str) -> str:
        """Extract resource type from Trivy rule ID."""
        # Trivy AVD IDs don't encode resource type directly
        # Return None and let the frontend display Trivy's rule info
        return None
```

### 7.3 Scheduled Sync

```python
# api/app/worker.py

from app.services.iac_config import IaCConfig

async def run_scheduled_iac_sync():
    """Run IaC sync if enabled and configured."""
    config = IaCConfig.from_env()

    if not config.is_configured():
        return  # IaC not configured, skip

    if not config.sync_enabled:
        return  # Sync disabled

    sync_service = IaCSyncService(db)
    await sync_service.sync()
```

---

## 8. API Endpoints

### 8.1 IaC Configuration

Since there's only one repository (configured via .env), there are no repository management endpoints. Instead, provide a status endpoint:

```
GET    /api/v1/iac/config             Get current IaC configuration status
```

### 8.2 IaC Syncs

```
POST   /api/v1/iac/sync               Trigger manual sync from GitHub
GET    /api/v1/iac/syncs              List sync history (with filters)
GET    /api/v1/iac/syncs/{id}         Get sync details
GET    /api/v1/iac/syncs/{id}/stream  SSE for real-time sync status
```

### 8.3 IaC Findings

```
GET    /api/v1/iac/findings           List findings (with filters)
GET    /api/v1/iac/findings/{id}      Get finding details
GET    /api/v1/iac/summary            Dashboard summary stats
```

### 8.4 Request/Response Examples

**Get Configuration Status:**
```json
GET /api/v1/iac/config

Response:
{
    "configured": true,
    "owner": "KineticEye",
    "repo": "iac",
    "branch": "main",
    "sync_enabled": true,
    "sync_interval_minutes": 15,
    "last_sync": {
        "id": "660e8400-e29b-41d4-a716-446655440001",
        "status": "COMPLETED",
        "completed_at": "2024-01-15T10:05:12Z",
        "open_alerts": 17
    }
}
```

**Trigger Sync (Pull Alerts from GitHub):**
```json
POST /api/v1/iac/sync

Response:
{
    "id": "660e8400-e29b-41d4-a716-446655440001",
    "status": "RUNNING",
    "started_at": "2024-01-15T10:05:00Z",
    "message": "Syncing alerts from GitHub Code Scanning API..."
}
```

**Sync Completed:**
```json
GET /api/v1/iac/syncs/660e8400-e29b-41d4-a716-446655440001

Response:
{
    "id": "660e8400-e29b-41d4-a716-446655440001",
    "status": "COMPLETED",
    "branch": "main",
    "commit_sha": "abc123def456",
    "started_at": "2024-01-15T10:05:00Z",
    "completed_at": "2024-01-15T10:05:12Z",
    "total_alerts": 25,
    "open_alerts": 17,
    "new_alerts": 3,
    "fixed_alerts": 1
}
```

**IaC Finding:**
```json
GET /api/v1/iac/findings/{id}

Response:
{
    "id": "770e8400-e29b-41d4-a716-446655440002",
    "github_alert_number": 42,
    "github_alert_url": "https://github.com/KineticEye/iac/security/code-scanning/42",
    "github_alert_state": "open",
    "trivy_rule_id": "AVD-AWS-0086",
    "trivy_rule_description": "S3 bucket should have versioning enabled",
    "severity": "MEDIUM",
    "file_path": "modules/storage/main.tf",
    "start_line": 45,
    "end_line": 52,
    "message": "Bucket does not have versioning enabled",
    "resource_type": null,
    "commit_sha": "abc123def456",
    "first_detected_at": "2024-01-10T08:00:00Z",
    "last_seen_at": "2024-01-15T10:05:12Z",
    "github_file_link": "https://github.com/KineticEye/iac/blob/main/modules/storage/main.tf#L45"
}
```

**IaC Summary (Dashboard):**
```json
GET /api/v1/iac/summary

Response:
{
    "configured": true,
    "owner": "KineticEye",
    "repo": "iac",
    "total_findings": 17,
    "by_severity": {
        "CRITICAL": 2,
        "HIGH": 5,
        "MEDIUM": 8,
        "LOW": 2
    },
    "by_state": {
        "open": 17,
        "fixed": 12,
        "dismissed": 3
    },
    "last_sync_at": "2024-01-15T10:05:12Z"
}
```

---

## 9. Frontend Changes

### 9.1 New Pages

| Page | Route | Description |
|------|-------|-------------|
| IaC Dashboard | `/iac` | Overview of IaC compliance (single repo) |
| IaC Syncs | `/iac/syncs` | List of sync history |
| IaC Sync Detail | `/iac/syncs/:id` | Sync details |
| IaC Findings | `/iac/findings` | Filterable findings list |
| IaC Finding Detail | `/iac/findings/:id` | Finding with code context |

Note: No repository management pages needed - config is via .env

### 9.2 IaC Dashboard Wireframe

```
┌─────────────────────────────────────────────────────────────────────────────┐
│  Infrastructure as Code Compliance                          [Sync Now]      │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  Repository: KineticEye/iac (main)              Last Sync: 15 minutes ago   │
│                                                                              │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐    │
│  │ Open Alerts  │  │  Critical    │  │    High      │  │   Medium     │    │
│  │     17       │  │     2        │  │     5        │  │     8        │    │
│  │              │  │   ●●         │  │   ●●●●●      │  │   ●●●●●●●●   │    │
│  └──────────────┘  └──────────────┘  └──────────────┘  └──────────────┘    │
│                                                                              │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │ Recent Syncs                                                          │  │
│  │ ┌─────────────────────────────────────────────────────────────────┐   │  │
│  │ │ Time         │ Branch │ Commit   │ Open │ New │ Fixed │ Status │   │  │
│  │ ├──────────────┼────────┼──────────┼──────┼─────┼───────┼────────┤   │  │
│  │ │ 15 min ago   │ main   │ abc123d  │ 17   │ 0   │ 0     │ ✓      │   │  │
│  │ │ 30 min ago   │ main   │ def456g  │ 17   │ 2   │ 1     │ ✓      │   │  │
│  │ │ 45 min ago   │ main   │ ghi789h  │ 16   │ 0   │ 0     │ ✓      │   │  │
│  │ └──────────────┴────────┴──────────┴──────┴─────┴───────┴────────┘   │  │
│  └───────────────────────────────────────────────────────────────────────┘  │
│                                                                              │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │ Open IaC Findings                                        [View All →] │  │
│  │ ┌─────────────────────────────────────────────────────────────────┐   │  │
│  │ │ Trivy Rule         │ Description           │ File         │ Sev │   │  │
│  │ ├────────────────────┼───────────────────────┼──────────────┼─────┤   │  │
│  │ │ AVD-AWS-0089       │ S3 public access      │ storage.tf:12│ CRIT│   │  │
│  │ │ AVD-AWS-0107       │ SG unrestricted       │ network.tf:45│ CRIT│   │  │
│  │ │ AVD-AWS-0080       │ RDS no encryption     │ database.tf:8│ HIGH│   │  │
│  │ │ AVD-AWS-0086       │ S3 no versioning      │ storage.tf:28│ MED │   │  │
│  │ └────────────────────┴───────────────────────┴──────────────┴─────┘   │  │
│  └───────────────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 9.3 IaC Finding Detail (with GitHub Integration)

```
┌─────────────────────────────────────────────────────────────────────────────┐
│  IaC Finding: AVD-AWS-0086                      [View in GitHub Security]   │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  State: open         Severity: MEDIUM        Alert #42                      │
│                                                                              │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │ Trivy Rule                                                           │    │
│  │                                                                       │    │
│  │ Rule ID:      AVD-AWS-0086                                           │    │
│  │ Description:  S3 bucket should have versioning enabled               │    │
│  │ More Info:    https://avd.aquasec.com/misconfig/avd-aws-0086        │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                                                              │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │ Location                                                             │    │
│  │                                                                       │    │
│  │ Repository:   KineticEye/iac                                        │    │
│  │ Branch:       main                                                   │    │
│  │ File:         modules/storage/main.tf                               │    │
│  │ Lines:        45-52                                                  │    │
│  │ Commit:       abc123d                                                │    │
│  │                                                                       │    │
│  │ [View File in GitHub]  [View Alert in GitHub Security]              │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                                                              │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │ Finding Message                                                      │    │
│  │                                                                       │    │
│  │ "Bucket does not have versioning enabled. Versioning in S3 buckets  │    │
│  │  means that old versions of objects are retained when an object is  │    │
│  │  modified or deleted."                                               │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                                                              │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │ Timeline                                                             │    │
│  │                                                                       │    │
│  │ First Detected: Jan 10, 2024 08:00 AM                               │    │
│  │ Last Seen:      Jan 15, 2024 10:05 AM                               │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 9.4 Navigation Updates

Add "IaC" section to sidebar:

```
├── Dashboard
├── Findings
├── Scans
├── Rules
├── Accounts
├── Exceptions
├── Remediation
├── Audit Logs
├── ─────────────
├── IaC                    ← NEW SECTION
│   ├── Dashboard
│   ├── Syncs
│   └── Findings
├── Settings
```

---

## 10. Worker Integration

### 10.1 New Job Queue

Add `iac_sync_jobs` queue alongside existing queues:

```python
# Redis queues
SCAN_JOBS_QUEUE = "scan_jobs"           # Runtime AWS scans
REMEDIATION_JOBS_QUEUE = "remediation_jobs"
IAC_SYNC_JOBS_QUEUE = "iac_sync_jobs"   # NEW: IaC sync from GitHub
```

### 10.2 Worker Loop Update

```python
# api/app/worker.py

from app.services.iac_sync import IaCSyncService
from app.services.iac_config import IaCConfig

async def main():
    """Main worker loop."""
    while True:
        # Check all queues with priority
        job = await redis.brpop([
            REMEDIATION_JOBS_QUEUE,  # Highest priority
            SCAN_JOBS_QUEUE,
            IAC_SYNC_JOBS_QUEUE      # NEW
        ], timeout=5)

        if job:
            queue_name, job_data = job
            if queue_name == IAC_SYNC_JOBS_QUEUE:
                await process_iac_sync_job(job_data)
            elif queue_name == SCAN_JOBS_QUEUE:
                await process_scan_job(job_data)
            elif queue_name == REMEDIATION_JOBS_QUEUE:
                await process_remediation_job(job_data)


async def process_iac_sync_job(job_data: dict):
    """Pull findings from GitHub Code Scanning API."""
    sync_id = job_data["sync_id"]

    sync_service = IaCSyncService(db)
    await sync_service.sync(
        progress_callback=lambda msg, data: publish_sync_status(sync_id, msg, data)
    )
```

### 10.3 Scheduled Sync

Periodically sync based on IAC_SYNC_INTERVAL_MINUTES:

```python
# api/app/worker.py

from app.services.iac_config import IaCConfig

# Run based on configured interval (default: every 15 minutes)
@scheduler.task("*/15 * * * *")
async def scheduled_iac_sync():
    """Sync IaC findings if configured and enabled."""
    config = IaCConfig.from_env()

    if not config.is_configured():
        return  # IaC not configured

    if not config.sync_enabled:
        return  # Sync disabled

    # Enqueue sync job
    await enqueue_iac_sync()


async def enqueue_iac_sync():
    """Add IaC sync job to queue."""
    job_data = {
        "sync_id": str(uuid.uuid4()),
        "type": "iac_sync"
    }
    await redis.lpush(IAC_SYNC_JOBS_QUEUE, json.dumps(job_data))
```

---

## 11. Drift Detection (Future Enhancement)

### 11.1 Concept

Compare IaC findings with runtime findings to detect drift:

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│  IaC Finding    │     │    Compare      │     │ Drift Status    │
│  (Terraform)    │────▶│   Resource ID   │────▶│                 │
└─────────────────┘     │                 │     │ • In Sync       │
                        │                 │     │ • Drift (IaC OK)│
┌─────────────────┐     │                 │     │ • Drift (RT OK) │
│ Runtime Finding │────▶│                 │     │ • Both Fail     │
│  (AWS API)      │     └─────────────────┘     └─────────────────┘
└─────────────────┘
```

### 11.2 Drift States

| IaC Status | Runtime Status | Drift State | Action |
|------------|----------------|-------------|--------|
| PASS | PASS | In Sync | None |
| FAIL | FAIL | Both Failing | Fix in IaC |
| PASS | FAIL | Runtime Drift | Manual change detected |
| FAIL | PASS | IaC Drift | Terraform not applied |

---

## 12. Environment Variables

All IaC configuration is via environment variables (no DB storage):

```env
# GitHub Authentication (required)
GITHUB_TOKEN=ghp_xxxxx                  # Personal Access Token with security_events:read, repo:read

# IaC Repository Configuration (required)
IAC_GITHUB_OWNER=KineticEye             # GitHub organization or user
IAC_GITHUB_REPO=iac                     # Repository name
IAC_GITHUB_BRANCH=main                  # Branch to sync (default: main)

# Sync Settings (optional)
IAC_SYNC_ENABLED=true                   # Enable/disable automatic sync (default: true)
IAC_SYNC_INTERVAL_MINUTES=15            # How often to sync (default: 15, 0 = manual only)
```

### Token Permissions

The GitHub token needs:
- `security_events:read` - Read code scanning alerts
- `repo:read` - Access private repositories (if applicable)

For public repos, a fine-grained PAT with only `security_events:read` is sufficient.

---

## 13. Implementation Phases

### Phase 1: GitHub Actions (Already Complete)
- [x] Trivy GitHub Actions workflow configured on KineticEye/iac
- [x] Results appearing in GitHub Security tab
- [ ] (Optional) Configure branch protection to require Trivy status check

### Phase 2: Core Infrastructure
- [ ] Database migrations (`iac_syncs`, `iac_findings`)
- [ ] SQLAlchemy models (IaCSync, IaCFinding)
- [ ] IaCConfig service (read from .env)
- [ ] GitHub Code Scanning API service
- [ ] IaC sync service (pull alerts from GitHub)
- [ ] API endpoints (config, sync, syncs, findings, summary)
- [ ] Worker job for scheduled syncs

### Phase 3: Frontend
- [ ] IaC Dashboard page (`/iac`)
- [ ] IaC Syncs list page (`/iac/syncs`)
- [ ] IaC Findings list/detail pages (`/iac/findings`)
- [ ] GitHub alert links in finding details
- [ ] Navigation sidebar update

### Phase 4: Enhancements (Future)
- [ ] Webhook support (trigger sync on push instead of polling)
- [ ] Drift detection (compare IaC vs runtime findings)
- [ ] JIRA integration for IaC findings
- [ ] Slack notifications for new IaC findings

---

## 14. Open Questions

1. **GitHub Advanced Security**: Required for private repos. KineticEye/iac is public, so not needed initially. If repo goes private, will need GitHub Advanced Security license.

2. **Webhook vs Polling**: Initial implementation uses polling (every 15 min by default). Webhooks can be added later for immediate sync.

3. **Alert Dismissal Sync**: Currently sync reads dismissal state from GitHub. Dashboard shows GitHub's state (open/fixed/dismissed) as source of truth.

---

## 15. Dependencies

### Python Packages

```
httpx>=0.25.0           # Async HTTP client for GitHub API
```

### GitHub Requirements

```
- Repository: KineticEye/iac
- GitHub Actions enabled (already configured)
- Trivy workflow running (already configured)
- PAT with security_events:read permission
- (If private) GitHub Advanced Security license
```

### Trivy (in GitHub Actions - Already Configured)

```
- aquasecurity/trivy-action@master
- github/codeql-action/upload-sarif@v3
```

---

## 16. Setup Checklist

### GitHub Side (Already Complete for KineticEye/iac)

1. [x] Trivy GitHub Actions workflow configured
2. [x] Results appearing in GitHub Security tab
3. [ ] (Optional) Configure branch protection to require Trivy status check

### Dashboard Side

1. [ ] Configure environment variables:
   ```env
   GITHUB_TOKEN=ghp_xxxx
   IAC_GITHUB_OWNER=KineticEye
   IAC_GITHUB_REPO=iac
   IAC_GITHUB_BRANCH=main
   IAC_SYNC_ENABLED=true
   IAC_SYNC_INTERVAL_MINUTES=15
   ```
2. [ ] Run database migrations
3. [ ] Verify IaC config endpoint: `GET /api/v1/iac/config`
4. [ ] Trigger initial sync: `POST /api/v1/iac/sync`
5. [ ] Verify findings appear in IaC dashboard
