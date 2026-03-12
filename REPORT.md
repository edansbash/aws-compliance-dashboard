# Report Generation Feature Design

## Overview

Add report generation capabilities to the AWS Compliance Dashboard, allowing users to generate, schedule, and export compliance reports in various formats.

---

## Report Types

### 1. Executive Summary Report
- High-level compliance posture overview
- Pass/fail percentages by category
- Trend comparison (vs. previous scan)
- Top 5 critical findings
- Account-level breakdown (for multi-account)

### 2. Detailed Findings Report
- Full list of all findings from a scan
- Grouped by severity, service, or rule
- Resource details and remediation steps
- Exception status included

### 3. Remediation Report
- Findings with available auto-remediation
- Manual remediation steps
- Estimated effort/impact ratings
- Priority recommendations

### 4. Trend/Historical Report
- Compliance score over time
- New vs. resolved findings
- Recurring issues identification
- Progress tracking

### 5. Exception Report
- All active exceptions
- Expiration dates
- Justifications and approvers
- Resources covered

---

## Export Formats

| Format | Use Case |
|--------|----------|
| PDF | Executive sharing, printing, archival |
| CSV | Data analysis, spreadsheet import |
| JSON | API integration, programmatic access |
| HTML | Email embedding, web viewing |

---

## User Interface

### Report Builder Page (`/reports`)

```
┌─────────────────────────────────────────────────────────┐
│  Generate Report                                        │
├─────────────────────────────────────────────────────────┤
│                                                         │
│  Report Type:    [Executive Summary    ▼]               │
│                                                         │
│  Scan:           [Latest Scan - 2024-01-15 ▼]          │
│                                                         │
│  Filters:                                               │
│    Accounts:     [All Accounts          ▼]              │
│    Regions:      [All Regions           ▼]              │
│    Severity:     [■] Critical [■] High [■] Medium [■] Low │
│    Services:     [Select services...    ▼]              │
│                                                         │
│  Format:         ○ PDF  ○ CSV  ○ JSON  ○ HTML          │
│                                                         │
│  [ ] Schedule recurring report                          │
│      Frequency:  [Weekly ▼]  Day: [Monday ▼]           │
│      Recipients: [email@example.com, ...]               │
│                                                         │
│              [Preview]  [Generate Report]               │
└─────────────────────────────────────────────────────────┘
```

### Report History Page (`/reports/history`)
- List of generated reports
- Download links
- Regenerate option
- Scheduled report management

---

## API Endpoints

### Reports Resource

```
POST   /api/v1/reports              # Generate a new report
GET    /api/v1/reports              # List generated reports
GET    /api/v1/reports/{id}         # Get report metadata
GET    /api/v1/reports/{id}/download # Download report file
DELETE /api/v1/reports/{id}         # Delete a report

POST   /api/v1/reports/preview      # Generate preview (limited data)
```

### Scheduled Reports

```
POST   /api/v1/reports/schedules         # Create schedule
GET    /api/v1/reports/schedules         # List schedules
GET    /api/v1/reports/schedules/{id}    # Get schedule details
PUT    /api/v1/reports/schedules/{id}    # Update schedule
DELETE /api/v1/reports/schedules/{id}    # Delete schedule
```

### Request/Response Examples

**Generate Report Request:**
```json
POST /api/v1/reports
{
  "report_type": "executive_summary",
  "scan_id": "uuid-of-scan",
  "format": "pdf",
  "filters": {
    "accounts": ["123456789012"],
    "regions": ["us-east-1", "us-west-2"],
    "severities": ["critical", "high"],
    "services": ["ec2", "s3", "iam"]
  }
}
```

**Response:**
```json
{
  "id": "report-uuid",
  "status": "generating",
  "report_type": "executive_summary",
  "format": "pdf",
  "created_at": "2024-01-15T10:30:00Z",
  "estimated_completion": "2024-01-15T10:31:00Z"
}
```

---

## Data Models

### Report

```python
class Report(Base):
    __tablename__ = "reports"

    id: UUID
    report_type: ReportType  # enum
    scan_id: UUID  # FK to scans
    format: ReportFormat  # enum
    status: ReportStatus  # pending, generating, completed, failed
    filters: JSON  # stored filter criteria
    file_path: str  # path to generated file
    file_size: int  # bytes
    created_at: datetime
    completed_at: datetime | None
    created_by: str  # user identifier
    error_message: str | None
```

### ReportSchedule

```python
class ReportSchedule(Base):
    __tablename__ = "report_schedules"

    id: UUID
    name: str
    report_type: ReportType
    format: ReportFormat
    filters: JSON
    frequency: ScheduleFrequency  # daily, weekly, monthly
    schedule_config: JSON  # day of week, time, etc.
    recipients: List[str]  # email addresses
    enabled: bool
    last_run_at: datetime | None
    next_run_at: datetime
    created_at: datetime
    created_by: str
```

---

## Backend Services

### ReportGenerator Service

```python
class ReportGenerator:
    async def generate(self, report_config: ReportConfig) -> Report:
        """Main entry point for report generation."""
        pass

    async def _gather_data(self, scan_id: UUID, filters: Filters) -> ReportData:
        """Collect and aggregate data for the report."""
        pass

    async def _render_pdf(self, data: ReportData, template: str) -> bytes:
        """Render PDF using template."""
        pass

    async def _render_csv(self, data: ReportData) -> bytes:
        """Generate CSV export."""
        pass

    async def _render_json(self, data: ReportData) -> bytes:
        """Generate JSON export."""
        pass

    async def _render_html(self, data: ReportData, template: str) -> bytes:
        """Render HTML report."""
        pass
```

### ReportScheduler Service

```python
class ReportScheduler:
    async def create_schedule(self, config: ScheduleConfig) -> ReportSchedule:
        pass

    async def run_scheduled_reports(self):
        """Called by background worker to process due reports."""
        pass

    async def send_report(self, report: Report, recipients: List[str]):
        """Email report to recipients."""
        pass
```

---

## File Structure (New Files)

```
api/app/
├── models/
│   └── report.py              # Report, ReportSchedule models
├── schemas/
│   └── report.py              # Pydantic schemas
├── routers/
│   └── reports.py             # API endpoints
├── services/
│   ├── report_generator.py    # Report generation logic
│   └── report_scheduler.py    # Scheduling logic
└── templates/
    └── reports/
        ├── executive_summary.html
        ├── detailed_findings.html
        └── base.html

frontend/src/
├── pages/
│   ├── Reports.tsx            # Report builder
│   └── ReportHistory.tsx      # Report history
├── components/
│   └── reports/
│       ├── ReportBuilder.tsx
│       ├── ReportFilters.tsx
│       ├── ReportPreview.tsx
│       └── ScheduleForm.tsx
└── services/
    └── reportService.ts       # API client
```

---

## Dependencies

### Backend (Python)
- `weasyprint` or `reportlab` - PDF generation
- `jinja2` - HTML templating (already in FastAPI)
- `celery` or existing scheduler - Background jobs

### Frontend
- Existing component library
- Date picker for scheduling

---

## Implementation Phases

### Phase 1: Core Report Generation (COMPLETED)
- [x] Database models and migrations (`api/app/models/report.py`)
- [x] Basic API endpoints (generate, list, download) (`api/app/routers/reports.py`)
- [x] Dashboard PDF report type
- [x] Findings Excel export
- [x] Frontend report builder UI (`frontend/src/pages/Reports.tsx`)

### Phase 2: Additional Report Types
- [ ] Executive Summary report
- [ ] Remediation report
- [ ] JSON and HTML formats
- [ ] Report preview functionality

### Phase 3: Scheduling & Distribution
- [ ] Report scheduling models
- [ ] Scheduler service integration
- [ ] Email delivery
- [ ] Schedule management UI

### Phase 4: Advanced Features
- [ ] Trend/Historical reports
- [ ] Exception reports
- [ ] Custom branding/templates
- [ ] Report comparison view

---

## Open Questions

1. **Storage**: Store generated reports in filesystem or S3/object storage?
2. **Retention**: How long to keep generated reports? Auto-cleanup policy?
3. **Authentication**: How to secure report downloads? Signed URLs?
4. **Email**: Use existing email service or add new dependency (SendGrid, SES)?
5. **Branding**: Allow custom logos/colors in reports?

---

## Notes

_Add design decisions and discussion notes here as we iterate._

---

## Implementation Log

### 2024-01-XX: Phase 1 Implementation

**Files Created:**
- `api/app/models/report.py` - Report database model with enums for type, format, status
- `api/app/schemas/report.py` - Pydantic schemas for API validation
- `api/app/services/report_generator.py` - Core report generation service
- `api/app/routers/reports.py` - REST API endpoints
- `frontend/src/pages/Reports.tsx` - Report builder UI

**Files Modified:**
- `api/requirements.txt` - Added openpyxl, reportlab, jinja2
- `api/app/models/__init__.py` - Export Report model
- `api/app/main.py` - Register reports router
- `frontend/src/services/api.ts` - Report API functions
- `frontend/src/App.tsx` - Reports route
- `frontend/src/components/Layout.tsx` - Reports navigation

**Features Implemented:**
1. **Dashboard PDF Report**
   - Compliance score summary card
   - Findings by status table
   - Findings by severity table (color-coded)
   - Findings by account breakdown
   - Top 10 non-compliant resources

2. **Findings Excel Export**
   - Summary sheet with statistics
   - Detailed findings sheet with all columns
   - Color-coded severity and status cells
   - Auto-sized columns

3. **Frontend UI**
   - Report type selection
   - Scan filter (optional)
   - Account filter (optional)
   - Severity toggle filters
   - Status toggle filters (Excel only)
   - One-click generation with download
   - Report history table

**API Endpoints:**
```
POST /api/v1/reports                    # Create report record
GET  /api/v1/reports                    # List reports
GET  /api/v1/reports/{id}               # Get report details
GET  /api/v1/reports/{id}/download      # Download report file
DELETE /api/v1/reports/{id}             # Delete report

POST /api/v1/reports/generate/dashboard-pdf    # Direct PDF download
POST /api/v1/reports/generate/findings-excel   # Direct Excel download
```
