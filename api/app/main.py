from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager

from app.routers import accounts, scans, findings, rules, exceptions, remediation, audit_logs, config, compliance_packs, notifications, schedules, reports, iac, integrations
from app.routers.health import router as health_router
from app.database import engine
from app import models
from app.services.cache import close_redis
from app.services.scheduler import start_scheduler, shutdown_scheduler

app = FastAPI(
    title="AWS Compliance Dashboard API",
    description="API for scanning AWS resources against compliance rules",
    version="1.0.0",
    redoc_url=None,
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(health_router, prefix="/api/v1", tags=["Health"])
app.include_router(accounts.router, prefix="/api/v1/accounts", tags=["Accounts"])
app.include_router(scans.router, prefix="/api/v1/scans", tags=["Scans"])
app.include_router(findings.router, prefix="/api/v1/findings", tags=["Findings"])
app.include_router(rules.router, prefix="/api/v1/rules", tags=["Rules"])
app.include_router(exceptions.router, prefix="/api/v1/exceptions", tags=["Exceptions"])
app.include_router(remediation.router, prefix="/api/v1/remediation-jobs", tags=["Remediation"])
app.include_router(audit_logs.router, prefix="/api/v1/audit-logs", tags=["Audit Logs"])
app.include_router(config.router, prefix="/api/v1/config", tags=["Configuration"])
app.include_router(compliance_packs.router, prefix="/api/v1/compliance-packs", tags=["Compliance Packs"])
app.include_router(notifications.router, prefix="/api/v1/notifications", tags=["Notifications"])
app.include_router(schedules.router, prefix="/api/v1/schedules", tags=["Schedules"])
app.include_router(reports.router, prefix="/api/v1/reports", tags=["Reports"])
app.include_router(iac.router, prefix="/api/v1/iac", tags=["IaC"])
app.include_router(integrations.router, prefix="/api/v1/integrations", tags=["Integrations"])


@app.on_event("startup")
async def startup():
    """Initialize database tables and scheduler on startup."""
    async with engine.begin() as conn:
        await conn.run_sync(models.Base.metadata.create_all)
    # Start the scheduler after database is ready
    await start_scheduler()


@app.on_event("shutdown")
async def shutdown():
    """Clean up resources on shutdown."""
    await shutdown_scheduler()
    await close_redis()
