from datetime import datetime
from pydantic import BaseModel


class HealthChecks(BaseModel):
    database: str
    aws_credentials: str


class HealthResponse(BaseModel):
    status: str
    version: str
    checks: HealthChecks
    timestamp: datetime
