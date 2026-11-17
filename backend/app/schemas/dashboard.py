from datetime import datetime

from pydantic import BaseModel

from app.schemas.accounts import IntegrationHealthRead
from app.schemas.events import CloudTrailEventRead
from app.schemas.incidents import IncidentRead


class DashboardCount(BaseModel):
    name: str
    count: int


class DashboardMetrics(BaseModel):
    total_events: int
    total_alerts: int
    open_incidents: int
    critical_high_incidents: int
    guardduty_findings: int
    securityhub_findings: int
    monitored_accounts: int
    monitored_regions: int
    notifications_pending: int
    notifications_failed: int


class DashboardSummary(BaseModel):
    generated_at: datetime
    since: datetime
    until: datetime
    metrics: DashboardMetrics
    severity_distribution: list[DashboardCount]
    top_detection_rules: list[DashboardCount]
    top_source_ips: list[DashboardCount]
    top_resources: list[DashboardCount]
    top_identities: list[DashboardCount]
    recent_events: list[CloudTrailEventRead]
    recent_incidents: list[IncidentRead]
    integrations: list[IntegrationHealthRead]
    aws_connection_status: str
