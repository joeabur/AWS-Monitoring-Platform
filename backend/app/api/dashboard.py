from collections import Counter
from datetime import UTC, datetime, timedelta
from typing import Annotated

from fastapi import APIRouter, HTTPException, Query, status
from sqlalchemy import case, func, select

from app.api.dependencies import CurrentUser, Database
from app.core.config import get_settings
from app.models import (
    AuditorFinding,
    AuditorReport,
    AwsIntegrationHealth,
    CloudTrailEvent,
    DetectionAlert,
    Incident,
    NotificationDelivery,
)
from app.schemas.audit_reports import AuditFindingRead, AuditReportRead
from app.schemas.dashboard import DashboardCount, DashboardMetrics, DashboardSummary
from app.schemas.incidents import IncidentRead

router = APIRouter(prefix="/api/v1/dashboard", tags=["dashboard"])
_ACTIVE_INCIDENTS = ("resolved", "false_positive")


@router.get("/summary", response_model=DashboardSummary)
def dashboard_summary(
    db: Database,
    _: CurrentUser,
    account_id: Annotated[str | None, Query(pattern=r"^\d{12}$")] = None,
    region: Annotated[str | None, Query(min_length=1, max_length=64)] = None,
    severity: Annotated[
        str | None, Query(pattern=r"^(critical|high|medium|low|informational)$")
    ] = None,
    since: datetime | None = None,
    until: datetime | None = None,
) -> DashboardSummary:
    now = datetime.now(UTC)

    def as_utc(value: datetime | None, name: str) -> datetime | None:
        if value is None:
            return None
        if value.tzinfo is None or value.utcoffset() is None:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail=f"{name} must include a timezone",
            )
        return value.astimezone(UTC)

    end = as_utc(until, "until") or now
    start = as_utc(since, "since") or end - timedelta(hours=24)
    if end < start:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="until must be greater than or equal to since",
        )

    common_event_filters = [
        CloudTrailEvent.event_time >= start,
        CloudTrailEvent.event_time <= end,
    ]
    alert_filters = [
        DetectionAlert.last_observed_at >= start,
        DetectionAlert.last_observed_at <= end,
    ]
    incident_filters = [
        Incident.last_observed_at >= start,
        Incident.last_observed_at <= end,
    ]
    if account_id is not None:
        common_event_filters.append(CloudTrailEvent.account_id == account_id)
        alert_filters.append(DetectionAlert.account_id == account_id)
        incident_filters.append(Incident.account_id == account_id)
    if region is not None:
        normalized_region = region.lower()
        common_event_filters.append(CloudTrailEvent.region == normalized_region)
        alert_filters.append(DetectionAlert.region == normalized_region)
        incident_filters.append(Incident.region == normalized_region)

    total_events = (
        db.scalar(select(func.count()).select_from(CloudTrailEvent).where(*common_event_filters))
        or 0
    )
    if severity is not None:
        alert_filters.append(DetectionAlert.severity == severity)
        incident_filters.append(Incident.severity == severity)
    total_alerts = (
        db.scalar(select(func.count()).select_from(DetectionAlert).where(*alert_filters)) or 0
    )
    active_filter = Incident.status.not_in(_ACTIVE_INCIDENTS)
    open_incidents = (
        db.scalar(
            select(func.count()).select_from(Incident).where(*incident_filters, active_filter)
        )
        or 0
    )
    critical_high = (
        db.scalar(
            select(func.count())
            .select_from(Incident)
            .where(
                *incident_filters,
                active_filter,
                Incident.severity.in_(("critical", "high")),
            )
        )
        or 0
    )
    guardduty_findings = (
        db.scalar(
            select(func.count())
            .select_from(CloudTrailEvent)
            .where(*common_event_filters, CloudTrailEvent.event_source == "guardduty.amazonaws.com")
        )
        or 0
    )
    securityhub_findings = (
        db.scalar(
            select(func.count())
            .select_from(CloudTrailEvent)
            .where(
                *common_event_filters, CloudTrailEvent.event_source == "securityhub.amazonaws.com"
            )
        )
        or 0
    )
    notification_window = [
        NotificationDelivery.created_at >= start,
        NotificationDelivery.created_at <= end,
    ]
    notifications_pending = (
        db.scalar(
            select(func.count())
            .select_from(NotificationDelivery)
            .where(
                *notification_window,
                NotificationDelivery.status.in_(("pending", "retrying")),
            )
        )
        or 0
    )
    notifications_failed = (
        db.scalar(
            select(func.count())
            .select_from(NotificationDelivery)
            .where(*notification_window, NotificationDelivery.status == "failed")
        )
        or 0
    )

    severity_distribution = db.execute(
        select(DetectionAlert.severity, func.count())
        .where(*alert_filters)
        .group_by(DetectionAlert.severity)
        .order_by(DetectionAlert.severity)
    ).all()
    rule_counts = db.execute(
        select(DetectionAlert.rule_id, func.count())
        .where(*alert_filters)
        .group_by(DetectionAlert.rule_id)
        .order_by(func.count().desc(), DetectionAlert.rule_id)
        .limit(5)
    ).all()
    recent_events = db.scalars(
        select(CloudTrailEvent)
        .where(*common_event_filters)
        .order_by(CloudTrailEvent.event_time.desc(), CloudTrailEvent.id)
        .limit(10)
    ).all()
    recent_incidents = db.scalars(
        select(Incident)
        .where(*incident_filters, active_filter)
        .order_by(
            case(
                (Incident.severity == "critical", 0),
                (Incident.severity == "high", 1),
                (Incident.severity == "medium", 2),
                (Incident.severity == "low", 3),
                else_=4,
            ),
            Incident.last_observed_at.desc(),
            Incident.id,
        )
        .limit(10)
    ).all()
    recent_alerts = db.scalars(
        select(DetectionAlert)
        .where(*alert_filters)
        .order_by(DetectionAlert.last_observed_at.desc())
        .limit(500)
    ).all()

    def top_counts(values: Counter[str]) -> list[DashboardCount]:
        return [DashboardCount(name=name, count=count) for name, count in values.most_common(5)]

    source_ips: Counter[str] = Counter(
        alert.source_ip for alert in recent_alerts if alert.source_ip
    )
    identities: Counter[str] = Counter(
        alert.principal_arn or alert.principal_id
        for alert in recent_alerts
        if alert.principal_arn or alert.principal_id
    )
    resources: Counter[str] = Counter(
        resource for alert in recent_alerts for resource in alert.resource_arns
    )
    configured_accounts = get_settings().monitored_aws_accounts
    monitored_account_ids = {account.account_id for account in configured_accounts}
    scoped_account_ids = (
        monitored_account_ids.intersection({account_id})
        if account_id is not None
        else monitored_account_ids
    )
    integration_filters = []
    if scoped_account_ids:
        integration_filters.append(AwsIntegrationHealth.account_id.in_(scoped_account_ids))
    if region is not None:
        integration_filters.append(AwsIntegrationHealth.region.in_((region.lower(), "")))
    integrations = (
        db.scalars(
            select(AwsIntegrationHealth)
            .where(*integration_filters)
            .order_by(AwsIntegrationHealth.integration, AwsIntegrationHealth.region)
        ).all()
        if scoped_account_ids
        else []
    )
    report_filters = []
    if account_id is not None:
        report_filters.append(AuditorReport.account_id == account_id)
    latest_audit_report = db.scalars(
        select(AuditorReport)
        .where(*report_filters)
        .order_by(AuditorReport.generated_at.desc(), AuditorReport.id)
        .limit(1)
    ).first()
    audit_findings: list[AuditorFinding] = []
    active_audit_failures = 0
    if latest_audit_report is not None:
        finding_filters = [
            AuditorFinding.report_id == latest_audit_report.id,
            AuditorFinding.status.in_(("FAIL", "ERROR", "NOT_ASSESSED")),
        ]
        if region is not None:
            finding_filters.append(AuditorFinding.region.in_((region.lower(), "global")))
        if severity is not None:
            audit_severity = "info" if severity == "informational" else severity
            finding_filters.append(AuditorFinding.severity == audit_severity)
        active_failure_filters = [
            AuditorFinding.report_id == latest_audit_report.id,
            AuditorFinding.status == "FAIL",
            AuditorFinding.suppression.is_(None),
        ]
        if region is not None:
            active_failure_filters.append(AuditorFinding.region.in_((region.lower(), "global")))
        if severity is not None:
            audit_severity = "info" if severity == "informational" else severity
            active_failure_filters.append(AuditorFinding.severity == audit_severity)
        active_audit_failures = (
            db.scalar(
                select(func.count()).select_from(AuditorFinding).where(*active_failure_filters)
            )
            or 0
        )
        audit_findings = db.scalars(
            select(AuditorFinding)
            .where(*finding_filters)
            .order_by(
                case(
                    (AuditorFinding.status == "FAIL", 0),
                    (AuditorFinding.status == "ERROR", 1),
                    else_=2,
                ),
                case(
                    (AuditorFinding.severity == "critical", 0),
                    (AuditorFinding.severity == "high", 1),
                    (AuditorFinding.severity == "medium", 2),
                    (AuditorFinding.severity == "low", 3),
                    else_=4,
                ),
                AuditorFinding.control_id,
                AuditorFinding.resource_id,
            )
            .limit(10)
        ).all()
    monitored_regions = {integration.region for integration in integrations if integration.region}
    if not configured_accounts:
        connection_status = "not_configured"
    elif not integrations:
        connection_status = "unknown"
    elif any(
        integration.integration == "sts" and integration.status == "unhealthy"
        for integration in integrations
    ):
        connection_status = "unhealthy"
    elif all(
        any(
            integration.account_id == account_id
            and integration.integration == "sts"
            and integration.status == "healthy"
            and (
                integration.last_checked_at.replace(tzinfo=UTC)
                if integration.last_checked_at.tzinfo is None
                else integration.last_checked_at.astimezone(UTC)
            )
            >= now - timedelta(hours=24)
            for integration in integrations
        )
        for account_id in scoped_account_ids
    ):
        connection_status = "healthy"
    else:
        connection_status = "unknown"

    return DashboardSummary(
        generated_at=now,
        since=start,
        until=end,
        metrics=DashboardMetrics(
            total_events=total_events,
            total_alerts=total_alerts,
            open_incidents=open_incidents,
            critical_high_incidents=critical_high,
            guardduty_findings=guardduty_findings,
            securityhub_findings=securityhub_findings,
            monitored_accounts=len(configured_accounts),
            monitored_regions=len(monitored_regions),
            notifications_pending=notifications_pending,
            notifications_failed=notifications_failed,
            active_audit_failures=active_audit_failures,
        ),
        severity_distribution=[
            DashboardCount(name=str(name), count=count) for name, count in severity_distribution
        ],
        top_detection_rules=[
            DashboardCount(name=str(name), count=count) for name, count in rule_counts
        ],
        top_source_ips=top_counts(source_ips),
        top_resources=top_counts(resources),
        top_identities=top_counts(identities),
        recent_events=recent_events,
        recent_incidents=[IncidentRead.model_validate(item) for item in recent_incidents],
        integrations=integrations,
        latest_audit_report=(
            AuditReportRead.model_validate(latest_audit_report)
            if latest_audit_report is not None
            else None
        ),
        audit_findings=[AuditFindingRead.model_validate(finding) for finding in audit_findings],
        aws_connection_status=connection_status,
    )
