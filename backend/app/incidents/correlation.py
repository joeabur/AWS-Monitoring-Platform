import hashlib
from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.models import DetectionAlert, Incident, IncidentAlert, IncidentAuditEntry

_SEVERITY_RANK = {
    "informational": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}
_FINAL_STATUSES = {"resolved", "false_positive"}
_CORRELATION_WINDOW = timedelta(hours=24)


def _utc(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


def _correlation_group(alert: DetectionAlert) -> str:
    subject = (
        alert.principal_id
        or alert.principal_arn
        or (alert.resource_arns[0] if alert.resource_arns else None)
        or alert.source_ip
        or f"{alert.rule_id}:{alert.dedup_key}"
    )
    identity = f"{alert.account_id}\0{alert.region}\0{subject}"
    return hashlib.sha256(identity.encode()).hexdigest()


def _active_incident(db: Session, group: str, observed_at: datetime) -> Incident | None:
    lower_bound = observed_at - _CORRELATION_WINDOW
    upper_bound = observed_at + _CORRELATION_WINDOW
    incident = db.scalar(
        select(Incident)
        .where(
            Incident.correlation_key == group,
            Incident.last_observed_at >= lower_bound,
            Incident.last_observed_at <= upper_bound,
        )
        .with_for_update()
    )
    if incident is not None:
        return incident

    stale_incidents = db.scalars(
        select(Incident)
        .where(
            Incident.correlation_key == group,
            (Incident.last_observed_at < lower_bound) | (Incident.last_observed_at > upper_bound),
        )
        .with_for_update()
    ).all()
    for stale in stale_incidents:
        stale_key = hashlib.sha256(
            f"stale:{stale.id}:{stale.last_observed_at}".encode()
        ).hexdigest()
        stale.correlation_key = stale_key
        db.add(
            IncidentAuditEntry(
                incident_id=stale.id,
                action="correlation_window_elapsed",
                previous_value=group,
                new_value=stale_key,
            )
        )
    return None


def _record_alert(incident: Incident, alert: DetectionAlert) -> None:
    event_time = _utc(alert.last_observed_at)
    incident.first_observed_at = min(
        _utc(incident.first_observed_at), _utc(alert.first_observed_at)
    )
    incident.last_observed_at = max(_utc(incident.last_observed_at), event_time)
    incident.resource_arns = list(dict.fromkeys([*incident.resource_arns, *alert.resource_arns]))
    incident.principal_id = incident.principal_id or alert.principal_id
    incident.principal_arn = incident.principal_arn or alert.principal_arn
    incident.source_ip = incident.source_ip or alert.source_ip
    severity_rank = _SEVERITY_RANK[alert.severity]
    incident_severity_rank = _SEVERITY_RANK[incident.severity]
    if severity_rank > incident_severity_rank or (
        severity_rank == incident_severity_rank and alert.risk_score > incident.risk_score
    ):
        incident.severity = alert.severity
        incident.risk_score = alert.risk_score
        incident.score_basis = alert.score_basis


def _link_alert(db: Session, incident: Incident, alert: DetectionAlert) -> None:
    association = db.scalar(
        select(IncidentAlert).where(
            IncidentAlert.incident_id == incident.id,
            IncidentAlert.alert_id == alert.id,
        )
    )
    if association is not None:
        return
    try:
        with db.begin_nested():
            db.add(IncidentAlert(incident_id=incident.id, alert_id=alert.id))
            db.flush()
    except IntegrityError:
        association = db.scalar(
            select(IncidentAlert).where(
                IncidentAlert.incident_id == incident.id,
                IncidentAlert.alert_id == alert.id,
            )
        )
        if association is None:
            raise
        return
    db.add(
        IncidentAuditEntry(
            incident_id=incident.id,
            action="alert_linked",
            new_value=str(alert.id),
            details={"rule_id": alert.rule_id},
        )
    )


def attach_alert_to_incident(db: Session, alert: DetectionAlert) -> Incident:
    """Attach an alert to a 24-hour active correlation group, creating it if needed."""
    observed_at = _utc(alert.last_observed_at)
    group = _correlation_group(alert)
    prior_link = db.scalar(
        select(IncidentAlert)
        .where(IncidentAlert.alert_id == alert.id)
        .order_by(IncidentAlert.linked_at.desc())
    )

    if prior_link is not None:
        prior_incident = db.get(Incident, prior_link.incident_id)
        if prior_incident is not None and prior_incident.status in _FINAL_STATUSES:
            elapsed = observed_at - _utc(prior_incident.last_observed_at)
            if timedelta(0) < elapsed <= _CORRELATION_WINDOW:
                active = _active_incident(db, group, observed_at)
                if active is not None:
                    _record_alert(active, alert)
                    _link_alert(db, active, alert)
                    return active
                previous_status = prior_incident.status
                prior_incident.status = "new"
                prior_incident.correlation_key = group
                _record_alert(prior_incident, alert)
                db.add(
                    IncidentAuditEntry(
                        incident_id=prior_incident.id,
                        action="reopened_by_detection",
                        previous_value=previous_status,
                        new_value="new",
                        details={"alert_id": str(alert.id)},
                    )
                )
                return prior_incident
        elif (
            prior_incident is not None
            and abs(observed_at - _utc(prior_incident.last_observed_at)) <= _CORRELATION_WINDOW
        ):
            _record_alert(prior_incident, alert)
            return prior_incident

    incident = _active_incident(db, group, observed_at)
    if incident is None:
        incident = Incident(
            correlation_key=group,
            correlation_group=group,
            title=alert.title,
            description=alert.description,
            status="new",
            severity=alert.severity,
            risk_score=alert.risk_score,
            score_basis=alert.score_basis,
            account_id=alert.account_id,
            region=alert.region,
            principal_id=alert.principal_id,
            principal_arn=alert.principal_arn,
            source_ip=alert.source_ip,
            resource_arns=list(alert.resource_arns),
            first_observed_at=_utc(alert.first_observed_at),
            last_observed_at=observed_at,
        )
        try:
            with db.begin_nested():
                db.add(incident)
                db.flush()
        except IntegrityError:
            incident = _active_incident(db, group, observed_at)
            if incident is None:
                raise
        else:
            db.add(
                IncidentAuditEntry(
                    incident_id=incident.id,
                    action="created",
                    details={"alert_id": str(alert.id), "rule_id": alert.rule_id},
                )
            )
    else:
        _record_alert(incident, alert)

    _link_alert(db, incident, alert)
    return incident
