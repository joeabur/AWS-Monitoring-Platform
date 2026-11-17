import hashlib
from dataclasses import dataclass
from datetime import UTC, timedelta

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.detections.engine import DetectionMatch, evaluate_event
from app.incidents.correlation import attach_alert_to_incident
from app.ingestion.cloudtrail import normalize_cloudtrail_event
from app.models import CloudTrailEvent, DetectionAlert


@dataclass(frozen=True)
class IngestResult:
    event: CloudTrailEvent
    duplicate: bool
    alerts: tuple[DetectionAlert, ...] = ()


def _update_alert(
    alert: DetectionAlert,
    match: DetectionMatch,
    event: CloudTrailEvent,
    evidence_refs: list[str],
) -> DetectionAlert:
    event_time = (
        event.event_time
        if event.event_time.tzinfo is not None
        else event.event_time.replace(tzinfo=UTC)
    )
    existing_refs = set(alert.event_refs)
    if str(event.id) not in existing_refs:
        alert.observed_count += 1
    alert.event_refs = list(dict.fromkeys([*alert.event_refs, *evidence_refs]))
    alert.observed_count = max(alert.observed_count, match.observed_count)
    last_observed = (
        alert.last_observed_at
        if alert.last_observed_at.tzinfo is not None
        else alert.last_observed_at.replace(tzinfo=UTC)
    )
    first_observed = (
        alert.first_observed_at
        if alert.first_observed_at.tzinfo is not None
        else alert.first_observed_at.replace(tzinfo=UTC)
    )
    alert.last_observed_at = max(last_observed, event_time)
    if event_time < first_observed:
        alert.first_observed_at = event_time
    return alert


def _save_alerts(
    db: Session,
    event: CloudTrailEvent,
    context: list[CloudTrailEvent],
    matches: list[DetectionMatch],
) -> tuple[DetectionAlert, ...]:
    alerts: list[DetectionAlert] = []
    records_by_event_id = {record.cloudtrail_event_id: record for record in context}
    for match in matches:
        dedup_key = hashlib.sha256(match.dedup_key.encode()).hexdigest()
        evidence_refs = [
            str(records_by_event_id[event_id].id)
            for event_id in match.event_ids
            if event_id in records_by_event_id
        ]
        existing = db.scalar(
            select(DetectionAlert).where(DetectionAlert.dedup_key == dedup_key).with_for_update()
        )
        if existing is not None:
            alerts.append(_update_alert(existing, match, event, evidence_refs))
            continue

        rule = match.rule
        alert = DetectionAlert(
            dedup_key=dedup_key,
            rule_id=rule.rule_id,
            rule_version=rule.version,
            title=match.title,
            description=match.description,
            severity=match.severity,
            risk_score=match.risk_score,
            score_basis=(
                f"Rule-defined relative prioritization, not a probability; "
                f"severity={match.severity}, base score={match.risk_score}/100."
            ),
            account_id=event.account_id,
            region=event.region,
            principal_id=event.principal_id,
            principal_arn=event.principal_arn,
            source_ip=event.source_ip,
            resource_arns=event.resource_arns,
            event_refs=evidence_refs,
            observed_count=match.observed_count,
            mitre_technique_id=rule.mitre_technique_id,
            mitre_technique_name=rule.mitre_technique_name,
            investigation_steps=list(rule.investigation_steps),
            response_recommendations=list(rule.response_recommendations),
            status="open",
            first_observed_at=event.event_time,
            last_observed_at=event.event_time,
        )
        try:
            with db.begin_nested():
                db.add(alert)
                db.flush()
        except IntegrityError:
            existing = db.scalar(
                select(DetectionAlert)
                .where(DetectionAlert.dedup_key == dedup_key)
                .with_for_update()
            )
            if existing is None:
                raise
            alert = _update_alert(existing, match, event, evidence_refs)
        alerts.append(alert)
    return tuple(alerts)


def ingest_cloudtrail_event(
    db: Session, event: dict[str, object], *, is_synthetic: bool = False
) -> IngestResult:
    normalized = normalize_cloudtrail_event(event, is_synthetic=is_synthetic)
    existing = db.scalar(
        select(CloudTrailEvent).where(CloudTrailEvent.event_key == normalized["event_key"])
    )
    if existing is not None:
        return IngestResult(event=existing, duplicate=True)

    record = CloudTrailEvent(**normalized)
    db.add(record)
    try:
        db.flush()
        context = list(
            db.scalars(
                select(CloudTrailEvent)
                .where(
                    CloudTrailEvent.account_id == record.account_id,
                    CloudTrailEvent.event_time >= record.event_time - timedelta(minutes=60),
                    CloudTrailEvent.event_time <= record.event_time,
                )
                .order_by(CloudTrailEvent.event_time.desc())
                .limit(1000)
            ).all()
        )
        matches = evaluate_event(record, context, get_settings())
        alerts = _save_alerts(db, record, context, matches)
        for alert in alerts:
            attach_alert_to_incident(db, alert)
        db.commit()
        db.refresh(record)
        for alert in alerts:
            db.refresh(alert)
        return IngestResult(event=record, duplicate=False, alerts=alerts)
    except IntegrityError:
        db.rollback()
        existing = db.scalar(
            select(CloudTrailEvent).where(CloudTrailEvent.event_key == normalized["event_key"])
        )
        if existing is None:
            raise
        return IngestResult(event=existing, duplicate=True)
