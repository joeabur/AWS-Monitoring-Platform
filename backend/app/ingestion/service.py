import hashlib
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.detections.engine import DetectionMatch, evaluate_event
from app.incidents.correlation import attach_alert_to_incident
from app.ingestion.cloudtrail import normalize_cloudtrail_event
from app.models import AwsFinding, CloudTrailEvent, DetectionAlert


@dataclass(frozen=True)
class IngestResult:
    event: CloudTrailEvent
    duplicate: bool
    alerts: tuple[DetectionAlert, ...] = ()


def _finding_status(provider: str, details: dict[str, object]) -> tuple[str, str | None, str]:
    finding = details.get("finding")
    finding_data = finding if isinstance(finding, dict) else {}
    if provider == "config":
        evaluation = details.get("newEvaluationResult")
        compliance = evaluation.get("complianceType") if isinstance(evaluation, dict) else None
        status_value = str(compliance or "unknown").lower()
        title = str(details.get("configRuleName") or "AWS Config compliance evaluation")
        return status_value, None, title

    workflow = finding_data.get("workflow", {})
    record_state = finding_data.get("recordState")
    workflow_status = workflow.get("status") if isinstance(workflow, dict) else None
    status_value = str(workflow_status or record_state or "active").lower()
    title = str(finding_data.get("title") or details.get("title") or "AWS security finding")
    severity_data = finding_data.get("severity")
    if provider == "guardduty":
        try:
            score = float(severity_data)
        except (TypeError, ValueError):
            return status_value, None, title
        severity = (
            "critical"
            if score >= 9
            else "high"
            if score >= 7
            else "medium"
            if score >= 4
            else "low"
        )
        return status_value, severity, title

    if isinstance(severity_data, dict):
        label = severity_data.get("label")
        if isinstance(label, str):
            return status_value, label.lower(), title
        normalized = severity_data.get("normalized")
        try:
            score = float(normalized)
        except (TypeError, ValueError):
            return status_value, None, title
        severity = (
            "critical"
            if score >= 90
            else "high"
            if score >= 70
            else "medium"
            if score >= 40
            else "low"
        )
        return status_value, severity, title
    return status_value, None, title


def _utc_datetime(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _upsert_aws_finding(db: Session, event: CloudTrailEvent) -> None:
    provider = {
        "guardduty.amazonaws.com": "guardduty",
        "securityhub.amazonaws.com": "securityhub",
        "config.amazonaws.com": "config",
    }.get(event.event_source)
    if provider is None:
        return

    details = event.event_details
    finding = details.get("finding")
    finding_data = finding if isinstance(finding, dict) else {}
    external_id = finding_data.get("id") or details.get("id")
    if provider == "config":
        external_id = f"{details.get('configRuleName', '')}:{details.get('resourceId', '')}"
    if not isinstance(external_id, str) or not external_id:
        return

    status_value, severity, title = _finding_status(provider, details)
    updated_at = event.event_time
    if isinstance(finding_data.get("updatedAt"), str):
        try:
            parsed_updated_at = datetime.fromisoformat(finding_data["updatedAt"])
            if parsed_updated_at.tzinfo is not None and parsed_updated_at.utcoffset() is not None:
                updated_at = parsed_updated_at.astimezone(UTC)
        except ValueError:
            pass
    created_at = event.event_time
    if isinstance(finding_data.get("createdAt"), str):
        try:
            parsed_created_at = datetime.fromisoformat(finding_data["createdAt"])
            if parsed_created_at.tzinfo is not None and parsed_created_at.utcoffset() is not None:
                created_at = parsed_created_at.astimezone(UTC)
        except ValueError:
            pass

    record = db.scalar(
        select(AwsFinding)
        .where(
            AwsFinding.provider == provider,
            AwsFinding.account_id == event.account_id,
            AwsFinding.region == event.region,
            AwsFinding.external_finding_id == external_id,
        )
        .with_for_update()
    )
    if record is None:
        record = AwsFinding(
            provider=provider,
            external_finding_id=external_id,
            account_id=event.account_id,
            region=event.region,
            title=title[:512],
            severity=severity,
            status=status_value[:32],
            resource_arns=list(event.resource_arns),
            first_observed_at=created_at,
            last_observed_at=event.event_time,
            last_updated_at=updated_at,
            latest_event_id=event.id,
        )
        try:
            with db.begin_nested():
                db.add(record)
                db.flush()
        except IntegrityError:
            record = db.scalar(
                select(AwsFinding)
                .where(
                    AwsFinding.provider == provider,
                    AwsFinding.account_id == event.account_id,
                    AwsFinding.region == event.region,
                    AwsFinding.external_finding_id == external_id,
                )
                .with_for_update()
            )
            if record is None:
                raise
    if _utc_datetime(record.last_updated_at) <= _utc_datetime(updated_at):
        record.title = title[:512]
        record.severity = severity
        record.status = status_value[:32]
        record.last_updated_at = _utc_datetime(updated_at)
        record.resource_arns = list(event.resource_arns)
        record.latest_event_id = event.id
    record.first_observed_at = min(
        _utc_datetime(record.first_observed_at), _utc_datetime(created_at)
    )
    record.last_observed_at = max(
        _utc_datetime(record.last_observed_at), _utc_datetime(event.event_time)
    )


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
        _upsert_aws_finding(db, record)
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
