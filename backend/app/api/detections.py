from datetime import UTC, datetime, timedelta
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, select

from app.api.dependencies import CurrentUser, Database, require_roles
from app.core.config import get_settings
from app.detections.engine import evaluate_event, is_rule_enabled
from app.detections.rules import RULES, RULES_BY_ID, DetectionRule
from app.ingestion.cloudtrail import EventNormalizationError, normalize_cloudtrail_event
from app.models import CloudTrailEvent, DetectionAlert, User
from app.schemas.auth import UserRole
from app.schemas.detections import (
    AlertEvidenceRead,
    AlertPage,
    AlertRead,
    DetectionEventTestRequest,
    DetectionPreview,
    DetectionRuleRead,
    DetectionTestResponse,
)
from app.schemas.events import CloudTrailEventDetailRead

router = APIRouter(tags=["detections"])


def _rule_read(rule: DetectionRule, enabled: bool) -> DetectionRuleRead:
    return DetectionRuleRead(
        rule_id=rule.rule_id,
        name=rule.name,
        description=rule.description,
        category=rule.category,
        severity=rule.severity,
        risk_score=rule.risk_score,
        mitre_technique_id=rule.mitre_technique_id,
        mitre_technique_name=rule.mitre_technique_name,
        event_sources=list(rule.event_sources),
        required_fields=list(rule.required_fields),
        investigation_steps=list(rule.investigation_steps),
        response_recommendations=list(rule.response_recommendations),
        version=rule.version,
        enabled=enabled,
        threshold=rule.threshold,
        window_minutes=rule.window_minutes,
    )


@router.get("/api/v1/detections", response_model=list[DetectionRuleRead])
def list_detection_rules(_: CurrentUser) -> list[DetectionRuleRead]:
    settings = get_settings()
    return [_rule_read(rule, is_rule_enabled(rule, settings)) for rule in RULES]


@router.get("/api/v1/detections/{rule_id}", response_model=DetectionRuleRead)
def get_detection_rule(rule_id: str, _: CurrentUser) -> DetectionRuleRead:
    rule = RULES_BY_ID.get(rule_id)
    if rule is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Detection rule not found"
        )
    return _rule_read(rule, is_rule_enabled(rule, get_settings()))


@router.post(
    "/api/v1/detections/{rule_id}/test",
    response_model=DetectionTestResponse,
)
def test_detection_rule(
    rule_id: str,
    payload: DetectionEventTestRequest,
    db: Database,
    _: Annotated[
        User,
        Depends(require_roles(UserRole.ADMINISTRATOR, UserRole.SECURITY_ANALYST)),
    ],
) -> DetectionTestResponse:
    rule = RULES_BY_ID.get(rule_id)
    if rule is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Detection rule not found"
        )
    settings = get_settings()
    if not is_rule_enabled(rule, settings):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Rule is disabled until its required allowlist is configured",
        )
    try:
        normalized = normalize_cloudtrail_event(payload.event, is_synthetic=True)
    except EventNormalizationError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=str(exc),
        ) from exc

    candidate = CloudTrailEvent(**normalized)
    context_start = candidate.event_time - timedelta(minutes=60)
    context = list(
        db.scalars(
            select(CloudTrailEvent)
            .where(
                CloudTrailEvent.account_id == candidate.account_id,
                CloudTrailEvent.event_time >= context_start,
                CloudTrailEvent.event_time <= candidate.event_time,
            )
            .order_by(CloudTrailEvent.event_time.desc())
            .limit(1000)
        ).all()
    )
    context = [
        item for item in context if item.cloudtrail_event_id != candidate.cloudtrail_event_id
    ]
    context.append(candidate)
    matches = evaluate_event(candidate, context, settings, rule_ids={rule_id})
    match = matches[0] if matches else None
    return DetectionTestResponse(
        synthetic_test=True,
        results=[
            DetectionPreview(
                rule=_rule_read(rule, True),
                matched=match is not None,
                evidence_event_ids=list(match.event_ids) if match else [],
                observed_count=match.observed_count if match else 0,
            )
        ],
    )


@router.get("/api/v1/alerts", response_model=AlertPage)
def list_alerts(
    db: Database,
    _: CurrentUser,
    severity: Annotated[
        str | None, Query(pattern="^(critical|high|medium|low|informational)$")
    ] = None,
    account_id: Annotated[str | None, Query(pattern=r"^\d{12}$")] = None,
    rule_id: Annotated[str | None, Query(max_length=64)] = None,
    alert_status: Annotated[
        str | None, Query(alias="status", pattern="^(open|acknowledged|suppressed)$")
    ] = None,
    since: datetime | None = None,
    until: datetime | None = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> AlertPage:
    def as_utc(value: datetime | None, name: str) -> datetime | None:
        if value is None:
            return None
        if value.tzinfo is None or value.utcoffset() is None:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail=f"{name} must include a timezone",
            )
        return value.astimezone(UTC)

    start = as_utc(since, "since")
    end = as_utc(until, "until")
    if start is not None and end is not None and end < start:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="until must be greater than or equal to since",
        )

    filters = []
    if severity:
        filters.append(DetectionAlert.severity == severity)
    if account_id:
        filters.append(DetectionAlert.account_id == account_id)
    if rule_id:
        filters.append(DetectionAlert.rule_id == rule_id)
    if alert_status:
        filters.append(DetectionAlert.status == alert_status)
    if start:
        filters.append(DetectionAlert.last_observed_at >= start)
    if end:
        filters.append(DetectionAlert.last_observed_at <= end)

    total = db.scalar(select(func.count()).select_from(DetectionAlert).where(*filters)) or 0
    alerts = db.scalars(
        select(DetectionAlert)
        .where(*filters)
        .order_by(DetectionAlert.last_observed_at.desc(), DetectionAlert.id)
        .limit(limit)
        .offset(offset)
    ).all()
    return AlertPage(items=alerts, total=total, limit=limit, offset=offset)


@router.get("/api/v1/alerts/{alert_id}", response_model=AlertEvidenceRead)
def get_alert_evidence(
    alert_id: UUID,
    db: Database,
    _: CurrentUser,
) -> AlertEvidenceRead:
    alert = db.get(DetectionAlert, alert_id)
    if alert is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Alert not found")
    event_ids = [UUID(value) for value in alert.event_refs]
    events = (
        db.scalars(
            select(CloudTrailEvent)
            .where(CloudTrailEvent.id.in_(event_ids))
            .order_by(CloudTrailEvent.event_time)
        ).all()
        if event_ids
        else []
    )
    return AlertEvidenceRead(
        alert=AlertRead.model_validate(alert),
        events=[CloudTrailEventDetailRead.model_validate(event) for event in events],
    )
