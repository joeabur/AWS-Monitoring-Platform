from datetime import UTC, datetime, timedelta
from uuid import uuid4

from sqlalchemy import select

from app.models import CloudTrailEvent, DetectionAlert
from app.scripts.prune_events import prune_expired_events


def _event(*, old: bool) -> CloudTrailEvent:
    return CloudTrailEvent(
        id=uuid4(),
        event_key=uuid4().hex,
        cloudtrail_event_id=uuid4().hex,
        account_id="111122223333",
        region="us-east-1",
        event_source="ec2.amazonaws.com",
        event_name="DescribeInstances",
        event_time=datetime.now(UTC) - (timedelta(days=120) if old else timedelta(days=1)),
        source_ip=None,
        principal_type=None,
        principal_id=None,
        principal_arn=None,
        user_agent=None,
        error_code=None,
        resource_arns=[],
        event_details={},
        is_synthetic=False,
    )


def test_retention_preview_is_non_destructive_and_preserves_alert_evidence(db_session) -> None:
    linked_event = _event(old=True)
    unlinked_event = _event(old=True)
    recent_event = _event(old=False)
    db_session.add_all([linked_event, unlinked_event, recent_event])
    db_session.flush()
    db_session.add(
        DetectionAlert(
            id=uuid4(),
            dedup_key=uuid4().hex,
            rule_id="test-rule",
            rule_version=1,
            title="Test alert",
            description="Test alert description",
            severity="low",
            risk_score=10,
            score_basis="Test-only priority.",
            account_id=linked_event.account_id,
            region=linked_event.region,
            resource_arns=[],
            event_refs=[str(linked_event.id)],
            observed_count=1,
            investigation_steps=[],
            response_recommendations=[],
            status="open",
            first_observed_at=linked_event.event_time,
            last_observed_at=linked_event.event_time,
        )
    )
    db_session.commit()

    result = prune_expired_events(db_session, older_than_days=90)

    assert result == {
        "dry_run": True,
        "older_than_days": 90,
        "scanned": 2,
        "eligible_for_deletion": 2,
        "expired_alert_references": 1,
        "alerts_updated": 1,
    }
    assert db_session.scalar(select(CloudTrailEvent).where(CloudTrailEvent.id == linked_event.id))
    assert db_session.scalar(select(CloudTrailEvent).where(CloudTrailEvent.id == unlinked_event.id))
    assert db_session.scalar(select(CloudTrailEvent).where(CloudTrailEvent.id == recent_event.id))


def test_retention_apply_removes_expired_events_and_alert_evidence_references(db_session) -> None:
    linked_event = _event(old=True)
    unlinked_event = _event(old=True)
    db_session.add_all([linked_event, unlinked_event])
    db_session.flush()
    db_session.add(
        DetectionAlert(
            id=uuid4(),
            dedup_key=uuid4().hex,
            rule_id="test-rule",
            rule_version=1,
            title="Test alert",
            description="Test alert description",
            severity="low",
            risk_score=10,
            score_basis="Test-only priority.",
            account_id=linked_event.account_id,
            region=linked_event.region,
            resource_arns=[],
            event_refs=[str(linked_event.id)],
            observed_count=1,
            investigation_steps=[],
            response_recommendations=[],
            status="open",
            first_observed_at=linked_event.event_time,
            last_observed_at=linked_event.event_time,
        )
    )
    db_session.commit()

    result = prune_expired_events(db_session, older_than_days=90, apply=True, batch_size=1)

    assert result["dry_run"] is False
    assert result["eligible_for_deletion"] == 2
    assert result["expired_alert_references"] == 1
    assert result["alerts_updated"] == 1
    assert (
        db_session.scalar(select(CloudTrailEvent).where(CloudTrailEvent.id == linked_event.id))
        is None
    )
    assert (
        db_session.scalar(select(CloudTrailEvent).where(CloudTrailEvent.id == unlinked_event.id))
        is None
    )
    alert = db_session.scalar(select(DetectionAlert))
    assert alert is not None
    assert alert.event_refs == []
