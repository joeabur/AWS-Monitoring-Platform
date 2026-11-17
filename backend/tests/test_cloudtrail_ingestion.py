from datetime import UTC, datetime

import pytest

from app.ingestion.cloudtrail import EventNormalizationError, normalize_cloudtrail_event
from app.ingestion.service import ingest_cloudtrail_event
from app.models import CloudTrailEvent
from app.scripts.generate_sample_events import generate_sample_event


def cloudtrail_event(
    event_id: str = "test-event-1",
    *,
    event_time: str = "2026-01-02T03:04:05-05:00",
) -> dict[str, object]:
    return {
        "version": "0",
        "account": "123456789012",
        "region": "us-east-1",
        "detail": {
            "eventID": event_id,
            "eventTime": event_time,
            "eventSource": "ec2.amazonaws.com",
            "eventName": "DescribeInstances",
            "awsRegion": "us-east-1",
            "recipientAccountId": "123456789012",
            "sourceIPAddress": "203.0.113.12",
            "userIdentity": {
                "type": "AssumedRole",
                "principalId": "AROATEST:analyst",
                "arn": "arn:aws:sts::123456789012:assumed-role/Analyst/analyst",
            },
            "requestParameters": {
                "password": "do-not-store",
                "filters": [{"name": "tag:env", "values": ["test"]}],
            },
            "resources": [{"ARN": "arn:aws:ec2:us-east-1:123456789012:instance/i-example"}],
        },
    }


def test_normalization_extracts_utc_context_and_redacts_sensitive_detail() -> None:
    event = normalize_cloudtrail_event(cloudtrail_event())

    assert event["event_time"] == datetime(2026, 1, 2, 8, 4, 5, tzinfo=UTC)
    assert event["account_id"] == "123456789012"
    assert event["principal_type"] == "AssumedRole"
    assert event["source_ip"] == "203.0.113.12"
    assert event["resource_arns"] == ["arn:aws:ec2:us-east-1:123456789012:instance/i-example"]
    assert event["event_details"]["requestParameters"]["password"] == "[REDACTED]"


@pytest.mark.parametrize(
    ("event", "message"),
    [
        ({}, "12-digit AWS account"),
        (cloudtrail_event(event_time="2026-01-02T03:04:05"), "must include a timezone"),
    ],
)
def test_normalization_rejects_missing_or_ambiguous_context(
    event: dict[str, object], message: str
) -> None:
    with pytest.raises(EventNormalizationError, match=message):
        normalize_cloudtrail_event(event)


def test_ingestion_is_idempotent_and_stores_only_one_record(db_session) -> None:
    raw_event = cloudtrail_event()

    first = ingest_cloudtrail_event(db_session, raw_event)
    second = ingest_cloudtrail_event(db_session, raw_event)

    assert not first.duplicate
    assert second.duplicate
    assert first.event.id == second.event.id
    assert db_session.query(CloudTrailEvent).count() == 1


def test_synthetic_generator_marks_data_as_synthetic(db_session) -> None:
    raw_event = generate_sample_event(0, now=datetime(2026, 1, 1, tzinfo=UTC))

    result = ingest_cloudtrail_event(db_session, raw_event, is_synthetic=True)

    assert result.event.is_synthetic
    assert result.event.account_id == "111122223333"
