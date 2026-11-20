import json
from types import SimpleNamespace

import pytest

from app.ingestion.worker import lambda_handler
from app.models import AwsFinding
from app.scripts.generate_sample_events import generate_sample_event


def test_sqs_worker_persists_valid_event_and_returns_poison_message_for_retry(
    db_session, monkeypatch, capsys
) -> None:
    class SessionFactory:
        def __call__(self):
            return db_session

    monkeypatch.setattr(
        "app.ingestion.worker.get_settings",
        lambda: SimpleNamespace(database_url="postgresql+psycopg://test"),
    )
    monkeypatch.setattr("app.ingestion.worker.get_session_factory", lambda: SessionFactory())
    valid_message = {
        "messageId": "valid-1",
        "body": json.dumps(generate_sample_event(0)),
    }
    invalid_message = {"messageId": "invalid-1", "body": "{bad json"}

    result = lambda_handler({"Records": [valid_message, invalid_message]}, None)

    assert result == {"batchItemFailures": [{"itemIdentifier": "invalid-1"}]}
    metric = json.loads(capsys.readouterr().out.splitlines()[-1])
    assert metric["WorkerMessagesProcessed"] == 1
    assert metric["WorkerMessagesFailed"] == 1


def test_sqs_worker_refuses_ephemeral_sqlite_storage() -> None:
    with pytest.raises(RuntimeError, match="requires a PostgreSQL DATABASE_URL"):
        lambda_handler({"Records": []}, None)


def test_sqs_worker_splits_securityhub_findings_and_normalizes_asff_keys(
    db_session, monkeypatch
) -> None:
    class SessionFactory:
        def __call__(self):
            return db_session

    monkeypatch.setattr(
        "app.ingestion.worker.get_settings",
        lambda: SimpleNamespace(database_url="postgresql+psycopg://test"),
    )
    monkeypatch.setattr("app.ingestion.worker.get_session_factory", lambda: SessionFactory())
    finding_template = {
        "AwsAccountId": "111122223333",
        "Region": "us-east-1",
        "CreatedAt": "2026-03-01T12:00:00Z",
        "UpdatedAt": "2026-03-01T12:05:00Z",
        "Severity": {"Label": "LOW", "Normalized": 20},
        "Workflow": {"Status": "NEW"},
        "Resources": [{"Id": "arn:aws:s3:::example-bucket"}],
    }
    securityhub_event = {
        "source": "aws.securityhub",
        "detail-type": "Security Hub Findings - Imported",
        "account": "111122223333",
        "region": "us-east-1",
        "time": "2026-03-01T12:05:00Z",
        "detail": {
            "findings": [
                {**finding_template, "Id": "securityhub-finding-1", "Title": "Finding one"},
                {**finding_template, "Id": "securityhub-finding-2", "Title": "Finding two"},
            ]
        },
    }

    result = lambda_handler(
        {"Records": [{"messageId": "securityhub-1", "body": json.dumps(securityhub_event)}]},
        None,
    )

    assert result == {"batchItemFailures": []}
    assert db_session.query(AwsFinding).count() == 2
    assert {finding.provider for finding in db_session.query(AwsFinding).all()} == {"securityhub"}
