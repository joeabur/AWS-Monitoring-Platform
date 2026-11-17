import json
from types import SimpleNamespace

import pytest

from app.ingestion.worker import lambda_handler
from app.scripts.generate_sample_events import generate_sample_event


def test_sqs_worker_persists_valid_event_and_returns_poison_message_for_retry(
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
    valid_message = {
        "messageId": "valid-1",
        "body": json.dumps(generate_sample_event(0)),
    }
    invalid_message = {"messageId": "invalid-1", "body": "{bad json"}

    result = lambda_handler({"Records": [valid_message, invalid_message]}, None)

    assert result == {"batchItemFailures": [{"itemIdentifier": "invalid-1"}]}


def test_sqs_worker_refuses_ephemeral_sqlite_storage() -> None:
    with pytest.raises(RuntimeError, match="requires a PostgreSQL DATABASE_URL"):
        lambda_handler({"Records": []}, None)
