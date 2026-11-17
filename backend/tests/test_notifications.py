from datetime import UTC, datetime, timedelta

from app.core.config import Settings
from app.models import NotificationDelivery
from app.notifications.service import (
    NotificationDeliveryError,
    dispatch_due_notifications,
)
from app.scripts.generate_sample_events import generate_sample_event


def _bearer(client, email: str) -> dict[str, str]:
    login = client.post(
        "/api/v1/auth/login",
        json={"email": email, "password": "correct-horse-battery"},
    )
    assert login.status_code == 200
    return {"Authorization": f"Bearer {login.json()['access_token']}"}


def test_alert_outbox_is_deduplicated_and_delivery_retry_is_tracked(
    client, db_session, monkeypatch
) -> None:
    settings = Settings(slack_webhook_url="https://hooks.example.invalid/services/private")
    monkeypatch.setattr("app.ingestion.service.get_settings", lambda: settings)
    headers = _bearer(client, "analyst@example.com")
    event = generate_sample_event(0)
    event["detail"]["userIdentity"] = {
        "type": "Root",
        "principalId": "111122223333",
        "arn": "arn:aws:iam::111122223333:root",
    }

    first = client.post("/api/v1/events/ingest", json=event, headers=headers)
    replay = client.post("/api/v1/events/ingest", json=event, headers=headers)
    delivery = db_session.query(NotificationDelivery).one()
    calls = 0

    def fail_delivery(*_) -> None:
        nonlocal calls
        calls += 1
        raise NotificationDeliveryError("TestTransportFailure")

    failed = dispatch_due_notifications(
        db_session,
        settings,
        senders={"slack": fail_delivery},
    )

    assert first.status_code == replay.status_code == 200
    assert first.json()["alert_ids"]
    assert replay.json()["duplicate"] is True
    assert replay.json()["alert_ids"] == []
    assert db_session.query(NotificationDelivery).count() == 1
    assert failed == {"selected": 1, "sent": 0, "retrying": 1, "failed": 0}
    assert calls == 1
    assert delivery.status == "retrying"
    assert delivery.last_error_code == "TestTransportFailure"
    assert delivery.next_attempt_at.replace(tzinfo=UTC) > datetime.now(UTC)

    delivery.next_attempt_at = datetime.now(UTC) - timedelta(seconds=1)
    db_session.commit()
    delivered = dispatch_due_notifications(
        db_session,
        settings,
        senders={"slack": lambda *_: None},
    )

    assert delivered == {"selected": 1, "sent": 1, "retrying": 0, "failed": 0}
    assert delivery.status == "delivered"
    assert delivery.attempt_count == 2
    assert delivery.delivered_at is not None


def test_notification_configuration_hides_webhook_and_admin_controls_processing(
    client, monkeypatch
) -> None:
    settings = Settings(
        slack_webhook_url="https://hooks.example.invalid/services/private-token",
        notification_min_severity="critical",
    )
    monkeypatch.setattr("app.api.notifications.get_settings", lambda: settings)
    viewer_headers = _bearer(client, "viewer@example.com")
    analyst_headers = _bearer(client, "analyst@example.com")

    config = client.get("/api/v1/notifications/config", headers=viewer_headers)
    viewer_process = client.post("/api/v1/notifications/process", headers=viewer_headers)
    analyst_process = client.post("/api/v1/notifications/process", headers=analyst_headers)

    assert config.status_code == 200
    assert config.json() == {
        "minimum_severity": "critical",
        "channels": [
            {"channel": "email", "enabled": False},
            {"channel": "slack", "enabled": True},
            {"channel": "teams", "enabled": False},
        ],
    }
    assert "private-token" not in config.text
    assert viewer_process.status_code == analyst_process.status_code == 403
