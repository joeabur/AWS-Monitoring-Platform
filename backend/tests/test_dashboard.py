from datetime import UTC, datetime, timedelta
from uuid import uuid4

from app.core.config import MonitoredAwsAccount, Settings
from app.models import AwsIntegrationHealth
from app.scripts.generate_sample_events import generate_sample_event


def _bearer(client) -> dict[str, str]:
    login = client.post(
        "/api/v1/auth/login",
        json={"email": "analyst@example.com", "password": "correct-horse-battery"},
    )
    assert login.status_code == 200
    return {"Authorization": f"Bearer {login.json()['access_token']}"}


def test_dashboard_summary_uses_persisted_events_alerts_and_incidents(client, monkeypatch) -> None:
    headers = _bearer(client)
    account = MonitoredAwsAccount(account_id="111122223333", name="production")
    monkeypatch.setattr(
        "app.api.dashboard.get_settings",
        lambda: Settings(monitored_aws_accounts=[account]),
    )
    event = generate_sample_event(0)
    event["detail"]["userIdentity"] = {
        "type": "Root",
        "principalId": "111122223333",
        "arn": "arn:aws:iam::111122223333:root",
    }
    ingested = client.post("/api/v1/events/ingest", json=event, headers=headers)

    summary = client.get(
        "/api/v1/dashboard/summary?account_id=111122223333&region=us-east-1",
        headers=headers,
    )
    critical = client.get(
        "/api/v1/dashboard/summary?severity=critical",
        headers=headers,
    )

    assert ingested.status_code == 200
    assert summary.status_code == critical.status_code == 200
    assert summary.json()["metrics"] == {
        "total_events": 1,
        "total_alerts": 1,
        "open_incidents": 1,
        "critical_high_incidents": 1,
        "guardduty_findings": 0,
        "securityhub_findings": 0,
        "monitored_accounts": 1,
        "monitored_regions": 0,
        "notifications_pending": 0,
        "notifications_failed": 0,
        "active_audit_failures": 0,
    }
    assert summary.json()["recent_events"][0]["is_synthetic"] is False
    assert summary.json()["recent_incidents"][0]["severity"] == "critical"
    assert summary.json()["latest_audit_report"] is None
    assert summary.json()["audit_findings"] == []
    assert critical.json()["metrics"]["total_alerts"] == 1
    assert critical.json()["aws_connection_status"] == "unknown"


def test_dashboard_requires_auth_and_rejects_timezone_naive_range(client) -> None:
    assert client.get("/api/v1/dashboard/summary").status_code == 401
    response = client.get(
        "/api/v1/dashboard/summary?since=2026-03-01T12:00:00",
        headers=_bearer(client),
    )
    assert response.status_code == 422


def test_dashboard_scopes_integration_health_to_selected_account_and_region(
    client, db_session, monkeypatch
) -> None:
    headers = _bearer(client)
    accounts = [
        MonitoredAwsAccount(account_id="111122223333", name="production"),
        MonitoredAwsAccount(account_id="444455556666", name="staging"),
    ]
    monkeypatch.setattr(
        "app.api.dashboard.get_settings",
        lambda: Settings(monitored_aws_accounts=accounts),
    )
    checked_at = datetime.now(UTC) - timedelta(minutes=5)
    db_session.add_all(
        [
            AwsIntegrationHealth(
                id=uuid4(),
                account_id="111122223333",
                integration="sts",
                region="",
                status="unhealthy",
                resource_count=0,
                last_checked_at=checked_at,
                last_success_at=None,
            ),
            AwsIntegrationHealth(
                id=uuid4(),
                account_id="444455556666",
                integration="sts",
                region="",
                status="healthy",
                resource_count=3,
                last_checked_at=checked_at,
                last_success_at=checked_at,
            ),
            AwsIntegrationHealth(
                id=uuid4(),
                account_id="444455556666",
                integration="guardduty",
                region="us-west-2",
                status="unhealthy",
                last_error_code="AccessDenied",
                resource_count=0,
                last_checked_at=checked_at,
                last_success_at=None,
            ),
            AwsIntegrationHealth(
                id=uuid4(),
                account_id="444455556666",
                integration="securityhub",
                region="us-east-1",
                status="healthy",
                resource_count=2,
                last_checked_at=checked_at,
                last_success_at=checked_at,
            ),
        ]
    )
    db_session.commit()

    response = client.get(
        "/api/v1/dashboard/summary?account_id=444455556666&region=us-west-2",
        headers=headers,
    )

    assert response.status_code == 200
    body = response.json()
    assert body["aws_connection_status"] == "healthy"
    assert [(item["integration"], item["region"]) for item in body["integrations"]] == [
        ("guardduty", "us-west-2"),
        ("sts", ""),
    ]
