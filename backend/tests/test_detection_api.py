from datetime import UTC, datetime, timedelta

from app.models import DetectionAlert
from app.scripts.generate_sample_events import generate_sample_event


def bearer(client, email: str = "analyst@example.com") -> dict[str, str]:
    login = client.post(
        "/api/v1/auth/login",
        json={"email": email, "password": "correct-horse-battery"},
    )
    assert login.status_code == 200
    return {"Authorization": f"Bearer {login.json()['access_token']}"}


def console_event(index: int, event_time: datetime) -> dict[str, object]:
    event = generate_sample_event(index, now=event_time)
    detail = event["detail"]
    detail["eventSource"] = "signin.amazonaws.com"
    detail["eventName"] = "ConsoleLogin"
    detail["responseElements"] = {"ConsoleLogin": "Failure"}
    detail["userIdentity"] = {
        "type": "IAMUser",
        "principalId": "AIDA-FAILED-LOGIN",
        "arn": "arn:aws:iam::111122223333:user/target",
    }
    return event


def test_root_activity_creates_deduplicated_alert_and_evidence(client, db_session) -> None:
    headers = bearer(client)
    first_event = generate_sample_event(0)
    first_event["detail"]["userIdentity"] = {
        "type": "Root",
        "principalId": "111122223333",
        "arn": "arn:aws:iam::111122223333:root",
    }
    second_event = generate_sample_event(1)
    second_event["detail"]["userIdentity"] = first_event["detail"]["userIdentity"]

    first = client.post("/api/v1/events/ingest", json=first_event, headers=headers)
    second = client.post("/api/v1/events/ingest", json=second_event, headers=headers)

    assert first.status_code == 200
    assert first.json()["alert_ids"]
    assert second.json()["alert_ids"] == first.json()["alert_ids"]
    alert_id = first.json()["alert_ids"][0]
    evidence = client.get(f"/api/v1/alerts/{alert_id}", headers=headers)
    assert evidence.status_code == 200
    assert evidence.json()["alert"]["rule_id"] == "AWS-CT-001"
    assert evidence.json()["alert"]["severity"] == "critical"
    assert evidence.json()["alert"]["observed_count"] == 2
    assert len(evidence.json()["events"]) == 2
    assert len(db_session.query(DetectionAlert).all()) == 1


def test_failed_login_threshold_creates_one_correlated_alert(client) -> None:
    headers = bearer(client)
    first = datetime(2026, 3, 1, tzinfo=UTC)
    responses = [
        client.post(
            "/api/v1/events/ingest",
            json=console_event(index, first + timedelta(minutes=index)),
            headers=headers,
        )
        for index in range(5)
    ]

    assert all(response.status_code == 200 for response in responses)
    assert all(response.json()["alert_ids"] == [] for response in responses[:4])
    assert len(responses[-1].json()["alert_ids"]) == 1
    alerts = client.get("/api/v1/alerts?rule_id=AWS-CT-002", headers=headers)
    assert alerts.status_code == 200
    assert alerts.json()["total"] == 1
    assert alerts.json()["items"][0]["observed_count"] == 5
    assert len(alerts.json()["items"][0]["event_refs"]) == 5


def test_detection_inventory_and_test_endpoint_do_not_persist(client, db_session) -> None:
    headers = bearer(client)
    inventory = client.get("/api/v1/detections", headers=headers)
    sample = generate_sample_event(0)
    sample["detail"]["userIdentity"]["type"] = "Root"
    tested = client.post(
        "/api/v1/detections/AWS-CT-001/test",
        json={"event": sample},
        headers=headers,
    )

    assert inventory.status_code == 200
    assert len(inventory.json()) == 19
    assert tested.status_code == 200
    assert tested.json()["synthetic_test"] is True
    assert tested.json()["results"][0]["matched"] is True
    assert db_session.query(DetectionAlert).count() == 0


def test_allowlist_rule_requires_configuration_and_viewer_cannot_test(client) -> None:
    analyst_headers = bearer(client)
    disabled = client.post(
        "/api/v1/detections/AWS-CT-010/test",
        json={"event": generate_sample_event(0)},
        headers=analyst_headers,
    )
    viewer_headers = bearer(client, "viewer@example.com")
    denied = client.post(
        "/api/v1/detections/AWS-CT-001/test",
        json={"event": generate_sample_event(0)},
        headers=viewer_headers,
    )

    assert disabled.status_code == 409
    assert denied.status_code == 403


def test_guardduty_finding_event_generates_alert(client) -> None:
    headers = bearer(client)
    finding = {
        "version": "0",
        "id": "event-envelope-id",
        "detail-type": "GuardDuty Finding",
        "source": "aws.guardduty",
        "account": "111122223333",
        "time": "2026-03-01T12:00:00Z",
        "region": "us-east-1",
        "detail": {
            "id": "finding-id-1",
            "accountId": "111122223333",
            "region": "us-east-1",
            "type": "CredentialAccess:IAMUser/AnomalousBehavior",
            "severity": 8.0,
            "createdAt": "2026-03-01T12:00:00Z",
            "resource": {"resourceType": "AccessKey", "accessKeyDetails": {"userName": "demo"}},
            "service": {
                "action": {
                    "networkConnectionAction": {"remoteIpDetails": {"ipAddressV4": "203.0.113.11"}}
                }
            },
        },
    }

    response = client.post("/api/v1/events/ingest", json=finding, headers=headers)

    assert response.status_code == 200
    assert len(response.json()["alert_ids"]) == 1
    alert = client.get(f"/api/v1/alerts/{response.json()['alert_ids'][0]}", headers=headers)
    assert alert.json()["alert"]["rule_id"] == "AWS-GD-011"
    assert alert.json()["alert"]["severity"] == "high"


def test_noncompliant_config_event_generates_security_group_alert(client) -> None:
    headers = bearer(client)
    config_event = {
        "version": "0",
        "id": "config-event-1",
        "detail-type": "Config Rules Compliance Change",
        "source": "aws.config",
        "account": "111122223333",
        "time": "2026-03-01T12:00:00Z",
        "region": "us-east-1",
        "detail": {
            "awsAccountId": "111122223333",
            "awsRegion": "us-east-1",
            "messageType": "Config Rules Compliance Change",
            "resourceType": "AWS::EC2::SecurityGroup",
            "resourceId": "sg-example",
            "newEvaluationResult": {"complianceType": "NON_COMPLIANT"},
        },
    }

    response = client.post("/api/v1/events/ingest", json=config_event, headers=headers)

    assert response.status_code == 200
    assert len(response.json()["alert_ids"]) == 1
    alert = client.get(f"/api/v1/alerts/{response.json()['alert_ids'][0]}", headers=headers)
    assert alert.json()["alert"]["rule_id"] == "AWS-CT-009"


def test_resolved_securityhub_finding_does_not_generate_alert(client) -> None:
    headers = bearer(client)
    finding = {
        "version": "0",
        "id": "resolved-securityhub-finding",
        "detail-type": "Security Hub Findings - Imported",
        "source": "aws.securityhub",
        "account": "111122223333",
        "time": "2026-03-01T12:00:00Z",
        "region": "us-east-1",
        "detail": {
            "id": "resolved-securityhub-finding",
            "accountId": "111122223333",
            "region": "us-east-1",
            "title": "Previously resolved critical finding",
            "createdAt": "2026-03-01T11:00:00Z",
            "updatedAt": "2026-03-01T12:00:00Z",
            "recordState": "ACTIVE",
            "workflow": {"status": "RESOLVED"},
            "severity": {"label": "CRITICAL", "normalized": 95},
        },
    }

    response = client.post("/api/v1/events/ingest", json=finding, headers=headers)

    assert response.status_code == 200
    assert response.json()["alert_ids"] == []
