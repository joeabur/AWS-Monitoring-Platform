from datetime import UTC, datetime, timedelta
from uuid import UUID

from sqlalchemy import select

from app.models import IncidentAlert, IncidentAuditEntry
from app.models.incident import InvestigationNote
from app.models.user import User
from app.scripts.generate_sample_events import generate_sample_event


def bearer(client, email: str = "analyst@example.com") -> dict[str, str]:
    login = client.post(
        "/api/v1/auth/login",
        json={"email": email, "password": "correct-horse-battery"},
    )
    assert login.status_code == 200
    return {"Authorization": f"Bearer {login.json()['access_token']}"}


def root_event(index: int, name: str, event_time: datetime) -> dict[str, object]:
    event = generate_sample_event(index, now=event_time)
    detail = event["detail"]
    detail["eventSource"] = (
        "cloudtrail.amazonaws.com" if name == "StopLogging" else "ec2.amazonaws.com"
    )
    detail["eventName"] = name
    detail["userIdentity"] = {
        "type": "Root",
        "principalId": "111122223333",
        "arn": "arn:aws:iam::111122223333:root",
    }
    return event


def create_incident(client, headers) -> UUID:
    event = root_event(0, "DescribeInstances", datetime(2026, 3, 1, tzinfo=UTC))
    response = client.post("/api/v1/events/ingest", json=event, headers=headers)
    assert response.status_code == 200
    incidents = client.get("/api/v1/incidents", headers=headers)
    assert incidents.status_code == 200
    assert incidents.json()["total"] == 1
    return UUID(incidents.json()["items"][0]["id"])


def test_related_alerts_group_in_one_incident_with_timeline(client, db_session) -> None:
    headers = bearer(client)
    first_time = datetime(2026, 3, 1, tzinfo=UTC)
    first = client.post(
        "/api/v1/events/ingest",
        json=root_event(0, "DescribeInstances", first_time),
        headers=headers,
    )
    second = client.post(
        "/api/v1/events/ingest",
        json=root_event(1, "StopLogging", first_time + timedelta(minutes=5)),
        headers=headers,
    )
    replay = client.post(
        "/api/v1/events/ingest",
        json=root_event(1, "StopLogging", first_time + timedelta(minutes=5)),
        headers=headers,
    )

    incidents = client.get("/api/v1/incidents", headers=headers)
    assert first.status_code == second.status_code == replay.status_code == 200
    assert replay.json()["duplicate"] is True
    assert incidents.json()["total"] == 1
    incident_id = incidents.json()["items"][0]["id"]
    detail = client.get(f"/api/v1/incidents/{incident_id}", headers=headers)
    assert detail.status_code == 200
    assert {alert["rule_id"] for alert in detail.json()["alerts"]} == {
        "AWS-CT-001",
        "AWS-CT-007",
    }
    assert len(detail.json()["events"]) == 2
    assert db_session.scalar(
        select(IncidentAlert).where(IncidentAlert.incident_id == UUID(incident_id))
    )
    assert len(detail.json()["timeline"]) >= 4


def test_incident_lifecycle_assignment_notes_and_audit(client, db_session) -> None:
    headers = bearer(client)
    incident_id = create_incident(client, headers)
    analyst = db_session.scalar(select(User).where(User.email == "analyst@example.com"))
    assert analyst is not None

    acknowledged = client.put(
        f"/api/v1/incidents/{incident_id}/status",
        json={"status": "acknowledged"},
        headers=headers,
    )
    assigned = client.put(
        f"/api/v1/incidents/{incident_id}/assignment",
        json={"assigned_to": str(analyst.id)},
        headers=headers,
    )
    note = client.post(
        f"/api/v1/incidents/{incident_id}/notes",
        json={"body": "Validated the actor against the approved change window."},
        headers=headers,
    )

    assert acknowledged.status_code == assigned.status_code == 200
    assert acknowledged.json()["status"] == "acknowledged"
    assert assigned.json()["assigned_to"] == str(analyst.id)
    assert note.status_code == 201
    assert note.json()["author_email"] == analyst.email

    detail = client.get(f"/api/v1/incidents/{incident_id}", headers=headers)
    actions = [entry["action"] for entry in detail.json()["audit_trail"]]
    assert actions.count("status_changed") == 1
    assert "assigned" in actions
    assert "note_added" in actions
    assert detail.json()["notes"][0]["body"].startswith("Validated")
    assert db_session.scalar(
        select(InvestigationNote).where(InvestigationNote.incident_id == incident_id)
    )


def test_incident_mutations_enforce_roles_and_valid_transitions(client, db_session) -> None:
    incident_id = create_incident(client, bearer(client))
    viewer_headers = bearer(client, "viewer@example.com")
    viewer_denied = client.put(
        f"/api/v1/incidents/{incident_id}/status",
        json={"status": "resolved"},
        headers=viewer_headers,
    )
    resolved = client.put(
        f"/api/v1/incidents/{incident_id}/status",
        json={"status": "resolved"},
        headers=bearer(client),
    )
    invalid_transition = client.put(
        f"/api/v1/incidents/{incident_id}/status",
        json={"status": "acknowledged"},
        headers=bearer(client),
    )
    assignment_to_viewer = db_session.scalar(select(User).where(User.email == "viewer@example.com"))
    assert assignment_to_viewer is not None
    invalid_assignee = client.put(
        f"/api/v1/incidents/{incident_id}/assignment",
        json={"assigned_to": str(assignment_to_viewer.id)},
        headers=bearer(client),
    )

    assert viewer_denied.status_code == 403
    assert resolved.status_code == 200
    assert invalid_transition.status_code == 409
    assert invalid_assignee.status_code == 422
    assert (
        db_session.scalar(
            select(IncidentAuditEntry).where(IncidentAuditEntry.incident_id == incident_id)
        )
        is not None
    )


def test_resolution_closes_correlation_and_later_activity_reopens(client) -> None:
    headers = bearer(client)
    incident_id = create_incident(client, headers)
    resolved = client.put(
        f"/api/v1/incidents/{incident_id}/status",
        json={"status": "resolved"},
        headers=headers,
    )
    assert resolved.status_code == 200
    later_event = root_event(
        1,
        "DescribeInstances",
        datetime(2026, 3, 2, tzinfo=UTC),
    )
    ingested = client.post("/api/v1/events/ingest", json=later_event, headers=headers)
    detail = client.get(f"/api/v1/incidents/{incident_id}", headers=headers)

    assert ingested.status_code == 200
    assert detail.json()["incident"]["status"] == "new"
    assert "reopened_by_detection" in [entry["action"] for entry in detail.json()["audit_trail"]]


def test_activity_outside_correlation_window_starts_a_new_incident(client) -> None:
    headers = bearer(client)
    incident_id = create_incident(client, headers)
    later_event = root_event(
        1,
        "DescribeInstances",
        datetime(2026, 3, 4, tzinfo=UTC),
    )

    ingested = client.post("/api/v1/events/ingest", json=later_event, headers=headers)
    incidents = client.get("/api/v1/incidents", headers=headers)
    prior = client.get(f"/api/v1/incidents/{incident_id}", headers=headers)

    assert ingested.status_code == 200
    assert incidents.json()["total"] == 2
    assert any(
        entry["action"] == "correlation_window_elapsed" for entry in prior.json()["audit_trail"]
    )
