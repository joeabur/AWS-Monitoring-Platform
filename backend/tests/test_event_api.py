from app.scripts.generate_sample_events import generate_sample_event


def login(client, email: str) -> str:
    response = client.post(
        "/api/v1/auth/login",
        json={"email": email, "password": "correct-horse-battery"},
    )
    assert response.status_code == 200
    return response.json()["access_token"]


def test_analyst_can_ingest_and_replay_cloudtrail_event(client) -> None:
    token = login(client, "analyst@example.com")
    headers = {"Authorization": f"Bearer {token}"}
    event = generate_sample_event(0)

    first = client.post("/api/v1/events/ingest", json=event, headers=headers)
    replay = client.post("/api/v1/events/ingest", json=event, headers=headers)

    assert first.status_code == 200
    assert first.json()["duplicate"] is False
    assert replay.status_code == 200
    assert replay.json()["duplicate"] is True
    assert first.json()["event"]["id"] == replay.json()["event"]["id"]
    assert first.json()["event"]["is_synthetic"] is False


def test_viewer_can_read_events_but_cannot_ingest(client) -> None:
    admin_headers = {
        "Authorization": f"Bearer {login(client, 'admin@example.com')}",
    }
    viewer_headers = {
        "Authorization": f"Bearer {login(client, 'viewer@example.com')}",
    }
    event = generate_sample_event(1)
    client.post("/api/v1/events/ingest", json=event, headers=admin_headers)

    listed = client.get("/api/v1/events?event_name=CreateAccessKey", headers=viewer_headers)
    denied = client.post("/api/v1/events/ingest", json=event, headers=viewer_headers)

    assert listed.status_code == 200
    assert listed.json()["total"] == 1
    assert listed.json()["items"][0]["event_name"] == "CreateAccessKey"
    assert denied.status_code == 403


def test_event_list_paginates_and_filters_by_account(client) -> None:
    token = login(client, "admin@example.com")
    headers = {"Authorization": f"Bearer {token}"}
    for index in range(3):
        client.post(
            "/api/v1/events/ingest",
            json=generate_sample_event(index),
            headers=headers,
        )

    response = client.get(
        "/api/v1/events?account_id=111122223333&limit=1&offset=1",
        headers=headers,
    )

    assert response.status_code == 200
    assert response.json()["total"] == 3
    assert response.json()["limit"] == 1
    assert len(response.json()["items"]) == 1


def test_ingestion_rejects_invalid_cloudtrail_event(client) -> None:
    token = login(client, "admin@example.com")

    response = client.post(
        "/api/v1/events/ingest",
        json={"detail": {"eventName": "ConsoleLogin"}},
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 422


def test_event_detail_includes_redacted_inspection_fields(client) -> None:
    token = login(client, "analyst@example.com")
    headers = {"Authorization": f"Bearer {token}"}
    event = generate_sample_event(0)
    event["detail"]["requestParameters"] = {"secretAccessKey": "must-not-be-returned"}
    ingested = client.post("/api/v1/events/ingest", json=event, headers=headers)

    response = client.get(
        f"/api/v1/events/{ingested.json()['event']['id']}",
        headers=headers,
    )

    assert response.status_code == 200
    assert response.json()["event_details"]["requestParameters"]["secretAccessKey"] == "[REDACTED]"
