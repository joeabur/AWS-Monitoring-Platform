import json
from datetime import UTC, datetime

from app.core.config import Settings
from app.models import CloudTrailEvent, DetectionAlert


def _bearer(client, email: str) -> dict[str, str]:
    login = client.post(
        "/api/v1/auth/login",
        json={"email": email, "password": "correct-horse-battery"},
    )
    assert login.status_code == 200
    return {"Authorization": f"Bearer {login.json()['access_token']}"}


def test_mcp_is_disabled_by_default(client) -> None:
    headers = _bearer(client, "analyst@example.com")

    response = client.get("/api/v1/mcp/capabilities", headers=headers)

    assert response.status_code == 404
    assert response.json()["detail"]["code"] == "McpDisabled"


def test_mcp_requires_authentication_when_enabled(client, monkeypatch) -> None:
    monkeypatch.setattr(
        "app.api.mcp.get_settings",
        lambda: Settings(mcp_enabled=True),
    )

    anonymous = client.post(
        "/api/v1/mcp",
        json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
    )
    headers = _bearer(client, "analyst@example.com")
    authenticated = client.post(
        "/api/v1/mcp",
        headers=headers,
        json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
    )

    assert anonymous.status_code == 401
    assert authenticated.status_code == 200
    names = [tool["name"] for tool in authenticated.json()["result"]["tools"]]
    assert names == [
        "list_incidents",
        "get_incident",
        "search_alerts",
        "get_alert_evidence",
        "get_guardrails",
    ]
    assert "execute" not in " ".join(names)


def test_mcp_tools_report_guardrails(client, monkeypatch) -> None:
    monkeypatch.setattr(
        "app.api.mcp.get_settings",
        lambda: Settings(mcp_enabled=True),
    )
    headers = _bearer(client, "viewer@example.com")

    guardrails = client.post(
        "/api/v1/mcp",
        headers=headers,
        json={
            "jsonrpc": "2.0",
            "id": "guardrails",
            "method": "tools/call",
            "params": {"name": "get_guardrails", "arguments": {}},
        },
    )
    listed = client.post(
        "/api/v1/mcp",
        headers=headers,
        json={
            "jsonrpc": "2.0",
            "id": "incidents",
            "method": "tools/call",
            "params": {"name": "list_incidents", "arguments": {"limit": 25}},
        },
    )

    assert guardrails.status_code == 200
    assert "MCP is read-only" in guardrails.json()["result"]["content"][0]["text"]
    assert listed.status_code == 200
    assert '"items": []' in listed.json()["result"]["content"][0]["text"]


def test_mcp_searches_alerts_and_returns_curated_evidence(client, db_session, monkeypatch) -> None:
    monkeypatch.setattr(
        "app.api.mcp.get_settings",
        lambda: Settings(mcp_enabled=True),
    )
    observed_at = datetime(2026, 11, 19, 12, 0, tzinfo=UTC)
    evidence = CloudTrailEvent(
        event_key="a" * 64,
        cloudtrail_event_id="cloudtrail-event-1",
        account_id="111122223333",
        region="us-east-1",
        event_source="iam.amazonaws.com",
        event_name="DeactivateMFADevice",
        event_time=observed_at,
        source_ip="203.0.113.12",
        principal_id="AIDAEXAMPLE",
        resource_arns=[],
        event_details={"sensitivePayload": "never return raw event details"},
    )
    db_session.add(evidence)
    db_session.flush()
    alert = DetectionAlert(
        dedup_key="b" * 64,
        rule_id="AWS-CT-018",
        rule_version=1,
        title="IAM MFA device removed",
        description="A virtual MFA device was removed.",
        severity="high",
        risk_score=85,
        score_basis="Rule-defined relative prioritization.",
        account_id="111122223333",
        region="us-east-1",
        principal_id="AIDAEXAMPLE",
        resource_arns=[],
        event_refs=[str(evidence.id)],
        observed_count=1,
        investigation_steps=["Review the change."],
        response_recommendations=["Restore MFA through the approved process."],
        first_observed_at=observed_at,
        last_observed_at=observed_at,
    )
    db_session.add(alert)
    db_session.commit()
    headers = _bearer(client, "viewer@example.com")

    searched = client.post(
        "/api/v1/mcp",
        headers=headers,
        json={
            "jsonrpc": "2.0",
            "id": "search",
            "method": "tools/call",
            "params": {
                "name": "search_alerts",
                "arguments": {"severity": "high", "account_id": "111122223333"},
            },
        },
    )
    detail = client.post(
        "/api/v1/mcp",
        headers=headers,
        json={
            "jsonrpc": "2.0",
            "id": "evidence",
            "method": "tools/call",
            "params": {
                "name": "get_alert_evidence",
                "arguments": {"alert_id": str(alert.id)},
            },
        },
    )
    invalid_filter = client.post(
        "/api/v1/mcp",
        headers=headers,
        json={
            "jsonrpc": "2.0",
            "id": "invalid",
            "method": "tools/call",
            "params": {
                "name": "search_alerts",
                "arguments": {"account_id": "not-an-account"},
            },
        },
    )

    assert searched.status_code == 200
    search_result = json.loads(searched.json()["result"]["content"][0]["text"])
    assert search_result["total"] == 1
    assert search_result["items"][0]["id"] == str(alert.id)
    assert detail.status_code == 200
    evidence_result = json.loads(detail.json()["result"]["content"][0]["text"])
    assert evidence_result["evidence"][0]["cloudtrail_event_id"] == "cloudtrail-event-1"
    assert "sensitivePayload" not in detail.text
    assert invalid_filter.json()["error"]["code"] == -32602
