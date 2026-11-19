from app.core.config import Settings


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
    assert names == ["list_incidents", "get_incident", "get_guardrails"]
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
