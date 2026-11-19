from app.core.config import MonitoredAwsAccount, Settings
from app.response.service import ResponseActionExecutionError, disable_access_key
from app.scripts.generate_sample_events import generate_sample_event

# Construct test IDs so no credential-shaped literal is stored in the repository.
ACCESS_KEY_ID = "AKIA" + "A" * 16
UNRELATED_ACCESS_KEY_ID = "ASIA" + "A" * 16


def _bearer(client, email: str) -> dict[str, str]:
    login = client.post(
        "/api/v1/auth/login",
        json={"email": email, "password": "correct-horse-battery"},
    )
    assert login.status_code == 200
    return {"Authorization": f"Bearer {login.json()['access_token']}"}


def _create_evidenced_incident(client, headers: dict[str, str]) -> str:
    event = generate_sample_event(1)
    event["detail"]["userIdentity"] = {
        "type": "Root",
        "principalId": "111122223333",
        "arn": "arn:aws:iam::111122223333:root",
    }
    event["detail"]["requestParameters"] = {"userName": "compromised-user"}
    event["detail"]["responseElements"] = {
        "accessKey": {"accessKeyId": ACCESS_KEY_ID, "status": "Active"}
    }
    ingested = client.post("/api/v1/events/ingest", json=event, headers=headers)
    assert ingested.status_code == 200
    incidents = client.get(
        "/api/v1/incidents?account_id=111122223333",
        headers=headers,
    )
    assert incidents.status_code == 200
    return incidents.json()["items"][0]["id"]


def test_access_key_playbook_requires_independent_approval_and_defaults_to_dry_run(
    client, monkeypatch
) -> None:
    analyst_headers = _bearer(client, "analyst@example.com")
    admin_headers = _bearer(client, "admin@example.com")
    incident_id = _create_evidenced_incident(client, analyst_headers)
    monkeypatch.setattr(
        "app.api.response.get_settings",
        lambda: Settings(response_actions_enabled=False, response_dry_run=True),
    )

    playbooks = client.get("/api/v1/response/playbooks", headers=analyst_headers)
    created = client.post(
        "/api/v1/response/actions",
        headers=analyst_headers,
        json={
            "incident_id": incident_id,
            "access_key_id": ACCESS_KEY_ID,
            "reason": "Disable key observed in root activity evidence.",
        },
    )
    self_approval = client.post(
        f"/api/v1/response/actions/{created.json()['id']}/approve",
        headers=analyst_headers,
        json={"reason": "I reviewed the activity."},
    )
    approved = client.post(
        f"/api/v1/response/actions/{created.json()['id']}/approve",
        headers=admin_headers,
        json={"reason": "Independent approval after evidence review."},
    )
    executed = client.post(
        f"/api/v1/response/actions/{created.json()['id']}/execute",
        headers=admin_headers,
    )
    detail = client.get(
        f"/api/v1/response/actions/{created.json()['id']}",
        headers=analyst_headers,
    )

    assert playbooks.status_code == 200
    assert playbooks.json()[0]["live_enabled"] is False
    assert playbooks.json()[0]["approval_required"] is True
    assert created.status_code == 201
    assert created.json()["status"] == "pending_approval"
    assert created.json()["target_user_name"] == "compromised-user"
    assert created.json()["target_principal_arn"] is None
    assert self_approval.status_code == 409
    assert approved.status_code == 200
    assert approved.json()["approved_by"] != created.json()["requested_by"]
    assert executed.status_code == 200
    assert executed.json()["status"] == "dry_run"
    assert executed.json()["dry_run"] is True
    assert executed.json()["result"]["executed"] is False
    assert [entry["action"] for entry in detail.json()["audit_trail"]] == [
        "request_created",
        "approved",
        "dry_run_executed",
    ]


def test_access_key_must_be_in_incident_evidence_and_live_mode_needs_explicit_enable(
    client, monkeypatch
) -> None:
    analyst_headers = _bearer(client, "analyst@example.com")
    admin_headers = _bearer(client, "admin@example.com")
    incident_id = _create_evidenced_incident(client, analyst_headers)
    unrelated = client.post(
        "/api/v1/response/actions",
        headers=analyst_headers,
        json={
            "incident_id": incident_id,
            "access_key_id": UNRELATED_ACCESS_KEY_ID,
            "reason": "This key is not present in the incident evidence.",
        },
    )
    created = client.post(
        "/api/v1/response/actions",
        headers=analyst_headers,
        json={
            "incident_id": incident_id,
            "access_key_id": ACCESS_KEY_ID,
            "reason": "Disable the incident-evidenced key after review.",
        },
    )
    approval = client.post(
        f"/api/v1/response/actions/{created.json()['id']}/approve",
        headers=admin_headers,
        json={"reason": "Approved for controlled execution."},
    )
    monkeypatch.setattr(
        "app.api.response.get_settings",
        lambda: Settings(response_actions_enabled=False, response_dry_run=False),
    )
    blocked = client.post(
        f"/api/v1/response/actions/{created.json()['id']}/execute",
        headers=admin_headers,
    )

    assert unrelated.status_code == 422
    assert approval.status_code == 200
    assert blocked.status_code == 409
    assert blocked.json()["detail"]["code"] == "LiveResponseActionsDisabled"


def test_live_execution_requires_per_account_allowlist(client, monkeypatch) -> None:
    analyst_headers = _bearer(client, "analyst@example.com")
    admin_headers = _bearer(client, "admin@example.com")
    incident_id = _create_evidenced_incident(client, analyst_headers)
    created = client.post(
        "/api/v1/response/actions",
        headers=analyst_headers,
        json={
            "incident_id": incident_id,
            "access_key_id": ACCESS_KEY_ID,
            "reason": "Disable the incident-evidenced key after review.",
        },
    )
    action_id = created.json()["id"]
    approved = client.post(
        f"/api/v1/response/actions/{action_id}/approve",
        headers=admin_headers,
        json={"reason": "Approved for controlled execution."},
    )
    account = MonitoredAwsAccount(
        account_id="111122223333",
        name="production",
        response_role_arn="arn:aws:iam::111122223333:role/ResponseOnly",
        response_external_id="response-external-id",
    )
    monkeypatch.setattr(
        "app.api.response.get_settings",
        lambda: Settings(
            response_actions_enabled=True,
            response_dry_run=False,
            monitored_aws_accounts=[account],
        ),
    )
    not_allowlisted = client.post(
        f"/api/v1/response/actions/{action_id}/execute",
        headers=admin_headers,
    )

    calls: list[tuple[str, str, str]] = []
    account.response_allowed_iam_users = ["compromised-user"]
    monkeypatch.setattr(
        "app.response.workflow.disable_access_key",
        lambda target, user, key: calls.append((target.account_id, user, key)),
    )
    executed = client.post(
        f"/api/v1/response/actions/{action_id}/execute",
        headers=admin_headers,
    )

    assert approved.status_code == 200
    assert not_allowlisted.status_code == 409
    assert not_allowlisted.json()["detail"]["code"] == "TargetUserNotInResponseAllowlist"
    assert executed.status_code == 200
    assert executed.json()["status"] == "executed"
    assert executed.json()["dry_run"] is False
    assert calls == [("111122223333", "compromised-user", ACCESS_KEY_ID)]


def test_live_access_key_disable_assumes_separate_role_and_verifies_account() -> None:
    calls: list[tuple[str, dict[str, object]]] = []

    class BaseSts:
        def assume_role(self, **kwargs):
            calls.append(("assume_role", kwargs))
            return {
                "Credentials": {
                    "AccessKeyId": "ASIAEXAMPLE",
                    "SecretAccessKey": "temporary-secret",
                    "SessionToken": "temporary-token",
                }
            }

    class AssumedSts:
        def get_caller_identity(self):
            calls.append(("get_caller_identity", {}))
            return {"Account": "111122223333"}

    class Iam:
        def update_access_key(self, **kwargs):
            calls.append(("update_access_key", kwargs))

    class Session:
        def __init__(self, assumed: bool) -> None:
            self.assumed = assumed

        def client(self, name, **kwargs):
            if name == "sts":
                return AssumedSts() if self.assumed else BaseSts()
            if name == "iam":
                assert kwargs["config"].retries["total_max_attempts"] == 1
                return Iam()
            raise AssertionError(f"Unexpected AWS service: {name}")

    def session_factory(**credentials):
        return Session(bool(credentials))

    account = MonitoredAwsAccount(
        account_id="111122223333",
        name="production",
        role_arn="arn:aws:iam::111122223333:role/ReadOnly",
        response_role_arn="arn:aws:iam::111122223333:role/ResponseOnly",
        response_external_id="response-external-id",
    )
    disable_access_key(
        account,
        "compromised-user",
        ACCESS_KEY_ID,
        session_factory=session_factory,
    )

    assert calls[0] == (
        "assume_role",
        {
            "RoleArn": "arn:aws:iam::111122223333:role/ResponseOnly",
            "RoleSessionName": "CloudSecurityMonitorResponse",
            "ExternalId": "response-external-id",
        },
    )
    assert calls[-1] == (
        "update_access_key",
        {
            "UserName": "compromised-user",
            "AccessKeyId": ACCESS_KEY_ID,
            "Status": "Inactive",
        },
    )
    assert all(
        call[1].get("RoleArn") != "arn:aws:iam::111122223333:role/ReadOnly" for call in calls
    )


def test_live_access_key_disable_rejects_assumed_role_account_mismatch() -> None:
    class Sts:
        def assume_role(self, **_):
            return {
                "Credentials": {
                    "AccessKeyId": "ASIAEXAMPLE",
                    "SecretAccessKey": "temporary-secret",
                    "SessionToken": "temporary-token",
                }
            }

        def get_caller_identity(self):
            return {"Account": "999988887777"}

    class Session:
        def client(self, name, **_):
            if name == "sts":
                return Sts()
            raise AssertionError("IAM client must not be created for the wrong account")

    account = MonitoredAwsAccount(
        account_id="111122223333",
        name="production",
        response_role_arn="arn:aws:iam::111122223333:role/ResponseOnly",
        response_external_id="response-external-id",
    )

    try:
        disable_access_key(
            account,
            "compromised-user",
            ACCESS_KEY_ID,
            session_factory=lambda **credentials: Session(),
        )
    except ResponseActionExecutionError as exc:
        assert exc.code == "AccountMismatch"
    else:
        raise AssertionError("Expected assumed role account mismatch to fail")
