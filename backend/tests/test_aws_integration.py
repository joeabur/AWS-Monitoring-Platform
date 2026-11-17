from datetime import UTC, datetime
from typing import Any

from pydantic import SecretStr, ValidationError

from app.core.config import MonitoredAwsAccount, Settings
from app.ingestion.cloudtrail import normalize_cloudtrail_event
from app.integrations.aws import (
    AwsIntegrationError,
    AwsIntegrationService,
    build_guardduty_envelope,
)


class FakeClient:
    def __init__(self, **operations: Any) -> None:
        self.operations = operations

    def __getattr__(self, operation: str) -> Any:
        return self.operations[operation]


class FakeSession:
    def __init__(self, **clients: FakeClient) -> None:
        self.clients = clients

    def client(self, service: str, **_: Any) -> FakeClient:
        return self.clients[service]


def test_monitored_account_validates_iam_role_account_and_external_id() -> None:
    account = MonitoredAwsAccount(
        account_id="111122223333",
        name="production",
        role_arn="arn:aws:iam::111122223333:role/MonitoringReadOnly",
        external_id=SecretStr("external-id-secret"),
    )

    assert account.external_id is not None
    assert "external-id-secret" not in repr(account)
    try:
        MonitoredAwsAccount(
            account_id="111122223333",
            name="production",
            role_arn="arn:aws:iam::444455556666:role/MonitoringReadOnly",
        )
    except ValidationError:
        pass
    else:
        raise AssertionError("Mismatched role account must be rejected")


def test_assumed_role_health_check_discovers_enabled_regions() -> None:
    account = MonitoredAwsAccount(
        account_id="111122223333",
        name="production",
        role_arn="arn:aws:iam::111122223333:role/MonitoringReadOnly",
        external_id="expected-external-id",
    )
    base = FakeSession(
        sts=FakeClient(
            assume_role=lambda **request: {
                "Credentials": {
                    "AccessKeyId": "temporary-access",
                    "SecretAccessKey": "temporary-secret",
                    "SessionToken": "temporary-token",
                },
                "request": request,
            }
        )
    )
    assumed = FakeSession(
        sts=FakeClient(get_caller_identity=lambda: {"Account": "111122223333"}),
        ec2=FakeClient(
            describe_regions=lambda **_: {
                "Regions": [
                    {"RegionName": "us-west-2"},
                    {"RegionName": "us-east-1"},
                ]
            }
        ),
    )
    sessions = iter((base, assumed))
    service = AwsIntegrationService(session_factory=lambda **_: next(sessions))

    regions = service.health(account)

    assert regions == ["us-east-1", "us-west-2"]
    assert (
        base.clients["sts"].operations["assume_role"](
            RoleArn=account.role_arn,
            RoleSessionName="CloudSecurityMonitorReadOnly",
            ExternalId="expected-external-id",
        )["request"]["ExternalId"]
        == "expected-external-id"
    )


def test_health_check_rejects_wrong_aws_account_identity() -> None:
    account = MonitoredAwsAccount(account_id="111122223333", name="production")
    session = FakeSession(sts=FakeClient(get_caller_identity=lambda: {"Account": "444455556666"}))
    service = AwsIntegrationService(session_factory=lambda **_: session)

    try:
        service.health(account)
    except AwsIntegrationError as exc:
        assert exc.code == "AccountMismatch"
    else:
        raise AssertionError("Unexpected AWS account identity must be rejected")


def test_guardduty_findings_are_paginated_and_context_is_checked() -> None:
    account = MonitoredAwsAccount(account_id="111122223333", name="production")
    page = iter(
        (
            {"FindingIds": ["finding-1", "finding-2"], "NextToken": "next-page"},
            {"FindingIds": ["finding-3"]},
        )
    )
    guardduty = FakeClient(
        list_detectors=lambda: {"DetectorIds": ["detector-1"]},
        list_findings=lambda **_: next(page),
        get_findings=lambda FindingIds, **_: {
            "Findings": [{"Id": finding_id} for finding_id in FindingIds]
        },
    )
    session = FakeSession(
        sts=FakeClient(get_caller_identity=lambda: {"Account": account.account_id}),
        guardduty=guardduty,
    )
    service = AwsIntegrationService(session_factory=lambda **_: session)

    findings = service.guardduty_findings(account, "us-east-1", 3)
    envelope = build_guardduty_envelope(
        {
            "Id": "finding-1",
            "AccountId": account.account_id,
            "Region": "us-east-1",
            "Type": "Recon:EC2/PortProbeUnprotectedPort",
            "Severity": 7.5,
            "CreatedAt": "2026-03-01T12:00:00Z",
        },
        account,
        "us-east-1",
    )

    assert findings == [{"Id": "finding-1"}, {"Id": "finding-2"}, {"Id": "finding-3"}]
    assert envelope["detail-type"] == "GuardDuty Finding"
    assert envelope["account"] == account.account_id
    initial_update = build_guardduty_envelope(
        {
            "Id": "finding-versioned",
            "AccountId": account.account_id,
            "Region": "us-east-1",
            "CreatedAt": "2026-03-01T12:00:00Z",
            "UpdatedAt": "2026-03-01T12:00:00Z",
        },
        account,
        "us-east-1",
    )
    later_update = build_guardduty_envelope(
        {
            "Id": "finding-versioned",
            "AccountId": account.account_id,
            "Region": "us-east-1",
            "CreatedAt": "2026-03-01T12:00:00Z",
            "UpdatedAt": "2026-03-01T12:05:00Z",
        },
        account,
        "us-east-1",
    )
    assert (
        normalize_cloudtrail_event(initial_update)["event_key"]
        != normalize_cloudtrail_event(later_update)["event_key"]
    )
    datetime_envelope = build_guardduty_envelope(
        {
            "Id": "datetime-finding",
            "AccountId": account.account_id,
            "Region": "us-east-1",
            "CreatedAt": datetime(2026, 3, 1, tzinfo=UTC),
        },
        account,
        "us-east-1",
    )
    assert datetime_envelope["time"] == "2026-03-01T00:00:00+00:00"
    try:
        build_guardduty_envelope(
            {"Id": "finding-1", "AccountId": "444455556666"},
            account,
            "us-east-1",
        )
    except AwsIntegrationError as exc:
        assert exc.code == "FindingAccountOrRegionMismatch"
    else:
        raise AssertionError("Cross-account findings must be rejected")


def test_account_api_hides_role_details_and_ingests_guardduty(client, monkeypatch) -> None:
    account = MonitoredAwsAccount(
        account_id="111122223333",
        name="production",
        role_arn="arn:aws:iam::111122223333:role/MonitoringReadOnly",
        external_id="do-not-return",
    )
    finding = {
        "Id": "guardduty-finding-api",
        "AccountId": account.account_id,
        "Region": "us-east-1",
        "Type": "Recon:EC2/PortProbeUnprotectedPort",
        "Severity": 7.5,
        "CreatedAt": "2026-03-01T12:00:00Z",
    }

    class FakeIntegration:
        def health(self, _: MonitoredAwsAccount) -> list[str]:
            return ["us-east-1", "us-west-2"]

        def guardduty_findings(
            self, _: MonitoredAwsAccount, __: str, ___: int
        ) -> list[dict[str, Any]]:
            return [finding]

    monkeypatch.setattr(
        "app.api.accounts.get_settings",
        lambda: Settings(monitored_aws_accounts=[account]),
    )
    monkeypatch.setattr("app.api.accounts.AwsIntegrationService", FakeIntegration)
    headers = _bearer(client)

    accounts = client.get("/api/v1/accounts", headers=headers)
    health = client.get("/api/v1/accounts/111122223333/health", headers=headers)
    synced = client.post(
        "/api/v1/accounts/111122223333/sync/guardduty?region=us-east-1",
        headers=headers,
    )
    viewer = client.post(
        "/api/v1/accounts/111122223333/sync/guardduty?region=us-east-1",
        headers=_bearer(client, "viewer@example.com"),
    )

    assert accounts.status_code == 200
    assert accounts.json() == [
        {
            "account_id": account.account_id,
            "name": "production",
            "assume_role_enabled": True,
        }
    ]
    assert "do-not-return" not in accounts.text
    assert health.json()["regions"] == ["us-east-1", "us-west-2"]
    assert synced.status_code == 200
    assert synced.json()["fetched"] == 1
    assert synced.json()["ingested"] == 1
    assert synced.json()["alert_ids"]
    assert viewer.status_code == 403


def _bearer(client, email: str = "analyst@example.com") -> dict[str, str]:
    login = client.post(
        "/api/v1/auth/login",
        json={"email": email, "password": "correct-horse-battery"},
    )
    assert login.status_code == 200
    return {"Authorization": f"Bearer {login.json()['access_token']}"}
