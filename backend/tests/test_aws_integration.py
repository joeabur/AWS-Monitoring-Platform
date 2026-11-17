from datetime import UTC, datetime
from typing import Any

from pydantic import SecretStr, ValidationError

from app.core.config import MonitoredAwsAccount, Settings
from app.ingestion.cloudtrail import normalize_cloudtrail_event
from app.integrations.aws import (
    AwsIntegrationError,
    AwsIntegrationService,
    build_guardduty_envelope,
    build_securityhub_envelope,
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


def test_securityhub_finding_pages_and_normalizes_severity_and_resource() -> None:
    account = MonitoredAwsAccount(account_id="111122223333", name="production")
    securityhub_pages = iter(
        (
            {
                "Findings": [
                    {
                        "Id": "finding-1",
                        "AwsAccountId": account.account_id,
                        "Region": "us-east-1",
                        "Title": "Public bucket exposure",
                        "CreatedAt": "2026-03-01T12:00:00Z",
                        "UpdatedAt": "2026-03-01T12:05:00Z",
                        "Severity": {"Label": "CRITICAL", "Normalized": 95},
                        "Resources": [{"Id": "arn:aws:s3:::example", "Type": "AwsS3Bucket"}],
                    }
                ],
                "NextToken": "next-page",
            },
            {"Findings": [{"Id": "finding-2", "AwsAccountId": account.account_id}]},
        )
    )
    session = FakeSession(
        sts=FakeClient(get_caller_identity=lambda: {"Account": account.account_id}),
        securityhub=FakeClient(get_findings=lambda **_: next(securityhub_pages)),
    )
    service = AwsIntegrationService(session_factory=lambda **_: session)

    findings = service.securityhub_findings(account, "us-east-1", 2)
    envelope = build_securityhub_envelope(findings[0], account, "us-east-1")
    normalized = normalize_cloudtrail_event(envelope)

    assert len(findings) == 2
    assert normalized["event_source"] == "securityhub.amazonaws.com"
    assert normalized["event_time"].isoformat() == "2026-03-01T12:05:00+00:00"
    assert normalized["resource_arns"] == ["arn:aws:s3:::example"]
    assert normalized["event_details"]["finding"]["severity"]["label"] == "CRITICAL"


def test_config_collector_maps_noncompliant_resource_to_event() -> None:
    account = MonitoredAwsAccount(account_id="111122223333", name="production")
    config = FakeClient(
        describe_compliance_by_config_rule=lambda **_: {
            "ComplianceByConfigRules": [
                {
                    "ConfigRuleName": "restricted-ssh",
                    "Compliance": {"ComplianceType": "NON_COMPLIANT"},
                },
                {
                    "ConfigRuleName": "encrypted-volumes",
                    "Compliance": {"ComplianceType": "COMPLIANT"},
                },
            ]
        },
        get_compliance_details_by_config_rule=lambda ConfigRuleName, **_: {
            "EvaluationResults": [
                {
                    "EvaluationResultIdentifier": {
                        "EvaluationResultQualifier": {
                            "ConfigRuleName": ConfigRuleName,
                            "ResourceType": "AWS::EC2::SecurityGroup",
                            "ResourceId": "sg-1234",
                        },
                        "OrderingTimestamp": datetime(2026, 3, 1, tzinfo=UTC),
                    },
                    "ComplianceType": (
                        "NON_COMPLIANT" if ConfigRuleName == "restricted-ssh" else "COMPLIANT"
                    ),
                }
            ]
        },
    )
    session = FakeSession(
        sts=FakeClient(get_caller_identity=lambda: {"Account": account.account_id}),
        config=config,
    )
    service = AwsIntegrationService(session_factory=lambda **_: session)

    envelopes = service.config_compliance_events(account, "us-east-1", 5)
    normalized = [normalize_cloudtrail_event(envelope) for envelope in envelopes]

    assert len(envelopes) == 2
    assert normalized[0]["event_source"] == "config.amazonaws.com"
    assert normalized[0]["event_name"] == "Config Rules Compliance Change"
    assert (
        normalized[0]["event_details"]["newEvaluationResult"]["complianceType"] == "NON_COMPLIANT"
    )
    assert normalized[1]["event_details"]["newEvaluationResult"]["complianceType"] == "COMPLIANT"
    assert normalized[0]["resource_arns"] == [
        "arn:aws:ec2:us-east-1:111122223333:security-group/sg-1234"
    ]


def test_account_api_hides_role_details_and_ingests_guardduty(client, monkeypatch) -> None:
    account = MonitoredAwsAccount(
        account_id="111122223333",
        name="production",
        role_arn="arn:aws:iam::111122223333:role/MonitoringReadOnly",
        external_id="do-not-return",
        response_role_arn="arn:aws:iam::111122223333:role/MonitoringResponse",
        response_external_id="response-do-not-return",
        response_allowed_iam_users=["compromised-user"],
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

        def securityhub_findings(
            self, _: MonitoredAwsAccount, __: str, ___: int
        ) -> list[dict[str, Any]]:
            return [
                {
                    "Id": "securityhub-finding-api",
                    "AwsAccountId": account.account_id,
                    "Region": "us-east-1",
                    "Title": "Sensitive resource finding",
                    "CreatedAt": "2026-03-01T12:00:00Z",
                    "UpdatedAt": "2026-03-01T12:05:00Z",
                    "Severity": {"Label": "HIGH", "Normalized": 75},
                    "Resources": [{"Id": "arn:aws:s3:::sensitive-demo"}],
                }
            ]

        def config_compliance_events(
            self, _: MonitoredAwsAccount, __: str, ___: int
        ) -> list[dict[str, Any]]:
            return [
                {
                    "version": "0",
                    "id": "config-finding-api",
                    "detail-type": "Config Rules Compliance Change",
                    "source": "aws.config",
                    "account": account.account_id,
                    "time": "2026-03-01T12:00:00Z",
                    "region": "us-east-1",
                    "detail": {
                        "awsAccountId": account.account_id,
                        "awsPartition": "aws",
                        "awsRegion": "us-east-1",
                        "configRuleName": "restricted-ssh",
                        "messageType": "Config Rules Compliance Change",
                        "notificationCreationTime": "2026-03-01T12:00:00Z",
                        "resourceId": "sg-api",
                        "resourceType": "AWS::EC2::SecurityGroup",
                        "newEvaluationResult": {"complianceType": "NON_COMPLIANT"},
                    },
                }
            ]

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
    securityhub = client.post(
        "/api/v1/accounts/111122223333/sync/security-hub?region=us-east-1",
        headers=headers,
    )
    config = client.post(
        "/api/v1/accounts/111122223333/sync/config?region=us-east-1",
        headers=headers,
    )
    health_after_sync = client.get("/api/v1/accounts/111122223333/health", headers=headers)
    findings = client.get("/api/v1/findings?limit=20", headers=headers)
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
    assert "MonitoringResponse" not in accounts.text
    assert health.json()["regions"] == ["us-east-1", "us-west-2"]
    assert synced.status_code == 200
    assert synced.json()["fetched"] == 1
    assert synced.json()["ingested"] == 1
    assert synced.json()["alert_ids"]
    assert securityhub.status_code == config.status_code == 200
    assert securityhub.json()["alert_ids"]
    assert config.json()["alert_ids"]
    assert findings.status_code == 200
    finding_items = findings.json()["items"]
    assert {item["provider"] for item in finding_items} == {
        "guardduty",
        "securityhub",
        "config",
    }
    assert health_after_sync.status_code == 200
    assert {item["integration"] for item in health_after_sync.json()["integrations"]} == {
        "sts",
        "guardduty",
        "securityhub",
        "config",
    }
    assert viewer.status_code == 403


def test_finding_updates_ignore_out_of_order_status_changes(client) -> None:
    headers = _bearer(client)
    findings = [
        {
            "Id": "securityhub-versioned-finding",
            "AwsAccountId": "111122223333",
            "Region": "us-east-1",
            "Title": "Sensitive resource finding",
            "CreatedAt": "2026-03-01T12:00:00Z",
            "UpdatedAt": "2026-03-01T12:10:00Z",
            "Workflow": {"Status": "RESOLVED"},
            "Severity": {"Label": "HIGH", "Normalized": 75},
        },
        {
            "Id": "securityhub-versioned-finding",
            "AwsAccountId": "111122223333",
            "Region": "us-east-1",
            "Title": "Sensitive resource finding",
            "CreatedAt": "2026-03-01T12:00:00Z",
            "UpdatedAt": "2026-03-01T12:08:00Z",
            "Workflow": {"Status": "NEW"},
            "Severity": {"Label": "HIGH", "Normalized": 75},
        },
    ]
    for finding in findings:
        envelope = build_securityhub_envelope(
            finding,
            MonitoredAwsAccount(account_id="111122223333", name="production"),
            "us-east-1",
        )
        response = client.post("/api/v1/events/ingest", json=envelope, headers=headers)
        assert response.status_code == 200

    response = client.get(
        "/api/v1/findings?provider=securityhub&status=resolved",
        headers=headers,
    )

    assert response.status_code == 200
    assert response.json()["total"] == 1
    finding = response.json()["items"][0]
    assert finding["status"] == "resolved"
    assert finding["last_updated_at"] == "2026-03-01T12:10:00"


def _bearer(client, email: str = "analyst@example.com") -> dict[str, str]:
    login = client.post(
        "/api/v1/auth/login",
        json={"email": email, "password": "correct-horse-battery"},
    )
    assert login.status_code == 200
    return {"Authorization": f"Bearer {login.json()['access_token']}"}
