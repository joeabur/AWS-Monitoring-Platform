from datetime import UTC, datetime, timedelta

import pytest
from pydantic import SecretStr

from app.core.config import Settings, get_settings
from app.detections.engine import evaluate_event, is_rule_enabled
from app.detections.rules import RULES
from app.ingestion.cloudtrail import normalize_cloudtrail_event
from app.models import CloudTrailEvent
from app.scripts.generate_sample_events import generate_sample_event


def settings(**overrides: str) -> Settings:
    return get_settings().model_copy(
        update={
            "jwt_secret_key": SecretStr("test-secret-key-with-at-least-32-characters"),
            **overrides,
        }
    )


def event(
    event_id: str,
    event_source: str,
    event_name: str,
    *,
    time: datetime | None = None,
    request: dict[str, object] | None = None,
    response: dict[str, object] | None = None,
    identity: dict[str, object] | None = None,
    additional: dict[str, object] | None = None,
    read_only: bool | None = None,
    source_ip: str = "198.51.100.24",
) -> CloudTrailEvent:
    generated = generate_sample_event(0, now=time or datetime(2026, 1, 1, tzinfo=UTC))
    detail = generated["detail"]
    detail.update(
        {
            "eventID": event_id,
            "eventSource": event_source,
            "eventName": event_name,
            "sourceIPAddress": source_ip,
            "userIdentity": identity
            or {
                "type": "IAMUser",
                "principalId": "AIDAEXAMPLE",
                "arn": "arn:aws:iam::111122223333:user/demo",
            },
        }
    )
    if request is not None:
        detail["requestParameters"] = request
    if response is not None:
        detail["responseElements"] = response
    if additional is not None:
        detail["additionalEventData"] = additional
    if read_only is not None:
        detail["readOnly"] = read_only
    return CloudTrailEvent(**normalize_cloudtrail_event(generated))


def match_rule(rule_id: str, current: CloudTrailEvent, context=None, config=None):
    results = evaluate_event(
        current,
        context or [current],
        config or settings(),
        rule_ids={rule_id},
    )
    return results[0] if results else None


def test_detection_inventory_has_sixteen_versioned_rules() -> None:
    assert len(RULES) == 16
    assert len({rule.rule_id for rule in RULES}) == 16
    assert all(rule.version >= 1 and 0 <= rule.risk_score <= 100 for rule in RULES)


@pytest.mark.parametrize(
    ("rule_id", "candidate", "config"),
    [
        (
            "AWS-CT-001",
            lambda: event(
                "root-1",
                "ec2.amazonaws.com",
                "DescribeInstances",
                identity={"type": "Root", "principalId": "123456789012"},
            ),
            {},
        ),
        (
            "AWS-CT-003",
            lambda: event(
                "mfa-1",
                "signin.amazonaws.com",
                "ConsoleLogin",
                response={"ConsoleLogin": "Success"},
                additional={"MFAUsed": "No"},
            ),
            {},
        ),
        (
            "AWS-CT-004",
            lambda: event("iam-policy-1", "iam.amazonaws.com", "AttachUserPolicy"),
            {},
        ),
        (
            "AWS-CT-005",
            lambda: event(
                "create-user-1",
                "iam.amazonaws.com",
                "CreateUser",
                request={"userName": "contractor"},
            ),
            {"expected_iam_users": "platform-admin,breakglass"},
        ),
        (
            "AWS-CT-007",
            lambda: event("trail-1", "cloudtrail.amazonaws.com", "StopLogging"),
            {},
        ),
        (
            "AWS-CT-008",
            lambda: event(
                "bucket-1",
                "s3.amazonaws.com",
                "PutBucketPolicy",
                request={
                    "bucketPolicy": '{"Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject"}]}'
                },
            ),
            {},
        ),
        (
            "AWS-CT-009",
            lambda: event(
                "sg-1",
                "ec2.amazonaws.com",
                "AuthorizeSecurityGroupIngress",
                request={
                    "ipPermissions": [
                        {
                            "ipProtocol": "tcp",
                            "fromPort": 22,
                            "toPort": 22,
                            "ipRanges": [{"cidrIp": "0.0.0.0/0"}],
                        }
                    ]
                },
            ),
            {},
        ),
        (
            "AWS-CT-010",
            lambda: event("ip-1", "ec2.amazonaws.com", "DescribeInstances"),
            {"trusted_ip_cidrs": "203.0.113.0/24"},
        ),
        (
            "AWS-GD-011",
            lambda: event(
                "gd-1",
                "guardduty.amazonaws.com",
                "CredentialAccess:IAMUser/AnomalousBehavior",
                request={},
            ),
            {},
        ),
        (
            "AWS-CT-012",
            lambda: event(
                "role-1",
                "sts.amazonaws.com",
                "AssumeRole",
                request={"roleArn": "arn:aws:iam::111122223333:role/AdminOperator"},
            ),
            {"trusted_ip_cidrs": "203.0.113.0/24"},
        ),
        (
            "AWS-CT-013",
            lambda: event("kms-1", "kms.amazonaws.com", "PutKeyPolicy"),
            {},
        ),
        (
            "AWS-CT-014",
            lambda: event("sensitive-1", "s3.amazonaws.com", "GetObject"),
            {"sensitive_resource_arns": "arn:aws:s3:::sensitive-data"},
        ),
    ],
)
def test_single_event_rules_match_expected_scenarios(rule_id, candidate, config) -> None:
    current = candidate()
    if rule_id == "AWS-GD-011":
        current.event_details["severity"] = 8.0
    if rule_id == "AWS-CT-014":
        current.resource_arns = ["arn:aws:s3:::sensitive-data/object"]

    assert match_rule(rule_id, current, config=settings(**config)) is not None


def test_failed_console_and_denied_api_rules_require_thresholds() -> None:
    start = datetime(2026, 2, 1, tzinfo=UTC)
    failures = [
        event(
            f"failed-{index}",
            "signin.amazonaws.com",
            "ConsoleLogin",
            time=start + timedelta(minutes=index),
            response={"ConsoleLogin": "Failure"},
        )
        for index in range(5)
    ]
    assert match_rule("AWS-CT-002", failures[-1], failures) is not None
    assert match_rule("AWS-CT-002", failures[-2], failures[:-1]) is None
    successful_login = event(
        "successful-login",
        "signin.amazonaws.com",
        "ConsoleLogin",
        time=start + timedelta(minutes=5),
        response={"ConsoleLogin": "Success"},
    )
    assert match_rule("AWS-CT-002", successful_login, failures[:4] + [successful_login]) is None
    different_sources = [
        event(
            f"other-ip-{index}",
            "signin.amazonaws.com",
            "ConsoleLogin",
            time=start + timedelta(minutes=index),
            response={"ConsoleLogin": "Failure"},
            source_ip=f"198.51.100.{index + 10}",
        )
        for index in range(5)
    ]
    assert match_rule("AWS-CT-002", different_sources[-1], different_sources) is None

    denied = [
        event(
            f"denied-{index}",
            "ec2.amazonaws.com",
            "DescribeInstances",
            time=start + timedelta(minutes=index),
        )
        for index in range(5)
    ]
    for candidate in denied:
        candidate.error_code = "AccessDenied"
    assert match_rule("AWS-CT-015", denied[-1], denied) is not None
    assert match_rule("AWS-CT-015", denied[-2], denied[:-1]) is None


def test_access_key_correlation_requires_following_write_by_same_principal() -> None:
    start = datetime(2026, 2, 1, tzinfo=UTC)
    created = event(
        "key-created",
        "iam.amazonaws.com",
        "CreateAccessKey",
        time=start,
        read_only=False,
    )
    later_write = event(
        "later-write",
        "ec2.amazonaws.com",
        "RunInstances",
        time=start + timedelta(minutes=5),
        read_only=False,
    )

    assert match_rule("AWS-CT-006", later_write, [created, later_write]) is not None

    earlier_write = event(
        "earlier-write",
        "ec2.amazonaws.com",
        "RunInstances",
        time=start - timedelta(minutes=5),
        read_only=False,
    )
    assert match_rule("AWS-CT-006", created, [earlier_write, created]) is None


def test_benign_network_and_storage_events_do_not_match_exposure_rules() -> None:
    no_public_s3_policy = event(
        "bucket-private",
        "s3.amazonaws.com",
        "PutBucketPolicy",
        request={"bucketPolicy": '{"Statement":[{"Effect":"Allow","Principal":{"AWS":"1234"}}]}'},
    )
    no_public_ssh = event(
        "sg-private",
        "ec2.amazonaws.com",
        "AuthorizeSecurityGroupIngress",
        request={
            "ipPermissions": [
                {
                    "ipProtocol": "tcp",
                    "fromPort": 22,
                    "toPort": 22,
                    "ipRanges": [{"cidrIp": "10.0.0.0/8"}],
                }
            ]
        },
    )
    trusted_api = event(
        "trusted-ip",
        "ec2.amazonaws.com",
        "DescribeInstances",
        source_ip="203.0.113.42",
    )

    assert match_rule("AWS-CT-008", no_public_s3_policy) is None
    assert match_rule("AWS-CT-009", no_public_ssh) is None
    assert (
        match_rule(
            "AWS-CT-010",
            trusted_api,
            config=settings(trusted_ip_cidrs="203.0.113.0/24"),
        )
        is None
    )


def test_allowlist_rules_are_disabled_until_configuration_is_present() -> None:
    rule = next(rule for rule in RULES if rule.rule_id == "AWS-CT-010")

    assert not is_rule_enabled(rule, settings(trusted_ip_cidrs=""))
    assert is_rule_enabled(rule, settings(trusted_ip_cidrs="192.0.2.0/24"))


def test_guardduty_critical_severity_increases_alert_priority() -> None:
    finding = event(
        "gd-critical",
        "guardduty.amazonaws.com",
        "CryptoCurrency:EC2/BitcoinTool.B!DNS",
    )
    finding.event_details["severity"] = 9.5

    match = match_rule("AWS-GD-011", finding)

    assert match is not None
    assert match.severity == "critical"
    assert match.risk_score == 95


def test_invalid_trusted_network_configuration_is_rejected() -> None:
    with pytest.raises(ValueError, match="Invalid trusted IP CIDR"):
        Settings(
            jwt_secret_key=SecretStr("test-secret-key-with-at-least-32-characters"),
            trusted_ip_cidrs="not-a-network",
        )
