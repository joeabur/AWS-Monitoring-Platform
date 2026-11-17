import ipaddress
import json
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from app.core.config import Settings
from app.detections.rules import RULES, DetectionRule
from app.models import CloudTrailEvent

CORRELATION_WINDOW_MINUTES = 60


@dataclass(frozen=True)
class DetectionMatch:
    rule: DetectionRule
    title: str
    description: str
    event_ids: tuple[str, ...]
    dedup_key: str
    observed_count: int
    severity: str
    risk_score: int


def _utc(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


def _csv_values(value: str) -> set[str]:
    return {item.strip() for item in value.split(",") if item.strip()}


def is_rule_enabled(rule: DetectionRule, settings: Settings) -> bool:
    if not rule.enabled:
        return False
    if rule.requires_config == "expected_iam_users":
        return bool(_csv_values(settings.expected_iam_users))
    if rule.requires_config == "trusted_ip_cidrs":
        return bool(_csv_values(settings.trusted_ip_cidrs))
    if rule.requires_config == "sensitive_resource_arns":
        return bool(_csv_values(settings.sensitive_resource_arns))
    return True


def _detail(event: CloudTrailEvent) -> dict[str, Any]:
    return event.event_details


def _identity(event: CloudTrailEvent) -> dict[str, Any]:
    identity = _detail(event).get("userIdentity", {})
    return identity if isinstance(identity, dict) else {}


def _request(event: CloudTrailEvent) -> dict[str, Any]:
    request = _detail(event).get("requestParameters", {})
    return request if isinstance(request, dict) else {}


def _response(event: CloudTrailEvent) -> dict[str, Any]:
    response = _detail(event).get("responseElements", {})
    return response if isinstance(response, dict) else {}


def _is_failed_console(event: CloudTrailEvent) -> bool:
    response = _response(event)
    return event.event_name == "ConsoleLogin" and (
        event.error_code is not None or str(response.get("ConsoleLogin", "")).lower() == "failure"
    )


def _is_successful_console_without_mfa(event: CloudTrailEvent) -> bool:
    detail = _detail(event)
    extra = detail.get("additionalEventData", {})
    response = _response(event)
    return (
        event.event_name == "ConsoleLogin"
        and event.error_code is None
        and str(response.get("ConsoleLogin", "Success")).lower() == "success"
        and isinstance(extra, dict)
        and str(extra.get("MFAUsed", "")).lower() == "no"
    )


def _is_escalation_api(event: CloudTrailEvent) -> bool:
    return (
        event.error_code is None
        and event.event_source == "iam.amazonaws.com"
        and event.event_name
        in {
            "AddUserToGroup",
            "AttachGroupPolicy",
            "AttachRolePolicy",
            "AttachUserPolicy",
            "CreatePolicyVersion",
            "PutGroupPolicy",
            "PutRolePolicy",
            "PutUserPolicy",
            "SetDefaultPolicyVersion",
        }
    )


def _is_public_s3_change(event: CloudTrailEvent) -> bool:
    if event.event_source == "config.amazonaws.com":
        detail = _detail(event)
        compliance = detail.get("newEvaluationResult", {})
        return (
            event.event_name == "Config Rules Compliance Change"
            and isinstance(compliance, dict)
            and str(compliance.get("complianceType", "")).upper() == "NON_COMPLIANT"
            and "S3" in str(detail.get("resourceType", ""))
        )
    if event.error_code is not None:
        return False
    if event.event_source != "s3.amazonaws.com":
        return False
    request = _request(event)
    if event.event_name == "PutPublicAccessBlock":
        configuration = request.get("publicAccessBlockConfiguration", {})
        return isinstance(configuration, dict) and any(
            configuration.get(key) is False
            for key in (
                "blockPublicAcls",
                "ignorePublicAcls",
                "blockPublicPolicy",
                "restrictPublicBuckets",
            )
        )
    if event.event_name == "PutBucketPolicy":
        policy = request.get("bucketPolicy") or request.get("policy")
        if isinstance(policy, str):
            try:
                policy = json.loads(policy)
            except json.JSONDecodeError:
                return False
        if not isinstance(policy, dict):
            return False
        statements = policy.get("Statement", [])
        if isinstance(statements, dict):
            statements = [statements]
        if not isinstance(statements, list):
            return False
        for statement in statements:
            if not isinstance(statement, dict) or statement.get("Effect") != "Allow":
                continue
            principal = statement.get("Principal")
            if principal == "*":
                return True
            if isinstance(principal, dict):
                aws_principal = principal.get("AWS")
                if aws_principal == "*" or (
                    isinstance(aws_principal, list) and "*" in aws_principal
                ):
                    return True
    if event.event_name == "PutBucketAcl":
        policy = request.get("accessControlPolicy", {})
        grants = policy.get("grants", []) if isinstance(policy, dict) else []
        if isinstance(grants, list):
            for grant in grants:
                grantee = grant.get("grantee", {}) if isinstance(grant, dict) else {}
                if not isinstance(grantee, dict):
                    continue
                uri = str(grantee.get("uri", ""))
                permission = str(grant.get("permission", "")).upper()
                if "AllUsers" in uri and permission in {"READ", "WRITE", "FULL_CONTROL"}:
                    return True
    return False


def _internet_cidrs(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    try:
        network = ipaddress.ip_network(value, strict=False)
    except ValueError:
        return False
    return network.prefixlen == 0


def _exposes_admin_port(event: CloudTrailEvent) -> bool:
    request = _request(event)
    if event.event_source == "config.amazonaws.com":
        detail = _detail(event)
        compliance = detail.get("newEvaluationResult", {})
        return (
            event.event_name == "Config Rules Compliance Change"
            and isinstance(compliance, dict)
            and str(compliance.get("complianceType", "")).upper() == "NON_COMPLIANT"
            and "SECURITYGROUP" in str(detail.get("resourceType", "")).replace("_", "").upper()
        )
    if (
        event.event_source != "ec2.amazonaws.com"
        or event.event_name != "AuthorizeSecurityGroupIngress"
        or event.error_code is not None
    ):
        return False
    permissions = request.get("ipPermissions", [])
    if not isinstance(permissions, list):
        return False
    for permission in permissions:
        if not isinstance(permission, dict):
            continue
        protocol = str(permission.get("ipProtocol", ""))
        from_port = permission.get("fromPort")
        to_port = permission.get("toPort")
        if protocol not in {"tcp", "-1"}:
            continue
        try:
            start = int(from_port) if from_port is not None else 0
            end = int(to_port) if to_port is not None else 65535
        except (TypeError, ValueError):
            continue
        if not any(start <= port <= end for port in (22, 3389)):
            continue
        ranges = permission.get("ipRanges", [])
        ranges_v6 = permission.get("ipv6Ranges", [])
        if isinstance(ranges, list) and any(
            isinstance(item, dict) and _internet_cidrs(item.get("cidrIp")) for item in ranges
        ):
            return True
        if isinstance(ranges_v6, list) and any(
            isinstance(item, dict) and _internet_cidrs(item.get("cidrIpv6")) for item in ranges_v6
        ):
            return True
    return False


def _in_trusted_network(source_ip: str | None, configured: set[str]) -> bool:
    if source_ip is None:
        return True
    try:
        address = ipaddress.ip_address(source_ip)
    except ValueError:
        return True
    for value in configured:
        try:
            if address in ipaddress.ip_network(value, strict=False):
                return True
        except ValueError:
            continue
    return False


def _matches(
    rule: DetectionRule, event: CloudTrailEvent, context: list[CloudTrailEvent], settings: Settings
) -> tuple[bool, int, tuple[str, ...]]:
    detail = _detail(event)
    identity = _identity(event)
    request = _request(event)
    rule_context = [
        item
        for item in context
        if item.account_id == event.account_id
        and _utc(item.event_time) <= _utc(event.event_time)
        and _utc(item.event_time)
        >= _utc(event.event_time)
        - timedelta(
            minutes=(
                CORRELATION_WINDOW_MINUTES
                if rule.condition == "key_then_write_activity"
                else rule.window_minutes
            )
        )
    ]

    if rule.condition == "root_activity":
        return identity.get("type") == "Root", 1, (event.cloudtrail_event_id,)
    if rule.condition == "failed_console_login":
        failed = [
            item
            for item in rule_context
            if _is_failed_console(item) and item.source_ip == event.source_ip
        ]
        if _is_failed_console(event) and not any(
            item.cloudtrail_event_id == event.cloudtrail_event_id for item in failed
        ):
            failed.append(event)
        matches = len({item.cloudtrail_event_id for item in failed}) >= rule.threshold
        chosen = sorted(failed, key=lambda item: _utc(item.event_time))[-rule.threshold :]
        return matches, len(failed), tuple(item.cloudtrail_event_id for item in chosen)
    if rule.condition == "console_without_mfa":
        return _is_successful_console_without_mfa(event), 1, (event.cloudtrail_event_id,)
    if rule.condition == "iam_privilege_change":
        return _is_escalation_api(event), 1, (event.cloudtrail_event_id,)
    if rule.condition == "unexpected_iam_user":
        user_name = request.get("userName")
        expected = _csv_values(settings.expected_iam_users)
        return (
            event.event_source == "iam.amazonaws.com"
            and event.event_name == "CreateUser"
            and event.error_code is None
            and isinstance(user_name, str)
            and user_name not in expected,
            1,
            (event.cloudtrail_event_id,),
        )
    if rule.condition == "key_then_write_activity":
        principal_id = event.principal_id
        key_created = any(
            item.event_source == "iam.amazonaws.com"
            and item.event_name == "CreateAccessKey"
            and item.error_code is None
            and item.principal_id == principal_id
            for item in rule_context
        )
        candidates = [
            item
            for item in rule_context
            if item.principal_id == principal_id
            and item.event_name != "CreateAccessKey"
            and item.error_code is None
            and _detail(item).get("readOnly") is False
        ]
        candidates = [
            item
            for item in candidates
            if any(
                _utc(item.event_time) > _utc(created.event_time)
                for created in rule_context
                if created.event_source == "iam.amazonaws.com"
                and created.event_name == "CreateAccessKey"
                and created.error_code is None
                and created.principal_id == principal_id
            )
        ]
        candidates.sort(key=lambda item: _utc(item.event_time))
        matched = key_created and bool(candidates)
        evidence = tuple(
            dict.fromkeys(
                [
                    item.cloudtrail_event_id
                    for item in rule_context
                    if item.event_source == "iam.amazonaws.com"
                    and item.event_name == "CreateAccessKey"
                    and item.principal_id == principal_id
                ]
                + [item.cloudtrail_event_id for item in candidates[-1:]]
            )
        )
        return matched, len(candidates), evidence or (event.cloudtrail_event_id,)
    if rule.condition == "cloudtrail_logging_change":
        logging_disabled = (
            event.event_source == "cloudtrail.amazonaws.com"
            and event.event_name in {"StopLogging", "DeleteTrail"}
            and event.error_code is None
        )
        if (
            event.event_source == "cloudtrail.amazonaws.com"
            and event.event_name == "UpdateTrail"
            and event.error_code is None
        ):
            logging_disabled = (
                any(
                    request.get(key) is False
                    for key in ("enableLogFileValidation", "isMultiRegionTrail")
                )
                or request.get("cloudWatchLogsLogGroupArn") == ""
            )
        return logging_disabled, 1, (event.cloudtrail_event_id,)
    if rule.condition == "public_s3_change":
        return _is_public_s3_change(event), 1, (event.cloudtrail_event_id,)
    if rule.condition == "public_admin_port":
        return _exposes_admin_port(event), 1, (event.cloudtrail_event_id,)
    if rule.condition == "untrusted_source_ip":
        configured = _csv_values(settings.trusted_ip_cidrs)
        is_relevant = event.event_source.endswith(".amazonaws.com")
        return (
            is_relevant
            and event.error_code is None
            and event.source_ip is not None
            and not _in_trusted_network(event.source_ip, configured),
            1,
            (event.cloudtrail_event_id,),
        )
    if rule.condition == "guardduty_high_finding":
        severity = detail.get("severity")
        try:
            high = float(severity) >= 7.0
        except (TypeError, ValueError):
            high = False
        return (
            event.event_source == "guardduty.amazonaws.com" and high,
            1,
            (event.cloudtrail_event_id,),
        )
    if rule.condition == "suspicious_role_assumption":
        configured = _csv_values(settings.trusted_ip_cidrs)
        role_arn = request.get("roleArn")
        sensitive_role = isinstance(role_arn, str) and any(
            marker in role_arn.lower()
            for marker in (":role/admin", ":role/administrator", ":role/securityadmin")
        )
        return (
            event.event_source == "sts.amazonaws.com"
            and event.event_name == "AssumeRole"
            and event.error_code is None
            and sensitive_role
            and event.source_ip is not None
            and not _in_trusted_network(event.source_ip, configured),
            1,
            (event.cloudtrail_event_id,),
        )
    if rule.condition == "kms_policy_change":
        return (
            event.event_source == "kms.amazonaws.com"
            and event.event_name == "PutKeyPolicy"
            and event.error_code is None,
            1,
            (event.cloudtrail_event_id,),
        )
    if rule.condition == "sensitive_resource_activity":
        sensitive_arns = _csv_values(settings.sensitive_resource_arns)
        resources = set(event.resource_arns)
        matched_resources = {
            resource
            for resource in resources
            if any(
                resource == configured or resource.startswith(configured)
                for configured in sensitive_arns
            )
        }
        return (
            bool(matched_resources),
            1,
            (event.cloudtrail_event_id,),
        )
    if rule.condition == "repeated_unauthorized":
        principal = event.principal_id
        denied = [
            item
            for item in rule_context
            if item.principal_id == principal
            and item.error_code is not None
            and any(
                marker in item.error_code.lower()
                for marker in ("accessdenied", "unauthorizedoperation")
            )
        ]
        if event.error_code and any(
            marker in event.error_code.lower()
            for marker in ("accessdenied", "unauthorizedoperation")
        ):
            denied.append(event)
        deduplicated = {item.cloudtrail_event_id: item for item in denied}
        matched = len(deduplicated) >= rule.threshold
        chosen = sorted(deduplicated.values(), key=lambda item: _utc(item.event_time))[
            -rule.threshold :
        ]
        return matched, len(deduplicated), tuple(item.cloudtrail_event_id for item in chosen)
    return False, 0, ()


def evaluate_event(
    event: CloudTrailEvent,
    context: list[CloudTrailEvent],
    settings: Settings,
    *,
    rule_ids: set[str] | None = None,
) -> list[DetectionMatch]:
    matches: list[DetectionMatch] = []
    for rule in RULES:
        if rule_ids is not None and rule.rule_id not in rule_ids:
            continue
        if not is_rule_enabled(rule, settings):
            continue
        matched, observed_count, evidence = _matches(rule, event, context, settings)
        if not matched:
            continue
        resource = event.resource_arns[0] if event.resource_arns else ""
        source_ip = (
            event.source_ip
            if rule.condition
            in {
                "failed_console_login",
                "root_activity",
                "suspicious_role_assumption",
                "untrusted_source_ip",
            }
            else ""
        )
        principal_id = (
            event.principal_id
            if rule.condition != "failed_console_login" or event.principal_id
            else ""
        )
        if rule.condition in {"repeated_unauthorized", "key_then_write_activity"}:
            source_ip = ""
        if rule.condition == "repeated_unauthorized":
            resource = ""
        key = "|".join(
            (
                rule.rule_id,
                event.account_id,
                event.region,
                principal_id or "",
                resource,
                source_ip or "",
            )
        )
        severity = rule.severity
        risk_score = rule.risk_score
        if rule.condition == "guardduty_high_finding":
            try:
                if float(_detail(event).get("severity", 0)) >= 9:
                    severity = "critical"
                    risk_score = 95
            except (TypeError, ValueError):
                pass
        matches.append(
            DetectionMatch(
                rule=rule,
                title=rule.name,
                description=rule.description,
                event_ids=evidence,
                dedup_key=key,
                observed_count=observed_count,
                severity=severity,
                risk_score=risk_score,
            )
        )
    return matches


def enabled_rule_count(settings: Settings) -> int:
    return sum(is_rule_enabled(rule, settings) for rule in RULES)
