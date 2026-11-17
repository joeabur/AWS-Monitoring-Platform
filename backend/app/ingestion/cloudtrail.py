import hashlib
import ipaddress
import re
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any


class EventNormalizationError(ValueError):
    """Raised when an input does not match the supported CloudTrail event shape."""


_ACCOUNT_ID = re.compile(r"^\d{12}$")
_RETAINED_DETAIL_FIELDS = (
    "additionalEventData",
    "eventCategory",
    "eventType",
    "eventVersion",
    "finding",
    "findingArn",
    "id",
    "managementEvent",
    "readOnly",
    "requestParameters",
    "resource",
    "responseElements",
    "resources",
    "severity",
    "serviceEventDetails",
    "tlsDetails",
    "title",
    "type",
    "userIdentity",
    "vpcEndpointId",
)
_SENSITIVE_KEY_PARTS = ("authorization", "credential", "password", "secret", "token")
_CONFIG_DETAIL_FIELDS = (
    "configRuleName",
    "messageType",
    "newEvaluationResult",
    "resourceId",
    "resourceType",
)


def _redact(value: Any) -> Any:
    if isinstance(value, Mapping):
        redacted: dict[str, Any] = {}
        for key, child in value.items():
            normalized_key = str(key).replace("_", "").lower()
            if any(part in normalized_key for part in _SENSITIVE_KEY_PARTS):
                redacted[str(key)] = "[REDACTED]"
            else:
                redacted[str(key)] = _redact(child)
        return redacted
    if isinstance(value, list):
        return [_redact(item) for item in value]
    return value


def _required_string(data: Mapping[str, Any], key: str) -> str:
    value = data.get(key)
    if not isinstance(value, str) or not value.strip():
        raise EventNormalizationError(f"CloudTrail event is missing required field: {key}")
    return value.strip()


def _optional_string(data: Mapping[str, Any], key: str, max_length: int) -> str | None:
    value = data.get(key)
    if value is None:
        return None
    if not isinstance(value, str):
        raise EventNormalizationError(f"CloudTrail event field {key} must be a string")
    value = value.strip()
    if not value:
        return None
    return value[:max_length]


def _event_time(value: Any) -> datetime:
    if not isinstance(value, str):
        raise EventNormalizationError("CloudTrail event is missing required field: eventTime")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise EventNormalizationError("CloudTrail event field eventTime is invalid") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise EventNormalizationError("CloudTrail event field eventTime must include a timezone")
    return parsed.astimezone(UTC)


def _identity(data: Mapping[str, Any]) -> Mapping[str, Any]:
    identity = data.get("userIdentity", {})
    if not isinstance(identity, Mapping):
        raise EventNormalizationError("CloudTrail event field userIdentity must be an object")
    return identity


def _resources(data: Mapping[str, Any]) -> list[str]:
    resources = data.get("resources", [])
    if resources is None:
        resources = []
    if not isinstance(resources, list):
        raise EventNormalizationError("CloudTrail event field resources must be a list")
    arns: list[str] = []
    for resource in resources:
        if not isinstance(resource, Mapping):
            continue
        arn = resource.get("ARN") or resource.get("arn")
        if isinstance(arn, str) and arn:
            arns.append(arn[:2048])
    finding_resource = data.get("resource")
    if isinstance(finding_resource, Mapping):
        for key in ("resourceArn", "arn"):
            arn = finding_resource.get(key)
            if isinstance(arn, str) and arn:
                arns.append(arn[:2048])
        instance_details = finding_resource.get("instanceDetails", {})
        instance_id = (
            instance_details.get("instanceId") if isinstance(instance_details, Mapping) else None
        )
        if (
            isinstance(instance_id, str)
            and isinstance(data.get("region"), str)
            and isinstance(data.get("accountId"), str)
        ):
            arns.append(
                f"arn:aws:ec2:{data['region']}:{data['accountId']}:instance/{instance_id}"[:2048]
            )
    return list(dict.fromkeys(arns))


def normalize_cloudtrail_event(
    event: Mapping[str, Any], *, is_synthetic: bool = False
) -> dict[str, Any]:
    """Normalize CloudTrail records and supported EventBridge threat envelopes."""
    if not isinstance(event, Mapping):
        raise EventNormalizationError("CloudTrail event must be a JSON object")

    envelope = event
    detail = envelope.get("detail", envelope)
    if not isinstance(detail, Mapping):
        raise EventNormalizationError("EventBridge detail must be a JSON object")

    guardduty_envelope = (
        envelope.get("source") == "aws.guardduty"
        and envelope.get("detail-type") == "GuardDuty Finding"
    )
    config_envelope = (
        envelope.get("source") == "aws.config"
        and envelope.get("detail-type") == "Config Rules Compliance Change"
    )
    account_id = (
        detail.get("recipientAccountId")
        or detail.get("accountId")
        or detail.get("awsAccountId")
        or envelope.get("account")
    )
    if not isinstance(account_id, str) or not _ACCOUNT_ID.fullmatch(account_id):
        raise EventNormalizationError("CloudTrail event must identify a 12-digit AWS account")

    region = detail.get("awsRegion") or detail.get("region") or envelope.get("region")
    if not isinstance(region, str) or not region.strip():
        raise EventNormalizationError("CloudTrail event is missing required field: awsRegion")
    region = region.strip().lower()

    if guardduty_envelope:
        finding_id = detail.get("id") or detail.get("findingArn")
        updated_at = detail.get("updatedAt")
        event_id = (
            f"{finding_id}:{updated_at}"
            if isinstance(finding_id, str) and isinstance(updated_at, str)
            else finding_id
        )
    elif config_envelope:
        event_id = envelope.get("id") or detail.get("eventId")
    else:
        event_id = detail.get("eventID") or detail.get("eventId")
    if not isinstance(event_id, str) or not event_id.strip():
        field_name = "id" if guardduty_envelope else "envelope id" if config_envelope else "eventID"
        raise EventNormalizationError(f"CloudTrail event is missing required field: {field_name}")
    event_id = event_id.strip()

    if guardduty_envelope:
        event_source = "guardduty.amazonaws.com"
        event_name = _optional_string(detail, "type", 255) or "Finding"
        event_time_value = (
            detail.get("updatedAt") or detail.get("createdAt") or envelope.get("time")
        )
        identity = detail.get("userIdentity", {})
        if not isinstance(identity, Mapping):
            identity = {}
    elif config_envelope:
        event_source = "config.amazonaws.com"
        event_name = (
            _optional_string(detail, "messageType", 255) or "Config Rules Compliance Change"
        )
        event_time_value = detail.get("notificationCreationTime") or envelope.get("time")
        identity = {}
    else:
        event_source = _required_string(detail, "eventSource").lower()
        event_name = _required_string(detail, "eventName")
        event_time_value = detail.get("eventTime")
        identity = _identity(detail)

    source_ip = _optional_string(detail, "sourceIPAddress", 128)
    if guardduty_envelope and source_ip is None:
        finding_service = detail.get("service", {})
        action = finding_service.get("action", {}) if isinstance(finding_service, Mapping) else {}
        network_action = (
            action.get("networkConnectionAction", {}) if isinstance(action, Mapping) else {}
        )
        remote_ip = (
            network_action.get("remoteIpDetails", {}) if isinstance(network_action, Mapping) else {}
        )
        if isinstance(remote_ip, Mapping):
            source_ip = _optional_string(remote_ip, "ipAddressV4", 128)
    if source_ip is not None:
        try:
            ipaddress.ip_address(source_ip)
        except ValueError:
            source_ip = None

    if guardduty_envelope:
        retained_details = {
            "finding": _redact(dict(detail)),
            "severity": detail.get("severity"),
            "type": event_name,
            "title": detail.get("title"),
            "id": event_id,
            "findingArn": detail.get("findingArn"),
        }
    elif config_envelope:
        retained_details = {
            key: _redact(detail[key]) for key in _CONFIG_DETAIL_FIELDS if key in detail
        }
    else:
        retained_details = {
            key: _redact(detail[key]) for key in _RETAINED_DETAIL_FIELDS if key in detail
        }

    event_key = hashlib.sha256(f"{account_id}:{region}:{event_id}".encode()).hexdigest()

    return {
        "event_key": event_key,
        "cloudtrail_event_id": event_id[:256],
        "account_id": account_id,
        "region": region[:64],
        "event_source": event_source[:255],
        "event_name": event_name[:255],
        "event_time": _event_time(event_time_value),
        "source_ip": source_ip,
        "principal_type": _optional_string(identity, "type", 64),
        "principal_id": _optional_string(identity, "principalId", 2048),
        "principal_arn": _optional_string(identity, "arn", 2048),
        "user_agent": _optional_string(detail, "userAgent", 1024),
        "error_code": _optional_string(detail, "errorCode", 256),
        "resource_arns": _resources(detail),
        "event_details": retained_details,
        "is_synthetic": is_synthetic,
    }
