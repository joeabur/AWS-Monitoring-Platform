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
    "managementEvent",
    "readOnly",
    "requestParameters",
    "responseElements",
    "resources",
    "serviceEventDetails",
    "tlsDetails",
    "userIdentity",
    "vpcEndpointId",
)
_SENSITIVE_KEY_PARTS = ("authorization", "credential", "password", "secret", "token")


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
    if not isinstance(resources, list):
        raise EventNormalizationError("CloudTrail event field resources must be a list")
    arns: list[str] = []
    for resource in resources:
        if not isinstance(resource, Mapping):
            continue
        arn = resource.get("ARN") or resource.get("arn")
        if isinstance(arn, str) and arn:
            arns.append(arn[:2048])
    return list(dict.fromkeys(arns))


def normalize_cloudtrail_event(
    event: Mapping[str, Any], *, is_synthetic: bool = False
) -> dict[str, Any]:
    """Normalize a CloudTrail record or EventBridge CloudTrail envelope."""
    if not isinstance(event, Mapping):
        raise EventNormalizationError("CloudTrail event must be a JSON object")

    envelope = event
    detail = envelope.get("detail", envelope)
    if not isinstance(detail, Mapping):
        raise EventNormalizationError("EventBridge detail must be a JSON object")

    account_id = (
        detail.get("recipientAccountId") or detail.get("accountId") or envelope.get("account")
    )
    if not isinstance(account_id, str) or not _ACCOUNT_ID.fullmatch(account_id):
        raise EventNormalizationError("CloudTrail event must identify a 12-digit AWS account")

    region = detail.get("awsRegion") or envelope.get("region")
    if not isinstance(region, str) or not region.strip():
        raise EventNormalizationError("CloudTrail event is missing required field: awsRegion")
    region = region.strip().lower()

    event_id = detail.get("eventID") or detail.get("eventId")
    if not isinstance(event_id, str) or not event_id.strip():
        raise EventNormalizationError("CloudTrail event is missing required field: eventID")
    event_id = event_id.strip()

    event_source = _required_string(detail, "eventSource").lower()
    event_name = _required_string(detail, "eventName")
    identity = _identity(detail)

    source_ip = _optional_string(detail, "sourceIPAddress", 128)
    if source_ip is not None:
        try:
            ipaddress.ip_address(source_ip)
        except ValueError:
            source_ip = None

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
        "event_time": _event_time(detail.get("eventTime")),
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
