import argparse
import json
import logging
from datetime import UTC, datetime
from uuid import NAMESPACE_URL, uuid5

from app.database import get_session_factory
from app.ingestion.service import ingest_cloudtrail_event

logger = logging.getLogger(__name__)

_SCENARIOS = (
    ("ec2.amazonaws.com", "DescribeInstances", "ec2", True),
    ("iam.amazonaws.com", "CreateAccessKey", "iam", False),
    ("ec2.amazonaws.com", "AuthorizeSecurityGroupIngress", "ec2", False),
    ("signin.amazonaws.com", "ConsoleLogin", "signin", False),
)
_SYNTHETIC_ACCOUNT = "111122223333"


def generate_sample_event(index: int, *, now: datetime | None = None) -> dict[str, object]:
    if index < 0:
        raise ValueError("index must not be negative")
    event_source, event_name, service, read_only = _SCENARIOS[index % len(_SCENARIOS)]
    event_id = str(uuid5(NAMESPACE_URL, f"aws-monitoring-demo:{index}"))
    event_time = (now or datetime.now(UTC)).astimezone(UTC).isoformat()
    detail: dict[str, object] = {
        "eventVersion": "1.08",
        "userIdentity": {
            "type": "IAMUser",
            "principalId": f"AIDAEXAMPLE{index:08d}",
            "arn": f"arn:aws:iam::{_SYNTHETIC_ACCOUNT}:user/demo-analyst",
            "accountId": _SYNTHETIC_ACCOUNT,
        },
        "eventTime": event_time,
        "eventSource": event_source,
        "eventName": event_name,
        "awsRegion": "us-east-1",
        "sourceIPAddress": "198.51.100.24",
        "userAgent": "aws-monitoring-synthetic-generator/1.0",
        "requestParameters": {"demo": True},
        "responseElements": None,
        "requestID": str(uuid5(NAMESPACE_URL, f"aws-monitoring-request:{index}")),
        "eventID": event_id,
        "readOnly": read_only,
        "eventType": "AwsApiCall",
        "managementEvent": True,
        "recipientAccountId": _SYNTHETIC_ACCOUNT,
    }
    if event_name == "ConsoleLogin":
        detail["additionalEventData"] = {
            "MFAUsed": "No",
            "LoginTo": "https://console.aws.amazon.com",
        }
        detail["responseElements"] = {"ConsoleLogin": "Failure"}
        detail["errorMessage"] = "Synthetic demonstration failure"
    if event_name == "AuthorizeSecurityGroupIngress":
        detail["resources"] = [{"ARN": "arn:aws:ec2:us-east-1:111122223333:security-group/sg-demo"}]

    return {
        "version": "0",
        "id": str(uuid5(NAMESPACE_URL, f"aws-monitoring-envelope:{index}")),
        "detail-type": "AWS API Call via CloudTrail",
        "source": f"aws.{service}",
        "account": _SYNTHETIC_ACCOUNT,
        "time": event_time,
        "region": "us-east-1",
        "detail": detail,
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Persist explicitly synthetic CloudTrail demo events."
    )
    parser.add_argument("--count", type=int, default=8, choices=range(1, 1001))
    args = parser.parse_args()

    factory = get_session_factory()
    inserted = 0
    duplicates = 0
    with factory() as session:
        for index in range(args.count):
            result = ingest_cloudtrail_event(
                session,
                generate_sample_event(index),
                is_synthetic=True,
            )
            inserted += not result.duplicate
            duplicates += result.duplicate

    logger.info(
        "Synthetic event generation complete",
        extra={"inserted": inserted, "duplicates": duplicates},
    )
    print(json.dumps({"synthetic": True, "inserted": inserted, "duplicates": duplicates}))


if __name__ == "__main__":
    main()
