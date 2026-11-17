import re
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

import boto3
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError

from app.core.config import MonitoredAwsAccount

_AWS_CLIENT_CONFIG = Config(
    connect_timeout=3,
    read_timeout=10,
    retries={"mode": "standard", "max_attempts": 5},
    user_agent_extra="aws-cloud-security-monitor/phase5",
)


class AwsIntegrationError(RuntimeError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


SessionFactory = Callable[..., Any]


class AwsIntegrationService:
    def __init__(self, session_factory: SessionFactory | None = None) -> None:
        self._session_factory = session_factory or boto3.Session

    @staticmethod
    def _call(operation: Callable[..., Any], **kwargs: Any) -> Any:
        try:
            return operation(**kwargs)
        except ClientError as exc:
            error = exc.response.get("Error", {})
            code = error.get("Code")
            raise AwsIntegrationError(code if isinstance(code, str) else "AWSServiceError") from exc
        except BotoCoreError as exc:
            raise AwsIntegrationError("AWSClientError") from exc

    @staticmethod
    def _sts_region(account: MonitoredAwsAccount, session: Any | None = None) -> str:
        if account.role_arn is None:
            region = getattr(session, "region_name", None)
            return region if isinstance(region, str) and region else "us-east-1"
        partition = account.role_arn.split(":", 2)[1]
        return {
            "aws": "us-east-1",
            "aws-us-gov": "us-gov-west-1",
            "aws-cn": "cn-north-1",
        }.get(partition, "us-east-1")

    def _session(self, account: MonitoredAwsAccount) -> Any:
        base_session = self._session_factory()
        if account.role_arn is None:
            return base_session

        sts = base_session.client(
            "sts", region_name=self._sts_region(account, base_session), config=_AWS_CLIENT_CONFIG
        )
        assume_role: dict[str, str] = {
            "RoleArn": account.role_arn,
            "RoleSessionName": "CloudSecurityMonitorReadOnly",
        }
        if account.external_id is not None:
            assume_role["ExternalId"] = account.external_id.get_secret_value()
        credentials = self._call(sts.assume_role, **assume_role).get("Credentials")
        if not isinstance(credentials, dict):
            raise AwsIntegrationError("InvalidAssumeRoleResponse")
        required = ("AccessKeyId", "SecretAccessKey", "SessionToken")
        if any(not isinstance(credentials.get(key), str) for key in required):
            raise AwsIntegrationError("InvalidAssumeRoleResponse")
        return self._session_factory(
            aws_access_key_id=credentials["AccessKeyId"],
            aws_secret_access_key=credentials["SecretAccessKey"],
            aws_session_token=credentials["SessionToken"],
        )

    def _verify_account(self, session: Any, account: MonitoredAwsAccount) -> None:
        sts = session.client(
            "sts", region_name=self._sts_region(account, session), config=_AWS_CLIENT_CONFIG
        )
        identity = self._call(sts.get_caller_identity)
        if identity.get("Account") != account.account_id:
            raise AwsIntegrationError("AccountMismatch")

    def health(self, account: MonitoredAwsAccount) -> list[str]:
        session = self._session(account)
        self._verify_account(session, account)
        ec2 = session.client(
            "ec2", region_name=self._sts_region(account, session), config=_AWS_CLIENT_CONFIG
        )
        response = self._call(ec2.describe_regions, AllRegions=False)
        regions = response.get("Regions", [])
        if not isinstance(regions, list):
            raise AwsIntegrationError("InvalidRegionResponse")
        return sorted(
            region["RegionName"]
            for region in regions
            if isinstance(region, dict) and isinstance(region.get("RegionName"), str)
        )

    def guardduty_findings(
        self,
        account: MonitoredAwsAccount,
        region: str,
        limit: int,
    ) -> list[dict[str, Any]]:
        session = self._session(account)
        self._verify_account(session, account)
        client = session.client("guardduty", region_name=region, config=_AWS_CLIENT_CONFIG)
        detectors = self._call(client.list_detectors).get("DetectorIds", [])
        if not isinstance(detectors, list):
            raise AwsIntegrationError("InvalidDetectorResponse")

        findings: list[dict[str, Any]] = []
        for detector_id in detectors:
            if not isinstance(detector_id, str) or len(findings) >= limit:
                continue
            token: str | None = None
            while len(findings) < limit:
                params: dict[str, Any] = {
                    "DetectorId": detector_id,
                    "MaxResults": min(50, limit - len(findings)),
                }
                if token:
                    params["NextToken"] = token
                page = self._call(client.list_findings, **params)
                finding_ids = page.get("FindingIds", [])
                if not isinstance(finding_ids, list):
                    raise AwsIntegrationError("InvalidFindingResponse")
                if finding_ids:
                    detail = self._call(
                        client.get_findings,
                        DetectorId=detector_id,
                        FindingIds=finding_ids[: limit - len(findings)],
                    )
                    page_findings = detail.get("Findings", [])
                    if not isinstance(page_findings, list):
                        raise AwsIntegrationError("InvalidFindingResponse")
                    findings.extend(item for item in page_findings if isinstance(item, dict))
                token = page.get("NextToken")
                if not token:
                    break
        return findings[:limit]


def build_guardduty_envelope(
    finding: dict[str, Any],
    account: MonitoredAwsAccount,
    requested_region: str,
) -> dict[str, Any]:
    region = finding.get("Region") or requested_region
    finding_account = finding.get("AccountId") or account.account_id
    if not isinstance(region, str) or not isinstance(finding_account, str):
        raise AwsIntegrationError("InvalidFindingContext")
    if region != requested_region or finding_account != account.account_id:
        raise AwsIntegrationError("FindingAccountOrRegionMismatch")
    detail = _eventbridge_shape(finding)
    detail["id"] = finding.get("Id")
    detail["accountId"] = finding_account
    detail["region"] = region
    return {
        "version": "0",
        "id": finding.get("Id"),
        "detail-type": "GuardDuty Finding",
        "source": "aws.guardduty",
        "account": finding_account,
        "time": detail.get("updatedAt") or detail.get("createdAt"),
        "region": region,
        "detail": detail,
    }


def _eventbridge_shape(value: Any) -> Any:
    if isinstance(value, datetime):
        if value.tzinfo is None or value.utcoffset() is None:
            value = value.replace(tzinfo=UTC)
        return value.astimezone(UTC).isoformat()
    if isinstance(value, dict):
        return {_lower_camel(key): _eventbridge_shape(child) for key, child in value.items()}
    if isinstance(value, list):
        return [_eventbridge_shape(child) for child in value]
    return value


def _lower_camel(value: str) -> str:
    if value.isupper():
        return value.lower()
    acronym = re.match(r"^([A-Z]+)(?=[A-Z][a-z]|$)", value)
    if acronym:
        prefix = acronym.group(1)
        return prefix.lower() + value[len(prefix) :]
    return value[:1].lower() + value[1:]
