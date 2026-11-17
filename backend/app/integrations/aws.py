import hashlib
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
        if not isinstance(detectors, list) or not all(
            isinstance(detector_id, str) for detector_id in detectors
        ):
            raise AwsIntegrationError("InvalidDetectorResponse")

        findings: list[dict[str, Any]] = []
        for detector_id in detectors:
            if len(findings) >= limit:
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
                if not isinstance(finding_ids, list) or not all(
                    isinstance(finding_id, str) for finding_id in finding_ids
                ):
                    raise AwsIntegrationError("InvalidFindingResponse")
                if finding_ids:
                    detail = self._call(
                        client.get_findings,
                        DetectorId=detector_id,
                        FindingIds=finding_ids[: limit - len(findings)],
                    )
                    page_findings = detail.get("Findings", [])
                    if not isinstance(page_findings, list) or not all(
                        isinstance(item, dict) for item in page_findings
                    ):
                        raise AwsIntegrationError("InvalidFindingResponse")
                    findings.extend(page_findings)
                token = page.get("NextToken")
                if not token:
                    break
        return findings[:limit]

    def securityhub_findings(
        self,
        account: MonitoredAwsAccount,
        region: str,
        limit: int,
    ) -> list[dict[str, Any]]:
        session = self._session(account)
        self._verify_account(session, account)
        client = session.client("securityhub", region_name=region, config=_AWS_CLIENT_CONFIG)
        findings: list[dict[str, Any]] = []
        token: str | None = None
        while len(findings) < limit:
            params: dict[str, Any] = {
                "Filters": {
                    "AwsAccountId": [{"Value": account.account_id, "Comparison": "EQUALS"}]
                },
                "MaxResults": min(100, limit - len(findings)),
            }
            if token:
                params["NextToken"] = token
            page = self._call(client.get_findings, **params)
            page_findings = page.get("Findings", [])
            if not isinstance(page_findings, list) or not all(
                isinstance(item, dict) for item in page_findings
            ):
                raise AwsIntegrationError("InvalidFindingResponse")
            findings.extend(page_findings)
            token = page.get("NextToken")
            if not token:
                break
        return findings[:limit]

    def config_compliance_events(
        self,
        account: MonitoredAwsAccount,
        region: str,
        limit: int,
    ) -> list[dict[str, Any]]:
        session = self._session(account)
        self._verify_account(session, account)
        client = session.client("config", region_name=region, config=_AWS_CLIENT_CONFIG)
        rules: list[dict[str, Any]] = []
        token: str | None = None
        while True:
            params: dict[str, Any] = {}
            if token:
                params["NextToken"] = token
            page = self._call(client.describe_compliance_by_config_rule, **params)
            summaries = page.get("ComplianceByConfigRules", [])
            if not isinstance(summaries, list):
                raise AwsIntegrationError("InvalidConfigComplianceResponse")
            for item in summaries:
                if not isinstance(item, dict) or not isinstance(item.get("Compliance"), dict):
                    raise AwsIntegrationError("InvalidConfigComplianceResponse")
                if not isinstance(item.get("ConfigRuleName"), str):
                    raise AwsIntegrationError("InvalidConfigComplianceResponse")
                if item["Compliance"].get("ComplianceType") in {"NON_COMPLIANT", "COMPLIANT"}:
                    rules.append(item)
            rules.sort(key=lambda item: item["Compliance"]["ComplianceType"] != "NON_COMPLIANT")
            token = page.get("NextToken")
            if len(rules) >= 1000 and token:
                raise AwsIntegrationError("ConfigRuleLimitExceeded")
            if not token:
                break

        events: list[dict[str, Any]] = []
        for rule in rules:
            if len(events) >= limit:
                break
            rule_name = rule["ConfigRuleName"]
            evaluation_token: str | None = None
            while len(events) < limit:
                detail_params: dict[str, Any] = {
                    "ConfigRuleName": rule_name,
                    "ComplianceTypes": ["NON_COMPLIANT", "COMPLIANT"],
                    "Limit": min(100, limit - len(events)),
                }
                if evaluation_token:
                    detail_params["NextToken"] = evaluation_token
                response = self._call(client.get_compliance_details_by_config_rule, **detail_params)
                evaluations = response.get("EvaluationResults", [])
                if not isinstance(evaluations, list) or not all(
                    isinstance(item, dict) for item in evaluations
                ):
                    raise AwsIntegrationError("InvalidConfigEvaluationResponse")
                events.extend(
                    _config_event_envelope(evaluation, account, region, rule_name)
                    for evaluation in evaluations
                )
                evaluation_token = response.get("NextToken")
                if not evaluation_token:
                    break
        return events[:limit]


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
    detail["awsPartition"] = _partition(account, region)
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


def build_securityhub_envelope(
    finding: dict[str, Any],
    account: MonitoredAwsAccount,
    requested_region: str,
) -> dict[str, Any]:
    region = finding.get("Region") or requested_region
    finding_account = finding.get("AwsAccountId") or account.account_id
    finding_id = finding.get("Id")
    if not isinstance(region, str) or not isinstance(finding_account, str):
        raise AwsIntegrationError("InvalidFindingContext")
    if region != requested_region or finding_account != account.account_id:
        raise AwsIntegrationError("FindingAccountOrRegionMismatch")
    if not isinstance(finding_id, str) or not finding_id:
        raise AwsIntegrationError("InvalidFindingContext")
    detail = _eventbridge_shape(finding)
    detail["id"] = finding_id
    detail["accountId"] = finding_account
    detail["region"] = region
    return {
        "version": "0",
        "id": finding_id,
        "detail-type": "Security Hub Findings - Imported",
        "source": "aws.securityhub",
        "account": finding_account,
        "time": detail.get("updatedAt") or detail.get("createdAt"),
        "region": region,
        "detail": detail,
    }


def _config_event_envelope(
    evaluation: dict[str, Any],
    account: MonitoredAwsAccount,
    region: str,
    rule_name: str,
) -> dict[str, Any]:
    identifier = evaluation.get("EvaluationResultIdentifier", {})
    qualifier = (
        identifier.get("EvaluationResultQualifier", {}) if isinstance(identifier, dict) else {}
    )
    resource_id = qualifier.get("ResourceId")
    resource_type = qualifier.get("ResourceType")
    compliance = evaluation.get("ComplianceType")
    ordering_timestamp = (
        identifier.get("OrderingTimestamp") if isinstance(identifier, dict) else None
    )
    if (
        not isinstance(resource_id, str)
        or not isinstance(resource_type, str)
        or compliance not in {"NON_COMPLIANT", "COMPLIANT"}
        or ordering_timestamp is None
    ):
        raise AwsIntegrationError("InvalidConfigEvaluation")
    observed_at = _eventbridge_shape(ordering_timestamp)
    partition = _partition(account, region)
    stable_id = hashlib.sha256(
        f"{account.account_id}\0{region}\0{rule_name}\0{resource_id}\0{compliance}\0{observed_at}".encode()
    ).hexdigest()
    return {
        "version": "0",
        "id": stable_id,
        "detail-type": "Config Rules Compliance Change",
        "source": "aws.config",
        "account": account.account_id,
        "time": observed_at,
        "region": region,
        "detail": {
            "awsAccountId": account.account_id,
            "awsPartition": partition,
            "awsRegion": region,
            "configRuleName": rule_name,
            "messageType": "Config Rules Compliance Change",
            "notificationCreationTime": observed_at,
            "resourceId": resource_id,
            "resourceType": resource_type,
            "newEvaluationResult": {
                "complianceType": compliance,
                "configRuleName": rule_name,
                "resourceId": resource_id,
                "resourceType": resource_type,
                "orderingTimestamp": observed_at,
            },
        },
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


def _partition(account: MonitoredAwsAccount, region: str) -> str:
    if account.role_arn is not None:
        return account.role_arn.split(":", 2)[1]
    if region.startswith("us-gov-"):
        return "aws-us-gov"
    if region.startswith("cn-"):
        return "aws-cn"
    return "aws"


def _lower_camel(value: str) -> str:
    if value.isupper():
        return value.lower()
    acronym = re.match(r"^([A-Z]+)(?=[A-Z][a-z]|$)", value)
    if acronym:
        prefix = acronym.group(1)
        return prefix.lower() + value[len(prefix) :]
    return value[:1].lower() + value[1:]
