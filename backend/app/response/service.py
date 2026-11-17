from collections.abc import Callable
from typing import Any

import boto3
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError

from app.core.config import MonitoredAwsAccount

_CLIENT_CONFIG = Config(
    connect_timeout=3,
    read_timeout=10,
    retries={"mode": "standard", "max_attempts": 3},
    user_agent_extra="aws-cloud-security-monitor/phase8-response",
)
_WRITE_CLIENT_CONFIG = Config(
    connect_timeout=3,
    read_timeout=10,
    retries={"mode": "standard", "total_max_attempts": 1},
    user_agent_extra="aws-cloud-security-monitor/phase8-response",
)

SessionFactory = Callable[..., Any]


class ResponseActionExecutionError(RuntimeError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def _call(operation: Callable[..., Any], **kwargs: Any) -> Any:
    try:
        return operation(**kwargs)
    except ClientError as exc:
        error = exc.response.get("Error", {})
        code = error.get("Code")
        raise ResponseActionExecutionError(
            code if isinstance(code, str) else "AWSServiceError"
        ) from exc
    except BotoCoreError as exc:
        raise ResponseActionExecutionError("AWSClientError") from exc


def _sts_region(role_arn: str) -> str:
    partition = role_arn.split(":", 2)[1]
    return {
        "aws": "us-east-1",
        "aws-us-gov": "us-gov-west-1",
        "aws-cn": "cn-north-1",
    }.get(partition, "us-east-1")


def disable_access_key(
    account: MonitoredAwsAccount,
    user_name: str,
    access_key_id: str,
    *,
    session_factory: SessionFactory | None = None,
) -> None:
    if account.response_role_arn is None:
        raise ResponseActionExecutionError("ResponseRoleNotConfigured")

    create_session = session_factory or boto3.Session
    base_session = create_session()
    region = _sts_region(account.response_role_arn)
    base_sts = base_session.client("sts", region_name=region, config=_CLIENT_CONFIG)
    assume_role: dict[str, str] = {
        "RoleArn": account.response_role_arn,
        "RoleSessionName": "CloudSecurityMonitorResponse",
    }
    if account.response_external_id is not None:
        assume_role["ExternalId"] = account.response_external_id.get_secret_value()
    credentials = _call(base_sts.assume_role, **assume_role).get("Credentials")
    if not isinstance(credentials, dict):
        raise ResponseActionExecutionError("InvalidAssumeRoleResponse")
    required = ("AccessKeyId", "SecretAccessKey", "SessionToken")
    if any(not isinstance(credentials.get(key), str) for key in required):
        raise ResponseActionExecutionError("InvalidAssumeRoleResponse")

    assumed_session = create_session(
        aws_access_key_id=credentials["AccessKeyId"],
        aws_secret_access_key=credentials["SecretAccessKey"],
        aws_session_token=credentials["SessionToken"],
    )
    assumed_sts = assumed_session.client("sts", region_name=region, config=_CLIENT_CONFIG)
    identity = _call(assumed_sts.get_caller_identity)
    if identity.get("Account") != account.account_id:
        raise ResponseActionExecutionError("AccountMismatch")

    iam = assumed_session.client("iam", region_name=region, config=_WRITE_CLIENT_CONFIG)
    _call(
        iam.update_access_key,
        UserName=user_name,
        AccessKeyId=access_key_id,
        Status="Inactive",
    )
