from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import ValidationError

from app.api.dependencies import CurrentUser, Database, require_roles
from app.core.config import MonitoredAwsAccount, get_settings
from app.ingestion.cloudtrail import EventNormalizationError
from app.ingestion.service import ingest_cloudtrail_event
from app.integrations.aws import (
    AwsIntegrationError,
    AwsIntegrationService,
    build_guardduty_envelope,
)
from app.models import User
from app.schemas.accounts import AwsAccountHealthRead, AwsAccountRead, GuardDutySyncRead
from app.schemas.auth import UserRole

router = APIRouter(prefix="/api/v1/accounts", tags=["accounts"])


def _account_config(account_id: str) -> MonitoredAwsAccount:
    for account in get_settings().monitored_aws_accounts:
        if account.account_id == account_id:
            return account
    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="AWS account not found")


def _aws_unavailable(exc: AwsIntegrationError) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        detail={"code": exc.code, "message": "AWS integration request failed"},
    )


@router.get("", response_model=list[AwsAccountRead])
def list_accounts(_: CurrentUser) -> list[AwsAccountRead]:
    try:
        accounts = get_settings().monitored_aws_accounts
    except ValidationError as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="MONITORED_AWS_ACCOUNTS configuration is invalid",
        ) from exc
    return [
        AwsAccountRead(
            account_id=account.account_id,
            name=account.name,
            assume_role_enabled=account.role_arn is not None,
        )
        for account in accounts
    ]


@router.get("/{account_id}/health", response_model=AwsAccountHealthRead)
def account_health(
    account_id: str,
    _: CurrentUser,
) -> AwsAccountHealthRead:
    account = _account_config(account_id)
    try:
        regions = AwsIntegrationService().health(account)
    except AwsIntegrationError as exc:
        raise _aws_unavailable(exc) from exc
    return AwsAccountHealthRead(account_id=account_id, status="healthy", regions=regions)


@router.post(
    "/{account_id}/sync/guardduty",
    response_model=GuardDutySyncRead,
)
def sync_guardduty(
    account_id: str,
    db: Database,
    _: Annotated[
        User,
        Depends(require_roles(UserRole.ADMINISTRATOR, UserRole.SECURITY_ANALYST)),
    ],
    region: Annotated[str, Query(min_length=1, max_length=64, pattern=r"^[a-z0-9-]+$")],
    limit: Annotated[int, Query(ge=1, le=50)] = 25,
) -> GuardDutySyncRead:
    account = _account_config(account_id)
    service = AwsIntegrationService()
    try:
        findings = service.guardduty_findings(account, region, limit)
    except AwsIntegrationError as exc:
        raise _aws_unavailable(exc) from exc

    ingested = 0
    duplicates = 0
    alert_ids: set[str] = set()
    try:
        for finding in findings:
            result = ingest_cloudtrail_event(
                db,
                build_guardduty_envelope(finding, account, region),
            )
            if result.duplicate:
                duplicates += 1
            else:
                ingested += 1
            alert_ids.update(str(alert.id) for alert in result.alerts)
    except (AwsIntegrationError, EventNormalizationError, ValidationError) as exc:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="An AWS finding could not be normalized or ingested",
        ) from exc
    return GuardDutySyncRead(
        account_id=account_id,
        region=region,
        fetched=len(findings),
        ingested=ingested,
        duplicates=duplicates,
        alert_ids=sorted(alert_ids),
    )
