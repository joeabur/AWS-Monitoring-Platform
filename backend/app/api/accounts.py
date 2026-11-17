from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import ValidationError
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from app.api.dependencies import CurrentUser, Database, require_roles
from app.core.config import MonitoredAwsAccount, get_settings
from app.ingestion.cloudtrail import EventNormalizationError
from app.ingestion.service import ingest_cloudtrail_event
from app.integrations.aws import (
    AwsIntegrationError,
    AwsIntegrationService,
    build_guardduty_envelope,
    build_securityhub_envelope,
)
from app.models import AwsIntegrationHealth, User
from app.schemas.accounts import (
    AwsAccountHealthRead,
    AwsAccountRead,
    AwsFindingSyncRead,
)
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


def _record_integration_health(
    db: Database,
    account_id: str,
    integration: str,
    region: str,
    *,
    healthy: bool,
    resource_count: int = 0,
    error_code: str | None = None,
) -> None:
    now = datetime.now(UTC)
    record = db.scalar(
        select(AwsIntegrationHealth).where(
            AwsIntegrationHealth.account_id == account_id,
            AwsIntegrationHealth.integration == integration,
            AwsIntegrationHealth.region == region,
        )
    )
    if record is None:
        record = AwsIntegrationHealth(
            account_id=account_id,
            integration=integration,
            region=region,
            status="healthy" if healthy else "unhealthy",
            last_error_code=error_code,
            resource_count=resource_count,
            last_checked_at=now,
            last_success_at=now if healthy else None,
        )
        try:
            with db.begin_nested():
                db.add(record)
                db.flush()
        except IntegrityError:
            record = db.scalar(
                select(AwsIntegrationHealth).where(
                    AwsIntegrationHealth.account_id == account_id,
                    AwsIntegrationHealth.integration == integration,
                    AwsIntegrationHealth.region == region,
                )
            )
            if record is None:
                raise
    record.status = "healthy" if healthy else "unhealthy"
    record.last_error_code = error_code
    record.resource_count = resource_count
    record.last_checked_at = now
    if healthy:
        record.last_success_at = now
    db.commit()


def _ingest_envelopes(
    db: Database,
    account: MonitoredAwsAccount,
    region: str,
    integration: str,
    envelopes: list[dict[str, object]],
) -> AwsFindingSyncRead:
    ingested = 0
    duplicates = 0
    alert_ids: set[str] = set()
    try:
        for envelope in envelopes:
            result = ingest_cloudtrail_event(db, envelope)
            if result.duplicate:
                duplicates += 1
            else:
                ingested += 1
            alert_ids.update(str(alert.id) for alert in result.alerts)
    except (AwsIntegrationError, EventNormalizationError, ValidationError) as exc:
        db.rollback()
        _record_integration_health(
            db, account.account_id, integration, region, healthy=False, error_code="IngestionFailed"
        )
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="An AWS finding could not be normalized or ingested",
        ) from exc
    _record_integration_health(
        db, account.account_id, integration, region, healthy=True, resource_count=len(envelopes)
    )
    return AwsFindingSyncRead(
        account_id=account.account_id,
        region=region,
        fetched=len(envelopes),
        ingested=ingested,
        duplicates=duplicates,
        alert_ids=sorted(alert_ids),
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
    db: Database,
    _: CurrentUser,
) -> AwsAccountHealthRead:
    account = _account_config(account_id)
    try:
        regions = AwsIntegrationService().health(account)
    except AwsIntegrationError as exc:
        _record_integration_health(db, account_id, "sts", "", healthy=False, error_code=exc.code)
        raise _aws_unavailable(exc) from exc
    _record_integration_health(db, account_id, "sts", "", healthy=True, resource_count=len(regions))
    integrations = db.scalars(
        select(AwsIntegrationHealth)
        .where(AwsIntegrationHealth.account_id == account_id)
        .order_by(AwsIntegrationHealth.integration, AwsIntegrationHealth.region)
    ).all()
    return AwsAccountHealthRead(
        account_id=account_id,
        status="healthy",
        regions=regions,
        integrations=integrations,
    )


@router.post(
    "/{account_id}/sync/guardduty",
    response_model=AwsFindingSyncRead,
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
) -> AwsFindingSyncRead:
    account = _account_config(account_id)
    service = AwsIntegrationService()
    try:
        findings = service.guardduty_findings(account, region, limit)
    except AwsIntegrationError as exc:
        _record_integration_health(
            db, account_id, "guardduty", region, healthy=False, error_code=exc.code
        )
        raise _aws_unavailable(exc) from exc

    try:
        envelopes = [build_guardduty_envelope(finding, account, region) for finding in findings]
    except AwsIntegrationError as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="An AWS finding could not be normalized or ingested",
        ) from exc
    return _ingest_envelopes(db, account, region, "guardduty", envelopes)


@router.post("/{account_id}/sync/security-hub", response_model=AwsFindingSyncRead)
def sync_security_hub(
    account_id: str,
    db: Database,
    _: Annotated[
        User,
        Depends(require_roles(UserRole.ADMINISTRATOR, UserRole.SECURITY_ANALYST)),
    ],
    region: Annotated[str, Query(min_length=1, max_length=64, pattern=r"^[a-z0-9-]+$")],
    limit: Annotated[int, Query(ge=1, le=50)] = 25,
) -> AwsFindingSyncRead:
    account = _account_config(account_id)
    try:
        findings = AwsIntegrationService().securityhub_findings(account, region, limit)
        envelopes = [build_securityhub_envelope(finding, account, region) for finding in findings]
    except AwsIntegrationError as exc:
        _record_integration_health(
            db, account_id, "securityhub", region, healthy=False, error_code=exc.code
        )
        raise _aws_unavailable(exc) from exc
    return _ingest_envelopes(db, account, region, "securityhub", envelopes)


@router.post("/{account_id}/sync/config", response_model=AwsFindingSyncRead)
def sync_config(
    account_id: str,
    db: Database,
    _: Annotated[
        User,
        Depends(require_roles(UserRole.ADMINISTRATOR, UserRole.SECURITY_ANALYST)),
    ],
    region: Annotated[str, Query(min_length=1, max_length=64, pattern=r"^[a-z0-9-]+$")],
    limit: Annotated[int, Query(ge=1, le=50)] = 25,
) -> AwsFindingSyncRead:
    account = _account_config(account_id)
    try:
        envelopes = AwsIntegrationService().config_compliance_events(account, region, limit)
    except AwsIntegrationError as exc:
        _record_integration_health(
            db, account_id, "config", region, healthy=False, error_code=exc.code
        )
        raise _aws_unavailable(exc) from exc
    return _ingest_envelopes(db, account, region, "config", envelopes)
