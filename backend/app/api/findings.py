from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, HTTPException, Query, status
from sqlalchemy import func, select

from app.api.dependencies import CurrentUser, Database
from app.models import AwsFinding
from app.schemas.findings import AwsFindingPage

router = APIRouter(prefix="/api/v1/findings", tags=["findings"])


@router.get("", response_model=AwsFindingPage)
def list_findings(
    db: Database,
    _: CurrentUser,
    account_id: Annotated[str | None, Query(pattern=r"^\d{12}$")] = None,
    region: Annotated[str | None, Query(min_length=1, max_length=64)] = None,
    provider: Annotated[str | None, Query(pattern=r"^(guardduty|securityhub|config)$")] = None,
    severity: Annotated[
        str | None, Query(pattern=r"^(critical|high|medium|low|informational)$")
    ] = None,
    finding_status: Annotated[
        str | None, Query(alias="status", min_length=1, max_length=32)
    ] = None,
    search: Annotated[str | None, Query(min_length=1, max_length=256)] = None,
    since: Annotated[datetime | None, Query()] = None,
    until: Annotated[datetime | None, Query()] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> AwsFindingPage:
    def as_utc(value: datetime | None, name: str) -> datetime | None:
        if value is None:
            return None
        if value.tzinfo is None or value.utcoffset() is None:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail=f"{name} must include a timezone",
            )
        return value.astimezone(UTC)

    start = as_utc(since, "since")
    end = as_utc(until, "until")
    if start is not None and end is not None and end < start:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="until must be greater than or equal to since",
        )

    filters = []
    if account_id is not None:
        filters.append(AwsFinding.account_id == account_id)
    if region is not None:
        filters.append(AwsFinding.region == region.lower())
    if provider is not None:
        filters.append(AwsFinding.provider == provider)
    if severity is not None:
        filters.append(AwsFinding.severity == severity)
    if finding_status is not None:
        filters.append(AwsFinding.status == finding_status.lower())
    if search is not None:
        filters.append(AwsFinding.title.ilike(f"%{search}%"))
    if start is not None:
        filters.append(AwsFinding.last_observed_at >= start)
    if end is not None:
        filters.append(AwsFinding.last_observed_at <= end)

    total = db.scalar(select(func.count()).select_from(AwsFinding).where(*filters)) or 0
    records = db.scalars(
        select(AwsFinding)
        .where(*filters)
        .order_by(AwsFinding.last_updated_at.desc(), AwsFinding.id)
        .limit(limit)
        .offset(offset)
    ).all()
    return AwsFindingPage(items=records, total=total, limit=limit, offset=offset)
