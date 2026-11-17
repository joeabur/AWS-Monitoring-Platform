from datetime import UTC, datetime
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, select

from app.api.dependencies import CurrentUser, Database, require_roles
from app.ingestion.cloudtrail import EventNormalizationError
from app.ingestion.service import ingest_cloudtrail_event
from app.models import CloudTrailEvent, User
from app.schemas.auth import UserRole
from app.schemas.events import (
    CloudTrailEventDetailRead,
    EventIngestResponse,
    EventPage,
)

router = APIRouter(prefix="/api/v1/events", tags=["events"])


@router.post("/ingest", response_model=EventIngestResponse)
def ingest_event(
    payload: dict[str, object],
    db: Database,
    _: Annotated[
        User,
        Depends(require_roles(UserRole.ADMINISTRATOR, UserRole.SECURITY_ANALYST)),
    ],
) -> EventIngestResponse:
    try:
        result = ingest_cloudtrail_event(db, payload)
    except EventNormalizationError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=str(exc),
        ) from exc
    return EventIngestResponse(event=result.event, duplicate=result.duplicate)


@router.get("", response_model=EventPage)
def list_events(
    db: Database,
    _: CurrentUser,
    account_id: Annotated[str | None, Query(pattern=r"^\d{12}$")] = None,
    region: Annotated[str | None, Query(min_length=1, max_length=64)] = None,
    event_name: Annotated[str | None, Query(min_length=1, max_length=255)] = None,
    since: Annotated[datetime | None, Query()] = None,
    until: Annotated[datetime | None, Query()] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> EventPage:
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
        filters.append(CloudTrailEvent.account_id == account_id)
    if region is not None:
        filters.append(CloudTrailEvent.region == region.lower())
    if event_name is not None:
        filters.append(CloudTrailEvent.event_name == event_name)
    if start is not None:
        filters.append(CloudTrailEvent.event_time >= start)
    if end is not None:
        filters.append(CloudTrailEvent.event_time <= end)

    total = db.scalar(select(func.count()).select_from(CloudTrailEvent).where(*filters)) or 0
    records = db.scalars(
        select(CloudTrailEvent)
        .where(*filters)
        .order_by(CloudTrailEvent.event_time.desc(), CloudTrailEvent.id)
        .limit(limit)
        .offset(offset)
    ).all()
    return EventPage(items=records, total=total, limit=limit, offset=offset)


@router.get("/{event_id}", response_model=CloudTrailEventDetailRead)
def get_event(event_id: UUID, db: Database, _: CurrentUser) -> CloudTrailEvent:
    record = db.get(CloudTrailEvent, event_id)
    if record is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Event not found")
    return record
