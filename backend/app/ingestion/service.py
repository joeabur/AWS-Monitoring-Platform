from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.ingestion.cloudtrail import normalize_cloudtrail_event
from app.models import CloudTrailEvent


@dataclass(frozen=True)
class IngestResult:
    event: CloudTrailEvent
    duplicate: bool


def ingest_cloudtrail_event(
    db: Session, event: dict[str, object], *, is_synthetic: bool = False
) -> IngestResult:
    normalized = normalize_cloudtrail_event(event, is_synthetic=is_synthetic)
    existing = db.scalar(
        select(CloudTrailEvent).where(CloudTrailEvent.event_key == normalized["event_key"])
    )
    if existing is not None:
        return IngestResult(event=existing, duplicate=True)

    record = CloudTrailEvent(**normalized)
    db.add(record)
    try:
        db.commit()
        db.refresh(record)
        return IngestResult(event=record, duplicate=False)
    except IntegrityError:
        db.rollback()
        existing = db.scalar(
            select(CloudTrailEvent).where(CloudTrailEvent.event_key == normalized["event_key"])
        )
        if existing is None:
            raise
        return IngestResult(event=existing, duplicate=True)
