import argparse
import json
import sys
from datetime import UTC, datetime, timedelta
from uuid import UUID

from sqlalchemy import delete, select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.database import get_session_factory
from app.models import CloudTrailEvent, DetectionAlert


def prune_expired_events(
    session: Session,
    *,
    older_than_days: int = 90,
    apply: bool = False,
    batch_size: int = 1000,
) -> dict[str, int | bool]:
    if older_than_days < 1:
        raise ValueError("older_than_days must be at least one")
    if batch_size < 1 or batch_size > 10000:
        raise ValueError("batch_size must be between 1 and 10000")

    cutoff = datetime.now(UTC) - timedelta(days=older_than_days)
    evidence_ids = {
        event_id
        for event_refs in session.scalars(select(DetectionAlert.event_refs))
        for event_id in event_refs
    }

    scanned = 0
    eligible = 0
    preserved = 0
    last_id: UUID | None = None
    try:
        while True:
            query = (
                select(CloudTrailEvent.id)
                .where(CloudTrailEvent.event_time < cutoff)
                .order_by(CloudTrailEvent.id)
                .limit(batch_size)
            )
            if last_id is not None:
                query = query.where(CloudTrailEvent.id > last_id)
            event_ids = list(session.scalars(query))
            if not event_ids:
                break

            scanned += len(event_ids)
            last_id = event_ids[-1]
            deletable = [event_id for event_id in event_ids if str(event_id) not in evidence_ids]
            eligible += len(deletable)
            preserved += len(event_ids) - len(deletable)
            if apply and deletable:
                session.execute(delete(CloudTrailEvent).where(CloudTrailEvent.id.in_(deletable)))

        if apply:
            session.commit()
        else:
            session.rollback()
    except SQLAlchemyError:
        session.rollback()
        raise

    return {
        "dry_run": not apply,
        "older_than_days": older_than_days,
        "scanned": scanned,
        "eligible_for_deletion": eligible,
        "preserved_as_alert_evidence": preserved,
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Preview or remove old CloudTrail events not referenced by detection alerts."
    )
    parser.add_argument("--older-than-days", type=int, default=90)
    parser.add_argument("--batch-size", type=int, default=1000)
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Commit deletion. Without this flag the command only reports eligible records.",
    )
    arguments = parser.parse_args()

    session = get_session_factory()()
    try:
        result = prune_expired_events(
            session,
            older_than_days=arguments.older_than_days,
            apply=arguments.apply,
            batch_size=arguments.batch_size,
        )
    finally:
        session.close()
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
