import argparse
import hashlib
import json
import sys
from datetime import UTC, datetime, timedelta

import boto3
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.database import get_session_factory
from app.models import AuditExportState, IncidentAuditEntry, ResponseActionAuditEntry
from app.telemetry import emit_emf_metric


def export_audit_entries(
    session: Session,
    *,
    bucket: str,
    retention_days: int,
    s3_client,
    now: datetime | None = None,
) -> dict[str, int | str]:
    if not bucket.strip():
        raise ValueError("An S3 audit archive bucket is required")
    if retention_days < 1:
        raise ValueError("retention_days must be at least one")

    now = _utc(now) if now is not None else datetime.now(UTC)
    bucket = bucket.strip()
    state = session.scalar(
        select(AuditExportState).where(AuditExportState.id == 1).with_for_update()
    )
    if state is None:
        state = AuditExportState(id=1, last_exported_at=None)
        session.add(state)
        session.flush()

    incident_query = (
        select(IncidentAuditEntry)
        .where(IncidentAuditEntry.archived_at.is_(None))
        .order_by(IncidentAuditEntry.created_at, IncidentAuditEntry.id)
        .with_for_update()
    )
    response_query = (
        select(ResponseActionAuditEntry)
        .where(ResponseActionAuditEntry.archived_at.is_(None))
        .order_by(ResponseActionAuditEntry.created_at, ResponseActionAuditEntry.id)
        .with_for_update()
    )

    entries: list[dict[str, object]] = []
    incident_entries = session.scalars(incident_query).all()
    response_entries = session.scalars(response_query).all()
    for entry in incident_entries:
        entries.append(
            {
                "type": "incident",
                "id": str(entry.id),
                "incident_id": str(entry.incident_id),
                "actor_id": str(entry.actor_id) if entry.actor_id else None,
                "action": entry.action,
                "previous_value": entry.previous_value,
                "new_value": entry.new_value,
                "details": entry.details,
                "created_at": _utc(entry.created_at).isoformat(),
            }
        )
    for entry in response_entries:
        entries.append(
            {
                "type": "response_action",
                "id": str(entry.id),
                "response_action_id": str(entry.response_action_id),
                "actor_id": str(entry.actor_id) if entry.actor_id else None,
                "action": entry.action,
                "details": entry.details,
                "created_at": _utc(entry.created_at).isoformat(),
            }
        )

    entries.sort(key=lambda entry: (str(entry["created_at"]), str(entry["id"])))
    object_count = 0
    if entries:
        export = {
            "schema_version": 1,
            "exported_at": now.isoformat(),
            "entries": entries,
        }
        body = json.dumps(export, sort_keys=True, separators=(",", ":")).encode()
        digest = hashlib.sha256(
            json.dumps(entries, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        key = f"audit-trails/{now:%Y/%m/%d}/{digest}.json"
        s3_client.put_object(
            Bucket=bucket,
            Key=key,
            Body=body,
            ContentType="application/json",
            ServerSideEncryption="aws:kms",
            BucketKeyEnabled=True,
            ObjectLockMode="COMPLIANCE",
            ObjectLockRetainUntilDate=now + timedelta(days=retention_days),
            Metadata={"sha256": digest},
        )
        object_count = 1
        for entry in incident_entries:
            entry.archived_at = now
        for entry in response_entries:
            entry.archived_at = now

    state.last_exported_at = now
    session.commit()
    result: dict[str, int | str] = {
        "records_exported": len(entries),
        "objects_written": object_count,
        "watermark_end": now.isoformat(),
    }
    emit_emf_metric(
        {
            "_aws": {
                "Timestamp": int(now.timestamp() * 1000),
                "CloudWatchMetrics": [
                    {
                        "Namespace": "AWSMonitoringPlatform",
                        "Dimensions": [["Service"]],
                        "Metrics": [
                            {"Name": "AuditRecordsExported", "Unit": "Count"},
                            {"Name": "AuditExportObjectsWritten", "Unit": "Count"},
                        ],
                    }
                ],
            },
            "Service": "audit-export",
            "AuditRecordsExported": len(entries),
            "AuditExportObjectsWritten": object_count,
        }
    )
    return result


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def main() -> int:
    settings = get_settings()
    parser = argparse.ArgumentParser(
        description="Export new incident and response audit entries to immutable S3 storage."
    )
    parser.add_argument("--bucket", default=settings.audit_archive_bucket)
    arguments = parser.parse_args()
    if not arguments.bucket:
        raise SystemExit("AUDIT_ARCHIVE_BUCKET or --bucket is required.")

    session = get_session_factory()()
    try:
        result = export_audit_entries(
            session,
            bucket=arguments.bucket,
            retention_days=settings.evidence_retention_days,
            s3_client=boto3.client("s3"),
        )
    finally:
        session.close()
    print(json.dumps(result, sort_keys=True), file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
