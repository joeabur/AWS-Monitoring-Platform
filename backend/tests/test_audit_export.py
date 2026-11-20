import json
from datetime import UTC, datetime, timedelta
from unittest.mock import Mock
from uuid import uuid4

import pytest
from sqlalchemy import select

from app.models import (
    AuditExportState,
    Incident,
    IncidentAuditEntry,
    ResponseAction,
    ResponseActionAuditEntry,
    User,
)
from app.scripts.export_audit import export_audit_entries


def test_exports_both_audit_trails_to_compliance_locked_s3_and_advances_watermark(
    db_session, capsys
) -> None:
    now = datetime.now(UTC) + timedelta(minutes=1)
    user = db_session.scalar(select(User).where(User.email == "admin@example.com"))
    assert user is not None
    incident = Incident(
        correlation_key=uuid4().hex,
        correlation_group=uuid4().hex,
        title="Audit export test",
        description="Incident used to test immutable audit exports.",
        severity="low",
        risk_score=10,
        score_basis="Test-only priority.",
        account_id="111122223333",
        region="us-east-1",
        resource_arns=[],
        first_observed_at=now,
        last_observed_at=now,
    )
    db_session.add(incident)
    db_session.flush()
    incident_entry = IncidentAuditEntry(
        incident_id=incident.id,
        actor_id=user.id,
        action="status_changed",
        previous_value="new",
        new_value="acknowledged",
        details={"reason": "test"},
        created_at=now - timedelta(seconds=2),
    )
    action = ResponseAction(
        incident_id=incident.id,
        action_type="disable_access_key",
        account_id="111122223333",
        region="us-east-1",
        target_user_name="test-user",
        target_access_key_id="AKIAEXAMPLE",
        reason="Test-only response action.",
        requested_by=user.id,
        created_at=now - timedelta(seconds=1),
    )
    db_session.add_all([incident_entry, action])
    db_session.flush()
    response_entry = ResponseActionAuditEntry(
        response_action_id=action.id,
        actor_id=user.id,
        action="approved",
        details={"status": "approved"},
        created_at=now - timedelta(seconds=1),
    )
    db_session.add(response_entry)
    db_session.commit()

    s3 = Mock()
    result = export_audit_entries(
        db_session,
        bucket="audit-archive",
        retention_days=90,
        s3_client=s3,
        now=now,
    )

    assert result == {
        "records_exported": 2,
        "objects_written": 1,
        "watermark_end": now.isoformat(),
    }
    request = s3.put_object.call_args.kwargs
    document = json.loads(request["Body"])
    assert [entry["type"] for entry in document["entries"]] == ["incident", "response_action"]
    assert request["Bucket"] == "audit-archive"
    assert request["ServerSideEncryption"] == "aws:kms"
    assert request["ObjectLockMode"] == "COMPLIANCE"
    assert request["ObjectLockRetainUntilDate"] == now + timedelta(days=90)
    state = db_session.scalar(select(AuditExportState).where(AuditExportState.id == 1))
    assert state is not None
    assert state.last_exported_at.replace(tzinfo=UTC) == now

    second_result = export_audit_entries(
        db_session,
        bucket="audit-archive",
        retention_days=90,
        s3_client=s3,
        now=now + timedelta(days=1),
    )
    assert second_result["records_exported"] == 0
    assert s3.put_object.call_count == 1

    next_entry = IncidentAuditEntry(
        incident_id=incident.id,
        actor_id=user.id,
        action="note_added",
        details={"reason": "inserted after first export"},
        created_at=now,
    )
    db_session.add(next_entry)
    db_session.commit()
    third_result = export_audit_entries(
        db_session,
        bucket="audit-archive",
        retention_days=90,
        s3_client=s3,
        now=now + timedelta(days=2),
    )
    assert third_result["records_exported"] == 1
    assert s3.put_object.call_count == 2
    assert next_entry.archived_at.replace(tzinfo=UTC) == now + timedelta(days=2)
    assert "AuditRecordsExported" in capsys.readouterr().out


def test_s3_failure_does_not_advance_audit_export_watermark(db_session) -> None:
    now = datetime.now(UTC) + timedelta(minutes=1)
    user = db_session.scalar(select(User).where(User.email == "admin@example.com"))
    assert user is not None
    incident = Incident(
        correlation_key=uuid4().hex,
        correlation_group=uuid4().hex,
        title="Audit export failure test",
        description="Incident used to test failed archive writes.",
        severity="low",
        risk_score=10,
        score_basis="Test-only priority.",
        account_id="111122223333",
        region="us-east-1",
        resource_arns=[],
        first_observed_at=now,
        last_observed_at=now,
    )
    db_session.add(incident)
    db_session.flush()
    db_session.add(
        IncidentAuditEntry(
            incident_id=incident.id,
            actor_id=user.id,
            action="status_changed",
            details={"reason": "test"},
        )
    )
    db_session.commit()
    s3 = Mock()
    s3.put_object.side_effect = RuntimeError("S3 unavailable")

    with pytest.raises(RuntimeError, match="S3 unavailable"):
        export_audit_entries(
            db_session,
            bucket="audit-archive",
            retention_days=90,
            s3_client=s3,
            now=now,
        )

    db_session.rollback()
    state = db_session.scalar(select(AuditExportState).where(AuditExportState.id == 1))
    assert state is None
    entry = db_session.scalar(select(IncidentAuditEntry))
    assert entry is not None
    assert entry.archived_at is None
