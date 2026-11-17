import hashlib
from datetime import UTC, datetime, timedelta
from typing import Annotated
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import case, func, or_, select
from sqlalchemy.orm import Session

from app.api.dependencies import CurrentUser, Database, require_roles
from app.models import CloudTrailEvent, DetectionAlert, Incident, IncidentAlert, IncidentAuditEntry
from app.models.incident import InvestigationNote
from app.models.user import User
from app.schemas.auth import UserRole
from app.schemas.detections import AlertRead
from app.schemas.events import CloudTrailEventDetailRead
from app.schemas.incidents import (
    IncidentAssignmentUpdate,
    IncidentAuditRead,
    IncidentDetail,
    IncidentPage,
    IncidentRead,
    IncidentStatus,
    IncidentStatusUpdate,
    IncidentTimelineEntry,
    InvestigationNoteCreate,
    InvestigationNoteRead,
)

router = APIRouter(prefix="/api/v1/incidents", tags=["incidents"])
_WRITE_ROLES = (UserRole.ADMINISTRATOR, UserRole.SECURITY_ANALYST)
_FINAL_STATUSES = {IncidentStatus.RESOLVED, IncidentStatus.FALSE_POSITIVE}
_TRANSITIONS = {
    IncidentStatus.NEW: {
        IncidentStatus.ACKNOWLEDGED,
        IncidentStatus.INVESTIGATING,
        IncidentStatus.CONTAINED,
        IncidentStatus.RESOLVED,
        IncidentStatus.FALSE_POSITIVE,
    },
    IncidentStatus.ACKNOWLEDGED: {
        IncidentStatus.INVESTIGATING,
        IncidentStatus.CONTAINED,
        IncidentStatus.RESOLVED,
        IncidentStatus.FALSE_POSITIVE,
    },
    IncidentStatus.INVESTIGATING: {
        IncidentStatus.ACKNOWLEDGED,
        IncidentStatus.CONTAINED,
        IncidentStatus.RESOLVED,
        IncidentStatus.FALSE_POSITIVE,
    },
    IncidentStatus.CONTAINED: {
        IncidentStatus.INVESTIGATING,
        IncidentStatus.RESOLVED,
        IncidentStatus.FALSE_POSITIVE,
    },
    IncidentStatus.RESOLVED: {IncidentStatus.INVESTIGATING},
    IncidentStatus.FALSE_POSITIVE: {IncidentStatus.INVESTIGATING},
}


def _get_incident(db: Session, incident_id: UUID) -> Incident:
    incident = db.get(Incident, incident_id)
    if incident is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Incident not found")
    return incident


def _audit(
    db: Session,
    incident: Incident,
    actor: User,
    action: str,
    *,
    previous: str | None = None,
    new: str | None = None,
    details: dict[str, str] | None = None,
) -> None:
    db.add(
        IncidentAuditEntry(
            incident_id=incident.id,
            actor_id=actor.id,
            action=action,
            previous_value=previous,
            new_value=new,
            details=details or {},
        )
    )


@router.get("", response_model=IncidentPage)
def list_incidents(
    db: Database,
    _: CurrentUser,
    incident_status: Annotated[IncidentStatus | None, Query(alias="status")] = None,
    severity: Annotated[
        str | None, Query(pattern="^(critical|high|medium|low|informational)$")
    ] = None,
    account_id: Annotated[str | None, Query(pattern=r"^\d{12}$")] = None,
    region: Annotated[str | None, Query(min_length=1, max_length=64)] = None,
    assigned_to: UUID | None = None,
    q: Annotated[str | None, Query(min_length=1, max_length=200)] = None,
    since: datetime | None = None,
    until: datetime | None = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> IncidentPage:
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
    if incident_status is not None:
        filters.append(Incident.status == incident_status.value)
    if severity is not None:
        filters.append(Incident.severity == severity)
    if account_id is not None:
        filters.append(Incident.account_id == account_id)
    if region is not None:
        filters.append(Incident.region == region.lower())
    if assigned_to is not None:
        filters.append(Incident.assigned_to == assigned_to)
    if start is not None:
        filters.append(Incident.last_observed_at >= start)
    if end is not None:
        filters.append(Incident.last_observed_at <= end)
    if q is not None:
        pattern = f"%{q}%"
        filters.append(
            or_(
                Incident.title.ilike(pattern),
                Incident.description.ilike(pattern),
                Incident.account_id.ilike(pattern),
                Incident.principal_id.ilike(pattern),
                Incident.principal_arn.ilike(pattern),
                Incident.source_ip.ilike(pattern),
            )
        )

    total = db.scalar(select(func.count()).select_from(Incident).where(*filters)) or 0
    incidents = db.scalars(
        select(Incident)
        .where(*filters)
        .order_by(
            case(
                (Incident.severity == "critical", 0),
                (Incident.severity == "high", 1),
                (Incident.severity == "medium", 2),
                (Incident.severity == "low", 3),
                else_=4,
            ),
            Incident.last_observed_at.desc(),
            Incident.id,
        )
        .limit(limit)
        .offset(offset)
    ).all()
    return IncidentPage(
        items=[IncidentRead.model_validate(item) for item in incidents],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.get("/{incident_id}", response_model=IncidentDetail)
def get_incident(
    incident_id: UUID,
    db: Database,
    _: CurrentUser,
) -> IncidentDetail:
    incident = _get_incident(db, incident_id)
    alerts = db.scalars(
        select(DetectionAlert)
        .join(IncidentAlert, IncidentAlert.alert_id == DetectionAlert.id)
        .where(IncidentAlert.incident_id == incident_id)
        .order_by(DetectionAlert.first_observed_at, DetectionAlert.id)
    ).all()
    event_ids = {UUID(ref) for alert in alerts for ref in alert.event_refs}
    events = (
        db.scalars(
            select(CloudTrailEvent)
            .where(CloudTrailEvent.id.in_(event_ids))
            .order_by(CloudTrailEvent.event_time, CloudTrailEvent.id)
        ).all()
        if event_ids
        else []
    )
    notes = db.scalars(
        select(InvestigationNote)
        .where(InvestigationNote.incident_id == incident_id)
        .order_by(InvestigationNote.created_at, InvestigationNote.id)
    ).all()
    audit_entries = db.scalars(
        select(IncidentAuditEntry)
        .where(IncidentAuditEntry.incident_id == incident_id)
        .order_by(IncidentAuditEntry.created_at, IncidentAuditEntry.id)
    ).all()
    user_ids = {note.author_id for note in notes if note.author_id is not None}
    users = (
        {
            user.id: user.email
            for user in db.scalars(select(User).where(User.id.in_(user_ids))).all()
        }
        if user_ids
        else {}
    )
    note_reads = [
        InvestigationNoteRead.model_validate(note).model_copy(
            update={"author_email": users.get(note.author_id)}
        )
        for note in notes
    ]

    timeline = [
        IncidentTimelineEntry(
            entry_type="event",
            occurred_at=event.event_time,
            summary=f"{event.event_source}:{event.event_name}",
            reference_id=event.id,
        )
        for event in events
    ]
    timeline.extend(
        IncidentTimelineEntry(
            entry_type="alert",
            occurred_at=alert.last_observed_at,
            summary=f"{alert.severity.title()} alert: {alert.title}",
            reference_id=alert.id,
        )
        for alert in alerts
    )
    timeline.extend(
        IncidentTimelineEntry(
            entry_type="note",
            occurred_at=note.created_at,
            summary=note.body,
            actor_id=note.author_id,
            reference_id=note.id,
        )
        for note in notes
    )
    timeline.extend(
        IncidentTimelineEntry(
            entry_type="audit",
            occurred_at=entry.created_at,
            summary=entry.action.replace("_", " "),
            actor_id=entry.actor_id,
            reference_id=entry.id,
        )
        for entry in audit_entries
    )
    timeline.sort(
        key=lambda entry: (
            entry.occurred_at.replace(tzinfo=UTC)
            if entry.occurred_at.tzinfo is None
            else entry.occurred_at.astimezone(UTC),
            str(entry.reference_id or ""),
        )
    )

    return IncidentDetail(
        incident=IncidentRead.model_validate(incident),
        alerts=[AlertRead.model_validate(alert) for alert in alerts],
        events=[CloudTrailEventDetailRead.model_validate(event) for event in events],
        notes=note_reads,
        audit_trail=[IncidentAuditRead.model_validate(entry) for entry in audit_entries],
        timeline=timeline,
    )


@router.put("/{incident_id}/status", response_model=IncidentRead)
def update_incident_status(
    incident_id: UUID,
    payload: IncidentStatusUpdate,
    db: Database,
    actor: Annotated[User, Depends(require_roles(*_WRITE_ROLES))],
) -> IncidentRead:
    incident = _get_incident(db, incident_id)
    previous = IncidentStatus(incident.status)
    if payload.status == previous:
        return IncidentRead.model_validate(incident)
    if payload.status not in _TRANSITIONS[previous]:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Cannot transition incident from {previous.value} to {payload.status.value}",
        )

    if previous in _FINAL_STATUSES and payload.status == IncidentStatus.INVESTIGATING:
        lower_bound = incident.last_observed_at - timedelta(hours=24)
        upper_bound = incident.last_observed_at + timedelta(hours=24)
        active = db.scalar(
            select(Incident.id).where(
                Incident.id != incident.id,
                Incident.correlation_key == incident.correlation_group,
                Incident.last_observed_at >= lower_bound,
                Incident.last_observed_at <= upper_bound,
            )
        )
        if active is not None:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Another active incident already covers this correlation group",
            )
        stale = db.scalars(
            select(Incident).where(
                Incident.id != incident.id,
                Incident.correlation_key == incident.correlation_group,
            )
        ).all()
        for stale_incident in stale:
            stale_key = hashlib.sha256(
                f"stale:{stale_incident.id}:{stale_incident.last_observed_at}".encode()
            ).hexdigest()
            stale_incident.correlation_key = stale_key
            db.add(
                IncidentAuditEntry(
                    incident_id=stale_incident.id,
                    action="correlation_window_elapsed",
                    previous_value=incident.correlation_group,
                    new_value=stale_key,
                )
            )

    incident.status = payload.status.value
    if payload.status in _FINAL_STATUSES:
        incident.correlation_key = hashlib.sha256(
            f"closed:{incident.id}:{datetime.now(UTC).isoformat()}".encode()
        ).hexdigest()
    elif previous in _FINAL_STATUSES:
        incident.correlation_key = incident.correlation_group
    _audit(
        db,
        incident,
        actor,
        "status_changed",
        previous=previous.value,
        new=payload.status.value,
    )
    db.commit()
    db.refresh(incident)
    return IncidentRead.model_validate(incident)


@router.put("/{incident_id}/assignment", response_model=IncidentRead)
def assign_incident(
    incident_id: UUID,
    payload: IncidentAssignmentUpdate,
    db: Database,
    actor: Annotated[User, Depends(require_roles(*_WRITE_ROLES))],
) -> IncidentRead:
    incident = _get_incident(db, incident_id)
    assignee_email: str | None = None
    if payload.assigned_to is not None:
        assignee = db.get(User, payload.assigned_to)
        if assignee is None or not assignee.is_active or assignee.role not in _WRITE_ROLES:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail="Assignee must be an active administrator or security analyst",
            )
        assignee_email = assignee.email

    previous = str(incident.assigned_to) if incident.assigned_to else None
    new = str(payload.assigned_to) if payload.assigned_to else None
    if previous != new:
        incident.assigned_to = payload.assigned_to
        _audit(
            db,
            incident,
            actor,
            "assigned",
            previous=previous,
            new=new,
            details={"assignee_email": assignee_email or ""},
        )
        db.commit()
        db.refresh(incident)
    return IncidentRead.model_validate(incident)


@router.post(
    "/{incident_id}/notes",
    response_model=InvestigationNoteRead,
    status_code=status.HTTP_201_CREATED,
)
def add_investigation_note(
    incident_id: UUID,
    payload: InvestigationNoteCreate,
    db: Database,
    actor: Annotated[User, Depends(require_roles(*_WRITE_ROLES))],
) -> InvestigationNoteRead:
    incident = _get_incident(db, incident_id)
    body = payload.body.strip()
    if not body:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="Note body cannot be blank",
        )
    note = InvestigationNote(id=uuid4(), incident_id=incident.id, author_id=actor.id, body=body)
    db.add(note)
    _audit(db, incident, actor, "note_added", details={"note_id": str(note.id)})
    db.commit()
    db.refresh(note)
    return InvestigationNoteRead.model_validate(note).model_copy(
        update={"author_email": actor.email}
    )
