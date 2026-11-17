from datetime import datetime
from enum import StrEnum
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from app.schemas.detections import AlertRead
from app.schemas.events import CloudTrailEventDetailRead


class IncidentStatus(StrEnum):
    NEW = "new"
    ACKNOWLEDGED = "acknowledged"
    INVESTIGATING = "investigating"
    CONTAINED = "contained"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"


class IncidentRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    title: str
    description: str
    status: IncidentStatus
    severity: str
    risk_score: int
    score_basis: str
    account_id: str
    region: str
    principal_id: str | None
    principal_arn: str | None
    source_ip: str | None
    resource_arns: list[str]
    assigned_to: UUID | None
    first_observed_at: datetime
    last_observed_at: datetime
    created_at: datetime
    updated_at: datetime


class IncidentPage(BaseModel):
    items: list[IncidentRead]
    total: int
    limit: int
    offset: int


class IncidentStatusUpdate(BaseModel):
    status: IncidentStatus


class IncidentAssignmentUpdate(BaseModel):
    assigned_to: UUID | None


class InvestigationNoteCreate(BaseModel):
    body: str = Field(min_length=1, max_length=4000)


class InvestigationNoteRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    incident_id: UUID
    author_id: UUID | None
    body: str
    created_at: datetime
    author_email: str | None = None


class IncidentAuditRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    actor_id: UUID | None
    action: str
    previous_value: str | None
    new_value: str | None
    details: dict[str, str]
    created_at: datetime


class IncidentTimelineEntry(BaseModel):
    entry_type: str
    occurred_at: datetime
    summary: str
    actor_id: UUID | None = None
    reference_id: UUID | None = None


class IncidentDetail(BaseModel):
    incident: IncidentRead
    alerts: list[AlertRead]
    events: list[CloudTrailEventDetailRead]
    notes: list[InvestigationNoteRead]
    audit_trail: list[IncidentAuditRead]
    timeline: list[IncidentTimelineEntry]
