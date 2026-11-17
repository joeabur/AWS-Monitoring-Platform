from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict


class CloudTrailEventRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    cloudtrail_event_id: str
    account_id: str
    region: str
    event_source: str
    event_name: str
    event_time: datetime
    ingested_at: datetime
    source_ip: str | None
    principal_type: str | None
    principal_id: str | None
    principal_arn: str | None
    error_code: str | None
    resource_arns: list[str]
    is_synthetic: bool


class CloudTrailEventDetailRead(CloudTrailEventRead):
    event_details: dict[str, object]


class EventIngestResponse(BaseModel):
    event: CloudTrailEventRead
    duplicate: bool
    alert_ids: list[UUID]


class EventIngestBatchResponse(BaseModel):
    events: list[CloudTrailEventRead]
    duplicate_count: int
    alert_ids: list[UUID]


class EventPage(BaseModel):
    items: list[CloudTrailEventRead]
    total: int
    limit: int
    offset: int
