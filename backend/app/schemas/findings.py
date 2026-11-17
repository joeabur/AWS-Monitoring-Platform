from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict


class AwsFindingRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    provider: str
    external_finding_id: str
    account_id: str
    region: str
    title: str
    severity: str | None
    status: str
    resource_arns: list[str]
    first_observed_at: datetime
    last_observed_at: datetime
    last_updated_at: datetime
    latest_event_id: UUID | None
    created_at: datetime
    updated_at: datetime


class AwsFindingPage(BaseModel):
    items: list[AwsFindingRead]
    total: int
    limit: int
    offset: int
