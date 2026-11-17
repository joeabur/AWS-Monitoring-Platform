from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict


class NotificationChannelStatus(BaseModel):
    channel: str
    enabled: bool


class NotificationConfigurationRead(BaseModel):
    minimum_severity: str
    channels: list[NotificationChannelStatus]


class NotificationDeliveryRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    alert_id: UUID
    incident_id: UUID
    channel: str
    status: str
    attempt_count: int
    next_attempt_at: datetime
    last_attempt_at: datetime | None
    delivered_at: datetime | None
    last_error_code: str | None
    created_at: datetime
    updated_at: datetime


class NotificationDeliveryPage(BaseModel):
    items: list[NotificationDeliveryRead]
    total: int
    limit: int
    offset: int


class NotificationDispatchResult(BaseModel):
    selected: int
    sent: int
    retrying: int
    failed: int
