from datetime import datetime

from pydantic import BaseModel, ConfigDict


class AwsAccountRead(BaseModel):
    account_id: str
    name: str
    assume_role_enabled: bool


class IntegrationHealthRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    integration: str
    region: str
    status: str
    last_error_code: str | None
    resource_count: int
    last_checked_at: datetime
    last_success_at: datetime | None


class AwsAccountHealthRead(BaseModel):
    account_id: str
    status: str
    regions: list[str]
    integrations: list[IntegrationHealthRead]


class AwsFindingSyncRead(BaseModel):
    account_id: str
    region: str
    fetched: int
    ingested: int
    duplicates: int
    alert_ids: list[str]
