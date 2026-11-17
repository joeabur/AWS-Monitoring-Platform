from pydantic import BaseModel


class AwsAccountRead(BaseModel):
    account_id: str
    name: str
    assume_role_enabled: bool


class AwsAccountHealthRead(BaseModel):
    account_id: str
    status: str
    regions: list[str]


class GuardDutySyncRead(BaseModel):
    account_id: str
    region: str
    fetched: int
    ingested: int
    duplicates: int
    alert_ids: list[str]
