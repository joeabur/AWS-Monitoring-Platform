from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator


class ResponseActionCreate(BaseModel):
    incident_id: UUID
    access_key_id: str = Field(pattern=r"^(AKIA|ASIA)[A-Z0-9]{16}$")
    reason: str = Field(min_length=10, max_length=4000)

    @field_validator("reason")
    @classmethod
    def require_nonblank_reason(cls, value: str) -> str:
        normalized = value.strip()
        if len(normalized) < 10:
            raise ValueError("reason must contain at least 10 non-whitespace characters")
        return normalized


class ResponseActionDecision(BaseModel):
    reason: str = Field(min_length=3, max_length=1000)

    @field_validator("reason")
    @classmethod
    def require_nonblank_reason(cls, value: str) -> str:
        normalized = value.strip()
        if len(normalized) < 3:
            raise ValueError("reason must contain at least 3 non-whitespace characters")
        return normalized


class ResponseActionRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    incident_id: UUID
    action_type: str
    account_id: str
    region: str
    target_principal_arn: str | None
    target_user_name: str
    target_access_key_id: str
    reason: str
    status: str
    dry_run: bool
    requested_by: UUID
    approved_by: UUID | None
    executed_by: UUID | None
    result: dict[str, object] | None
    error_code: str | None
    approved_at: datetime | None
    executed_at: datetime | None
    created_at: datetime
    updated_at: datetime


class ResponseActionAuditRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    actor_id: UUID | None
    action: str
    details: dict[str, str]
    created_at: datetime


class ResponseActionDetail(BaseModel):
    response_action: ResponseActionRead
    audit_trail: list[ResponseActionAuditRead]


class ResponseActionPage(BaseModel):
    items: list[ResponseActionRead]
    total: int
    limit: int
    offset: int


class ResponsePlaybookRead(BaseModel):
    action_type: str
    title: str
    description: str
    approval_required: bool
    live_enabled: bool
    dry_run: bool
