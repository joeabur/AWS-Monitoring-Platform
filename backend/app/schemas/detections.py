from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict

from app.schemas.events import CloudTrailEventDetailRead


class DetectionRuleRead(BaseModel):
    rule_id: str
    name: str
    description: str
    category: str
    severity: str
    risk_score: int
    mitre_technique_id: str | None
    mitre_technique_name: str | None
    event_sources: list[str]
    required_fields: list[str]
    investigation_steps: list[str]
    response_recommendations: list[str]
    version: int
    enabled: bool
    threshold: int
    window_minutes: int


class DetectionPreview(BaseModel):
    rule: DetectionRuleRead
    matched: bool
    evidence_event_ids: list[str]
    observed_count: int


class DetectionTestResponse(BaseModel):
    synthetic_test: bool
    results: list[DetectionPreview]


class AlertRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    rule_id: str
    rule_version: int
    title: str
    description: str
    severity: str
    risk_score: int
    score_basis: str
    account_id: str
    region: str
    principal_id: str | None
    principal_arn: str | None
    source_ip: str | None
    resource_arns: list[str]
    event_refs: list[str]
    observed_count: int
    mitre_technique_id: str | None
    mitre_technique_name: str | None
    investigation_steps: list[str]
    response_recommendations: list[str]
    status: str
    first_observed_at: datetime
    last_observed_at: datetime
    created_at: datetime
    updated_at: datetime


class AlertPage(BaseModel):
    items: list[AlertRead]
    total: int
    limit: int
    offset: int


class DetectionEventTestRequest(BaseModel):
    event: dict[str, object]


class AlertEvidenceRead(BaseModel):
    alert: AlertRead
    events: list[CloudTrailEventDetailRead]
