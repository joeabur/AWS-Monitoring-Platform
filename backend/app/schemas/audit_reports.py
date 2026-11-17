from datetime import date, datetime
from enum import StrEnum
from typing import Literal
from uuid import UUID

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, model_validator


class AuditFindingSeverity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class AuditFindingStatus(StrEnum):
    PASS = "PASS"
    FAIL = "FAIL"
    ERROR = "ERROR"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    NOT_ASSESSED = "NOT_ASSESSED"


class AuditSuppression(BaseModel):
    model_config = ConfigDict(extra="forbid")

    reason: str = Field(min_length=1, max_length=2048)
    owner: str = Field(min_length=1, max_length=256)
    expires: date


class AuditorFindingInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    finding_id: str = Field(min_length=1, max_length=128)
    control_id: str = Field(pattern=r"^[A-Z]{2,4}-\d{3}$")
    title: str = Field(min_length=1, max_length=512)
    account_id: str = Field(min_length=1, max_length=64)
    region: str = Field(min_length=1, max_length=64)
    resource_id: str = Field(min_length=1, max_length=2048)
    resource_type: str = Field(min_length=1, max_length=256)
    severity: AuditFindingSeverity
    status: AuditFindingStatus
    message: str = Field(max_length=2048)
    evidence: dict[str, object] = Field(default_factory=dict)
    sources: list[str] = Field(default_factory=list, max_length=256)
    observed_at: AwareDatetime
    remediation: str = Field(max_length=4096)
    uncertainty: list[str] = Field(default_factory=list, max_length=256)
    suppression: AuditSuppression | None = None


class AuditorReportInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal[1]
    tool: dict[str, str]
    catalog_version: str = Field(min_length=1, max_length=64)
    generated_at: AwareDatetime
    started_at: AwareDatetime
    account_id: str = Field(min_length=1, max_length=64)
    regions: list[str] = Field(max_length=1000)
    audit_profile: str = Field(min_length=1, max_length=128)
    controls_evaluated: list[str] = Field(max_length=1000)
    summary: dict[str, object]
    api_actions: dict[str, int]
    warnings: list[str] = Field(max_length=1000)
    disclaimer: str = Field(max_length=4096)
    findings: list[AuditorFindingInput] = Field(max_length=10000)

    @model_validator(mode="after")
    def validate_tool_and_findings(self) -> "AuditorReportInput":
        if self.tool.get("name") != "aws-security-auditing-tool":
            raise ValueError("Report tool must be aws-security-auditing-tool")
        if self.generated_at < self.started_at:
            raise ValueError("Report generated_at cannot precede started_at")
        finding_ids = [finding.finding_id for finding in self.findings]
        if len(finding_ids) != len(set(finding_ids)):
            raise ValueError("Report contains duplicate finding IDs")
        return self


class AuditFindingRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    report_id: UUID
    report_generated_at: datetime
    source_finding_id: str
    account_id: str
    region: str
    control_id: str
    title: str
    resource_id: str
    resource_type: str
    severity: AuditFindingSeverity
    status: AuditFindingStatus
    message: str
    evidence: dict[str, object]
    sources: list[str]
    observed_at: datetime
    remediation: str
    uncertainty: list[str]
    suppression: AuditSuppression | None


class AuditReportRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    fingerprint: str
    account_id: str
    regions: list[str]
    audit_profile: str
    tool_name: str
    tool_version: str
    catalog_version: str
    generated_at: datetime
    started_at: datetime
    finding_count: int
    imported_by: UUID | None
    imported_at: datetime


class AuditReportImportResult(BaseModel):
    report: AuditReportRead
    findings_imported: int
    duplicate: bool


class AuditReportPage(BaseModel):
    items: list[AuditReportRead]
    total: int
    limit: int
    offset: int


class AuditReportDetail(BaseModel):
    report: AuditReportRead
    findings: list[AuditFindingRead]
    total: int
    limit: int
    offset: int


class AuditFindingPage(BaseModel):
    items: list[AuditFindingRead]
    total: int
    limit: int
    offset: int
