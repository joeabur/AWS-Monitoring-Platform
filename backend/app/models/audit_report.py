from datetime import datetime
from uuid import UUID, uuid4

from sqlalchemy import (
    JSON,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Uuid,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.models.user import Base


class AuditorReport(Base):
    __tablename__ = "auditor_reports"
    __table_args__ = (
        Index("uq_auditor_reports_fingerprint", "fingerprint", unique=True),
        Index("ix_auditor_reports_account_generated", "account_id", "generated_at"),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)
    account_id: Mapped[str] = mapped_column(String(64), nullable=False)
    regions: Mapped[list[str]] = mapped_column(JSON, nullable=False)
    audit_profile: Mapped[str] = mapped_column(String(128), nullable=False)
    tool_name: Mapped[str] = mapped_column(String(128), nullable=False)
    tool_version: Mapped[str] = mapped_column(String(64), nullable=False)
    catalog_version: Mapped[str] = mapped_column(String(64), nullable=False)
    generated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    finding_count: Mapped[int] = mapped_column(Integer, nullable=False)
    imported_by: Mapped[UUID | None] = mapped_column(
        Uuid, ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    imported_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )


class AuditorFinding(Base):
    __tablename__ = "auditor_findings"
    __table_args__ = (
        Index(
            "uq_auditor_findings_report_source_id", "report_id", "source_finding_id", unique=True
        ),
        Index("ix_auditor_findings_account_resource", "account_id", "resource_id"),
        Index("ix_auditor_findings_control_status", "control_id", "status"),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    report_id: Mapped[UUID] = mapped_column(
        Uuid, ForeignKey("auditor_reports.id", ondelete="CASCADE"), nullable=False
    )
    report_generated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    source_finding_id: Mapped[str] = mapped_column(String(128), nullable=False)
    account_id: Mapped[str] = mapped_column(String(64), nullable=False)
    region: Mapped[str] = mapped_column(String(64), nullable=False)
    control_id: Mapped[str] = mapped_column(String(32), nullable=False)
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    resource_id: Mapped[str] = mapped_column(String(2048), nullable=False)
    resource_type: Mapped[str] = mapped_column(String(256), nullable=False)
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    message: Mapped[str] = mapped_column(String(2048), nullable=False)
    evidence: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False)
    sources: Mapped[list[str]] = mapped_column(JSON, nullable=False)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    remediation: Mapped[str] = mapped_column(String(4096), nullable=False)
    uncertainty: Mapped[list[str]] = mapped_column(JSON, nullable=False)
    suppression: Mapped[dict[str, object] | None] = mapped_column(JSON(none_as_null=True))
