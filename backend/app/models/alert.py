from datetime import datetime
from uuid import UUID, uuid4

from sqlalchemy import JSON, DateTime, Index, Integer, String, Uuid, func
from sqlalchemy.orm import Mapped, mapped_column

from app.models.user import Base


class DetectionAlert(Base):
    __tablename__ = "detection_alerts"
    __table_args__ = (
        Index("ix_detection_alert_account_status", "account_id", "status"),
        Index("ix_detection_alert_severity_time", "severity", "last_observed_at"),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    dedup_key: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    rule_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    rule_version: Mapped[int] = mapped_column(Integer, nullable=False)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(String(2048), nullable=False)
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    risk_score: Mapped[int] = mapped_column(Integer, nullable=False)
    score_basis: Mapped[str] = mapped_column(String(512), nullable=False)
    account_id: Mapped[str] = mapped_column(String(12), nullable=False)
    region: Mapped[str] = mapped_column(String(64), nullable=False)
    principal_id: Mapped[str | None] = mapped_column(String(2048))
    principal_arn: Mapped[str | None] = mapped_column(String(2048))
    source_ip: Mapped[str | None] = mapped_column(String(128))
    resource_arns: Mapped[list[str]] = mapped_column(JSON, nullable=False)
    event_refs: Mapped[list[str]] = mapped_column(JSON, nullable=False)
    observed_count: Mapped[int] = mapped_column(Integer, nullable=False)
    mitre_technique_id: Mapped[str | None] = mapped_column(String(32))
    mitre_technique_name: Mapped[str | None] = mapped_column(String(128))
    investigation_steps: Mapped[list[str]] = mapped_column(JSON, nullable=False)
    response_recommendations: Mapped[list[str]] = mapped_column(JSON, nullable=False)
    status: Mapped[str] = mapped_column(String(16), default="open", nullable=False)
    first_observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )
