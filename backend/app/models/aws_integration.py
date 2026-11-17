from datetime import datetime
from uuid import UUID, uuid4

from sqlalchemy import (
    JSON,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    String,
    Uuid,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.models.user import Base


class AwsFinding(Base):
    __tablename__ = "aws_findings"
    __table_args__ = (
        Index(
            "uq_aws_findings_provider_account_region_id",
            "provider",
            "account_id",
            "region",
            "external_finding_id",
            unique=True,
        ),
        Index("ix_aws_findings_status_updated", "status", "last_updated_at"),
        Index("ix_aws_findings_account_provider", "account_id", "provider"),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    provider: Mapped[str] = mapped_column(String(32), nullable=False)
    external_finding_id: Mapped[str] = mapped_column(String(2048), nullable=False)
    account_id: Mapped[str] = mapped_column(String(12), nullable=False)
    region: Mapped[str] = mapped_column(String(64), nullable=False)
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    severity: Mapped[str | None] = mapped_column(String(16))
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    resource_arns: Mapped[list[str]] = mapped_column(JSON, nullable=False)
    first_observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    latest_event_id: Mapped[UUID | None] = mapped_column(
        Uuid, ForeignKey("cloudtrail_events.id", ondelete="SET NULL"), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )


class AwsIntegrationHealth(Base):
    __tablename__ = "aws_integration_health"
    __table_args__ = (
        CheckConstraint(
            "status IN ('healthy', 'unhealthy')",
            name="ck_aws_integration_health_status",
        ),
        Index(
            "uq_aws_integration_health_account_integration_region",
            "account_id",
            "integration",
            "region",
            unique=True,
        ),
        Index("ix_aws_integration_health_status_checked", "status", "last_checked_at"),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    account_id: Mapped[str] = mapped_column(String(12), nullable=False)
    integration: Mapped[str] = mapped_column(String(32), nullable=False)
    region: Mapped[str] = mapped_column(String(64), default="", nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False)
    last_error_code: Mapped[str | None] = mapped_column(String(128))
    resource_count: Mapped[int] = mapped_column(default=0, nullable=False)
    last_checked_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_success_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )
