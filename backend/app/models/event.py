from datetime import datetime
from uuid import UUID, uuid4

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Index,
    String,
    Uuid,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.models.user import Base


class CloudTrailEvent(Base):
    __tablename__ = "cloudtrail_events"
    __table_args__ = (
        Index("ix_cloudtrail_account_region_time", "account_id", "region", "event_time"),
        Index("ix_cloudtrail_event_name_time", "event_name", "event_time"),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    event_key: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    cloudtrail_event_id: Mapped[str] = mapped_column(String(256), nullable=False)
    account_id: Mapped[str] = mapped_column(String(12), nullable=False)
    region: Mapped[str] = mapped_column(String(64), nullable=False)
    event_source: Mapped[str] = mapped_column(String(255), nullable=False)
    event_name: Mapped[str] = mapped_column(String(255), nullable=False)
    event_time: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    ingested_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    source_ip: Mapped[str | None] = mapped_column(String(128))
    principal_type: Mapped[str | None] = mapped_column(String(64))
    principal_id: Mapped[str | None] = mapped_column(String(2048))
    principal_arn: Mapped[str | None] = mapped_column(String(2048))
    user_agent: Mapped[str | None] = mapped_column(String(1024))
    error_code: Mapped[str | None] = mapped_column(String(256))
    resource_arns: Mapped[list[str]] = mapped_column(JSON, nullable=False)
    event_details: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False)
    is_synthetic: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
