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


class ResponseAction(Base):
    __tablename__ = "response_actions"
    __table_args__ = (
        CheckConstraint(
            "action_type IN ('disable_access_key')",
            name="ck_response_actions_type",
        ),
        CheckConstraint(
            "status IN ('pending_approval', 'approved', 'rejected', 'dry_run', 'executed', 'failed')",
            name="ck_response_actions_status",
        ),
        Index("ix_response_actions_incident_created", "incident_id", "created_at"),
        Index("ix_response_actions_account_status", "account_id", "status"),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    incident_id: Mapped[UUID] = mapped_column(
        Uuid, ForeignKey("incidents.id", ondelete="RESTRICT"), nullable=False
    )
    action_type: Mapped[str] = mapped_column(String(64), nullable=False)
    account_id: Mapped[str] = mapped_column(String(12), nullable=False)
    region: Mapped[str] = mapped_column(String(64), nullable=False)
    target_principal_arn: Mapped[str | None] = mapped_column(String(2048))
    target_user_name: Mapped[str] = mapped_column(String(128), nullable=False)
    target_access_key_id: Mapped[str] = mapped_column(String(128), nullable=False)
    reason: Mapped[str] = mapped_column(String(4000), nullable=False)
    status: Mapped[str] = mapped_column(String(24), default="pending_approval", nullable=False)
    dry_run: Mapped[bool] = mapped_column(default=True, nullable=False)
    requested_by: Mapped[UUID] = mapped_column(
        Uuid, ForeignKey("users.id", ondelete="RESTRICT"), nullable=False
    )
    approved_by: Mapped[UUID | None] = mapped_column(
        Uuid, ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    executed_by: Mapped[UUID | None] = mapped_column(
        Uuid, ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    result: Mapped[dict[str, object] | None] = mapped_column(JSON(none_as_null=True))
    error_code: Mapped[str | None] = mapped_column(String(128))
    approved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    executed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )


class ResponseActionAuditEntry(Base):
    __tablename__ = "response_action_audit_entries"
    __table_args__ = (
        Index("ix_response_action_audit_action_time", "response_action_id", "created_at"),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    response_action_id: Mapped[UUID] = mapped_column(
        Uuid, ForeignKey("response_actions.id", ondelete="CASCADE"), nullable=False
    )
    actor_id: Mapped[UUID | None] = mapped_column(
        Uuid, ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    action: Mapped[str] = mapped_column(String(64), nullable=False)
    details: Mapped[dict[str, str]] = mapped_column(JSON, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
