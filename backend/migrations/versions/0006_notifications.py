"""Persist deduplicated alert notification deliveries.

Revision ID: 0006_notifications
Revises: 0005_aws_integrations
"""

import sqlalchemy as sa
from alembic import op

revision = "0006_notifications"
down_revision = "0005_aws_integrations"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "notification_deliveries",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("alert_id", sa.Uuid(), nullable=False),
        sa.Column("incident_id", sa.Uuid(), nullable=False),
        sa.Column("channel", sa.String(length=16), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("attempt_count", sa.Integer(), nullable=False),
        sa.Column("next_attempt_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_attempt_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("delivered_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_error_code", sa.String(length=128), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.CheckConstraint(
            "channel IN ('slack', 'teams', 'email')",
            name="ck_notification_deliveries_channel",
        ),
        sa.CheckConstraint(
            "status IN ('pending', 'retrying', 'delivered', 'failed')",
            name="ck_notification_deliveries_status",
        ),
        sa.ForeignKeyConstraint(
            ["alert_id"], ["detection_alerts.id"], ondelete="RESTRICT"
        ),
        sa.ForeignKeyConstraint(["incident_id"], ["incidents.id"], ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "uq_notification_deliveries_alert_channel",
        "notification_deliveries",
        ["alert_id", "channel"],
        unique=True,
    )
    op.create_index(
        "ix_notification_deliveries_due",
        "notification_deliveries",
        ["status", "next_attempt_at"],
    )
    op.create_index(
        "ix_notification_deliveries_created",
        "notification_deliveries",
        ["created_at"],
    )


def downgrade() -> None:
    op.drop_index("ix_notification_deliveries_created", table_name="notification_deliveries")
    op.drop_index("ix_notification_deliveries_due", table_name="notification_deliveries")
    op.drop_index(
        "uq_notification_deliveries_alert_channel", table_name="notification_deliveries"
    )
    op.drop_table("notification_deliveries")
