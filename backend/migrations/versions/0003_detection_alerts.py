"""Persist detection alerts.

Revision ID: 0003_detection_alerts
Revises: 0002_cloudtrail_events
"""

import sqlalchemy as sa
from alembic import op

revision = "0003_detection_alerts"
down_revision = "0002_cloudtrail_events"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "detection_alerts",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("dedup_key", sa.String(length=64), nullable=False),
        sa.Column("rule_id", sa.String(length=64), nullable=False),
        sa.Column("rule_version", sa.Integer(), nullable=False),
        sa.Column("title", sa.String(length=255), nullable=False),
        sa.Column("description", sa.String(length=2048), nullable=False),
        sa.Column("severity", sa.String(length=16), nullable=False),
        sa.Column("risk_score", sa.Integer(), nullable=False),
        sa.Column("score_basis", sa.String(length=512), nullable=False),
        sa.Column("account_id", sa.String(length=12), nullable=False),
        sa.Column("region", sa.String(length=64), nullable=False),
        sa.Column("principal_id", sa.String(length=2048), nullable=True),
        sa.Column("principal_arn", sa.String(length=2048), nullable=True),
        sa.Column("source_ip", sa.String(length=128), nullable=True),
        sa.Column("resource_arns", sa.JSON(), nullable=False),
        sa.Column("event_refs", sa.JSON(), nullable=False),
        sa.Column("observed_count", sa.Integer(), nullable=False),
        sa.Column("mitre_technique_id", sa.String(length=32), nullable=True),
        sa.Column("mitre_technique_name", sa.String(length=128), nullable=True),
        sa.Column("investigation_steps", sa.JSON(), nullable=False),
        sa.Column("response_recommendations", sa.JSON(), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("first_observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_observed_at", sa.DateTime(timezone=True), nullable=False),
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
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("dedup_key"),
    )
    op.create_index("ix_detection_alerts_rule_id", "detection_alerts", ["rule_id"])
    op.create_index(
        "ix_detection_alert_account_status", "detection_alerts", ["account_id", "status"]
    )
    op.create_index(
        "ix_detection_alert_severity_time",
        "detection_alerts",
        ["severity", "last_observed_at"],
    )


def downgrade() -> None:
    op.drop_index("ix_detection_alert_severity_time", table_name="detection_alerts")
    op.drop_index("ix_detection_alert_account_status", table_name="detection_alerts")
    op.drop_index("ix_detection_alerts_rule_id", table_name="detection_alerts")
    op.drop_table("detection_alerts")
