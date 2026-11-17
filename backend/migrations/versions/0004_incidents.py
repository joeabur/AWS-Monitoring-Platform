"""Create incident management records.

Revision ID: 0004_incidents
Revises: 0003_detection_alerts
"""

import sqlalchemy as sa
from alembic import op

revision = "0004_incidents"
down_revision = "0003_detection_alerts"
branch_labels = None
depends_on = None

_ACTIVE_INCIDENT = sa.text("status NOT IN ('resolved', 'false_positive')")


def upgrade() -> None:
    op.create_table(
        "incidents",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("correlation_key", sa.String(length=64), nullable=False),
        sa.Column("correlation_group", sa.String(length=64), nullable=False),
        sa.Column("title", sa.String(length=255), nullable=False),
        sa.Column("description", sa.String(length=2048), nullable=False),
        sa.Column("status", sa.String(length=24), nullable=False),
        sa.Column("severity", sa.String(length=16), nullable=False),
        sa.Column("risk_score", sa.Integer(), nullable=False),
        sa.Column("score_basis", sa.String(length=512), nullable=False),
        sa.Column("account_id", sa.String(length=12), nullable=False),
        sa.Column("region", sa.String(length=64), nullable=False),
        sa.Column("principal_id", sa.String(length=2048), nullable=True),
        sa.Column("principal_arn", sa.String(length=2048), nullable=True),
        sa.Column("source_ip", sa.String(length=128), nullable=True),
        sa.Column("resource_arns", sa.JSON(), nullable=False),
        sa.Column("assigned_to", sa.Uuid(), nullable=True),
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
        sa.ForeignKeyConstraint(["assigned_to"], ["users.id"], ondelete="SET NULL"),
        sa.CheckConstraint(
            "status IN ('new', 'acknowledged', 'investigating', 'contained', 'resolved', 'false_positive')",
            name="ck_incidents_status",
        ),
        sa.CheckConstraint(
            "severity IN ('critical', 'high', 'medium', 'low', 'informational')",
            name="ck_incidents_severity",
        ),
        sa.CheckConstraint("risk_score BETWEEN 0 AND 100", name="ck_incidents_risk_score"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "uq_incidents_active_correlation",
        "incidents",
        ["correlation_key"],
        unique=True,
        sqlite_where=_ACTIVE_INCIDENT,
        postgresql_where=_ACTIVE_INCIDENT,
    )
    op.create_index("ix_incidents_correlation_group", "incidents", ["correlation_group"])
    op.create_index("ix_incidents_account_status", "incidents", ["account_id", "status"])
    op.create_index("ix_incidents_severity_updated", "incidents", ["severity", "updated_at"])
    op.create_index("ix_incidents_assigned_to", "incidents", ["assigned_to"])

    op.create_table(
        "incident_alerts",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("incident_id", sa.Uuid(), nullable=False),
        sa.Column("alert_id", sa.Uuid(), nullable=False),
        sa.Column(
            "linked_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(["alert_id"], ["detection_alerts.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["incident_id"], ["incidents.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("incident_id", "alert_id", name="uq_incident_alert_pair"),
    )
    op.create_index("ix_incident_alerts_incident_id", "incident_alerts", ["incident_id"])

    op.create_table(
        "investigation_notes",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("incident_id", sa.Uuid(), nullable=False),
        sa.Column("author_id", sa.Uuid(), nullable=True),
        sa.Column("body", sa.String(length=4000), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(["author_id"], ["users.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["incident_id"], ["incidents.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_investigation_notes_incident_time",
        "investigation_notes",
        ["incident_id", "created_at"],
    )

    op.create_table(
        "incident_audit_entries",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("incident_id", sa.Uuid(), nullable=False),
        sa.Column("actor_id", sa.Uuid(), nullable=True),
        sa.Column("action", sa.String(length=64), nullable=False),
        sa.Column("previous_value", sa.String(length=512), nullable=True),
        sa.Column("new_value", sa.String(length=512), nullable=True),
        sa.Column("details", sa.JSON(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(["actor_id"], ["users.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["incident_id"], ["incidents.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_incident_audit_incident_time",
        "incident_audit_entries",
        ["incident_id", "created_at"],
    )


def downgrade() -> None:
    op.drop_index("ix_incident_audit_incident_time", table_name="incident_audit_entries")
    op.drop_table("incident_audit_entries")
    op.drop_index("ix_investigation_notes_incident_time", table_name="investigation_notes")
    op.drop_table("investigation_notes")
    op.drop_index("ix_incident_alerts_incident_id", table_name="incident_alerts")
    op.drop_table("incident_alerts")
    op.drop_index("ix_incidents_assigned_to", table_name="incidents")
    op.drop_index("ix_incidents_severity_updated", table_name="incidents")
    op.drop_index("ix_incidents_account_status", table_name="incidents")
    op.drop_index("ix_incidents_correlation_group", table_name="incidents")
    op.drop_index("uq_incidents_active_correlation", table_name="incidents")
    op.drop_table("incidents")
