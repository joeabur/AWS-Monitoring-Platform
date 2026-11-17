"""Persist imported point-in-time auditor reports and findings.

Revision ID: 0007_auditor_reports
Revises: 0006_notifications
"""

import sqlalchemy as sa
from alembic import op

revision = "0007_auditor_reports"
down_revision = "0006_notifications"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "auditor_reports",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("fingerprint", sa.String(length=64), nullable=False),
        sa.Column("account_id", sa.String(length=64), nullable=False),
        sa.Column("regions", sa.JSON(), nullable=False),
        sa.Column("audit_profile", sa.String(length=128), nullable=False),
        sa.Column("tool_name", sa.String(length=128), nullable=False),
        sa.Column("tool_version", sa.String(length=64), nullable=False),
        sa.Column("catalog_version", sa.String(length=64), nullable=False),
        sa.Column("generated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("finding_count", sa.Integer(), nullable=False),
        sa.Column("imported_by", sa.Uuid(), nullable=True),
        sa.Column(
            "imported_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(["imported_by"], ["users.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "uq_auditor_reports_fingerprint",
        "auditor_reports",
        ["fingerprint"],
        unique=True,
    )
    op.create_index(
        "ix_auditor_reports_account_generated",
        "auditor_reports",
        ["account_id", "generated_at"],
    )
    op.create_table(
        "auditor_findings",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("report_id", sa.Uuid(), nullable=False),
        sa.Column("report_generated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("source_finding_id", sa.String(length=128), nullable=False),
        sa.Column("account_id", sa.String(length=64), nullable=False),
        sa.Column("region", sa.String(length=64), nullable=False),
        sa.Column("control_id", sa.String(length=32), nullable=False),
        sa.Column("title", sa.String(length=512), nullable=False),
        sa.Column("resource_id", sa.String(length=2048), nullable=False),
        sa.Column("resource_type", sa.String(length=256), nullable=False),
        sa.Column("severity", sa.String(length=16), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("message", sa.String(length=2048), nullable=False),
        sa.Column("evidence", sa.JSON(), nullable=False),
        sa.Column("sources", sa.JSON(), nullable=False),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("remediation", sa.String(length=4096), nullable=False),
        sa.Column("uncertainty", sa.JSON(), nullable=False),
        sa.Column("suppression", sa.JSON(none_as_null=True), nullable=True),
        sa.ForeignKeyConstraint(["report_id"], ["auditor_reports.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "uq_auditor_findings_report_source_id",
        "auditor_findings",
        ["report_id", "source_finding_id"],
        unique=True,
    )
    op.create_index(
        "ix_auditor_findings_account_resource",
        "auditor_findings",
        ["account_id", "resource_id"],
    )
    op.create_index(
        "ix_auditor_findings_control_status",
        "auditor_findings",
        ["control_id", "status"],
    )


def downgrade() -> None:
    op.drop_index("ix_auditor_findings_control_status", table_name="auditor_findings")
    op.drop_index("ix_auditor_findings_account_resource", table_name="auditor_findings")
    op.drop_index("uq_auditor_findings_report_source_id", table_name="auditor_findings")
    op.drop_table("auditor_findings")
    op.drop_index("ix_auditor_reports_account_generated", table_name="auditor_reports")
    op.drop_index("uq_auditor_reports_fingerprint", table_name="auditor_reports")
    op.drop_table("auditor_reports")
