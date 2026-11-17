"""Persist AWS integration health and normalized findings.

Revision ID: 0005_aws_integrations
Revises: 0004_incidents
"""

import sqlalchemy as sa
from alembic import op

revision = "0005_aws_integrations"
down_revision = "0004_incidents"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "aws_findings",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("provider", sa.String(length=32), nullable=False),
        sa.Column("external_finding_id", sa.String(length=2048), nullable=False),
        sa.Column("account_id", sa.String(length=12), nullable=False),
        sa.Column("region", sa.String(length=64), nullable=False),
        sa.Column("title", sa.String(length=512), nullable=False),
        sa.Column("severity", sa.String(length=16), nullable=True),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("resource_arns", sa.JSON(), nullable=False),
        sa.Column("first_observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("latest_event_id", sa.Uuid(), nullable=True),
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
        sa.ForeignKeyConstraint(
            ["latest_event_id"], ["cloudtrail_events.id"], ondelete="SET NULL"
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "uq_aws_findings_provider_account_region_id",
        "aws_findings",
        ["provider", "account_id", "region", "external_finding_id"],
        unique=True,
    )
    op.create_index(
        "ix_aws_findings_status_updated", "aws_findings", ["status", "last_updated_at"]
    )
    op.create_index(
        "ix_aws_findings_account_provider", "aws_findings", ["account_id", "provider"]
    )

    op.create_table(
        "aws_integration_health",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("account_id", sa.String(length=12), nullable=False),
        sa.Column("integration", sa.String(length=32), nullable=False),
        sa.Column("region", sa.String(length=64), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("last_error_code", sa.String(length=128), nullable=True),
        sa.Column("resource_count", sa.Integer(), nullable=False),
        sa.Column("last_checked_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_success_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.CheckConstraint(
            "status IN ('healthy', 'unhealthy')",
            name="ck_aws_integration_health_status",
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "uq_aws_integration_health_account_integration_region",
        "aws_integration_health",
        ["account_id", "integration", "region"],
        unique=True,
    )
    op.create_index(
        "ix_aws_integration_health_status_checked",
        "aws_integration_health",
        ["status", "last_checked_at"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_aws_integration_health_status_checked", table_name="aws_integration_health"
    )
    op.drop_index(
        "uq_aws_integration_health_account_integration_region",
        table_name="aws_integration_health",
    )
    op.drop_table("aws_integration_health")
    op.drop_index("ix_aws_findings_account_provider", table_name="aws_findings")
    op.drop_index("ix_aws_findings_status_updated", table_name="aws_findings")
    op.drop_index("uq_aws_findings_provider_account_region_id", table_name="aws_findings")
    op.drop_table("aws_findings")
