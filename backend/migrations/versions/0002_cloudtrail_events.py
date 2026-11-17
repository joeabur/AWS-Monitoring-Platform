"""Persist normalized CloudTrail events.

Revision ID: 0002_cloudtrail_events
Revises: 0001_users
"""

import sqlalchemy as sa
from alembic import op

revision = "0002_cloudtrail_events"
down_revision = "0001_users"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "cloudtrail_events",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("event_key", sa.String(length=64), nullable=False),
        sa.Column("cloudtrail_event_id", sa.String(length=256), nullable=False),
        sa.Column("account_id", sa.String(length=12), nullable=False),
        sa.Column("region", sa.String(length=64), nullable=False),
        sa.Column("event_source", sa.String(length=255), nullable=False),
        sa.Column("event_name", sa.String(length=255), nullable=False),
        sa.Column("event_time", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "ingested_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column("source_ip", sa.String(length=128), nullable=True),
        sa.Column("principal_type", sa.String(length=64), nullable=True),
        sa.Column("principal_id", sa.String(length=2048), nullable=True),
        sa.Column("principal_arn", sa.String(length=2048), nullable=True),
        sa.Column("user_agent", sa.String(length=1024), nullable=True),
        sa.Column("error_code", sa.String(length=256), nullable=True),
        sa.Column("resource_arns", sa.JSON(), nullable=False),
        sa.Column("event_details", sa.JSON(), nullable=False),
        sa.Column("is_synthetic", sa.Boolean(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("event_key"),
    )
    op.create_index(
        "ix_cloudtrail_account_region_time",
        "cloudtrail_events",
        ["account_id", "region", "event_time"],
    )
    op.create_index(
        "ix_cloudtrail_event_name_time",
        "cloudtrail_events",
        ["event_name", "event_time"],
    )


def downgrade() -> None:
    op.drop_index("ix_cloudtrail_event_name_time", table_name="cloudtrail_events")
    op.drop_index("ix_cloudtrail_account_region_time", table_name="cloudtrail_events")
    op.drop_table("cloudtrail_events")
