"""Persist analyst-approved, audited response playbooks.

Revision ID: 0008_response_actions
Revises: 0007_auditor_reports
"""

import sqlalchemy as sa
from alembic import op

revision = "0008_response_actions"
down_revision = "0007_auditor_reports"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "response_actions",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("incident_id", sa.Uuid(), nullable=False),
        sa.Column("action_type", sa.String(length=64), nullable=False),
        sa.Column("account_id", sa.String(length=12), nullable=False),
        sa.Column("region", sa.String(length=64), nullable=False),
        sa.Column("target_principal_arn", sa.String(length=2048), nullable=True),
        sa.Column("target_user_name", sa.String(length=128), nullable=False),
        sa.Column("target_access_key_id", sa.String(length=128), nullable=False),
        sa.Column("reason", sa.String(length=4000), nullable=False),
        sa.Column("status", sa.String(length=24), nullable=False),
        sa.Column("dry_run", sa.Boolean(), nullable=False),
        sa.Column("requested_by", sa.Uuid(), nullable=False),
        sa.Column("approved_by", sa.Uuid(), nullable=True),
        sa.Column("executed_by", sa.Uuid(), nullable=True),
        sa.Column("result", sa.JSON(none_as_null=True), nullable=True),
        sa.Column("error_code", sa.String(length=128), nullable=True),
        sa.Column("approved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("executed_at", sa.DateTime(timezone=True), nullable=True),
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
            "action_type IN ('disable_access_key')",
            name="ck_response_actions_type",
        ),
        sa.CheckConstraint(
            "status IN ('pending_approval', 'approved', 'rejected', 'dry_run', 'executed', 'failed')",
            name="ck_response_actions_status",
        ),
        sa.ForeignKeyConstraint(["incident_id"], ["incidents.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["requested_by"], ["users.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["approved_by"], ["users.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["executed_by"], ["users.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_response_actions_incident_created",
        "response_actions",
        ["incident_id", "created_at"],
    )
    op.create_index(
        "ix_response_actions_account_status",
        "response_actions",
        ["account_id", "status"],
    )
    op.create_table(
        "response_action_audit_entries",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("response_action_id", sa.Uuid(), nullable=False),
        sa.Column("actor_id", sa.Uuid(), nullable=True),
        sa.Column("action", sa.String(length=64), nullable=False),
        sa.Column("details", sa.JSON(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["response_action_id"], ["response_actions.id"], ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(["actor_id"], ["users.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_response_action_audit_action_time",
        "response_action_audit_entries",
        ["response_action_id", "created_at"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_response_action_audit_action_time",
        table_name="response_action_audit_entries",
    )
    op.drop_table("response_action_audit_entries")
    op.drop_index("ix_response_actions_account_status", table_name="response_actions")
    op.drop_index("ix_response_actions_incident_created", table_name="response_actions")
    op.drop_table("response_actions")
