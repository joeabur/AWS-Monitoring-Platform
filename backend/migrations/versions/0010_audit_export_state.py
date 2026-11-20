"""Track immutable audit export progress.

Revision ID: 0010_audit_export_state
Revises: 0009_cognito_identity
"""

import sqlalchemy as sa
from alembic import op

revision = "0010_audit_export_state"
down_revision = "0009_cognito_identity"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "audit_export_state",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("last_exported_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    op.bulk_insert(
        sa.table(
            "audit_export_state",
            sa.column("id", sa.Integer()),
            sa.column("last_exported_at", sa.DateTime(timezone=True)),
        ),
        [{"id": 1, "last_exported_at": None}],
    )


def downgrade() -> None:
    op.drop_table("audit_export_state")
