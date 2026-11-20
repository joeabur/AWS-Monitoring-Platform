"""Track audit entries archived to immutable object storage.

Revision ID: 0011_audit_entry_archive_markers
Revises: 0010_audit_export_state
"""

import sqlalchemy as sa
from alembic import op

revision = "0011_audit_entry_archive_markers"
down_revision = "0010_audit_export_state"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "incident_audit_entries",
        sa.Column("archived_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column(
        "response_action_audit_entries",
        sa.Column("archived_at", sa.DateTime(timezone=True), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("response_action_audit_entries", "archived_at")
    op.drop_column("incident_audit_entries", "archived_at")
