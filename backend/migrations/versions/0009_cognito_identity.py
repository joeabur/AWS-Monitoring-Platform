"""Map application users to Cognito identities.

Revision ID: 0009_cognito_identity
Revises: 0008_response_actions
"""

import sqlalchemy as sa
from alembic import op

revision = "0009_cognito_identity"
down_revision = "0008_response_actions"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("users", sa.Column("cognito_sub", sa.String(length=128), nullable=True))
    op.create_index("ix_users_cognito_sub", "users", ["cognito_sub"], unique=True)


def downgrade() -> None:
    op.drop_index("ix_users_cognito_sub", table_name="users")
    op.drop_column("users", "cognito_sub")
