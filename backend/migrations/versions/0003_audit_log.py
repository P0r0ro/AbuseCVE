"""audit_log table.

Revision ID: 0003_audit_log
Revises: 0002_users
Create Date: 2026-05-12
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0003_audit_log"
down_revision: Union[str, None] = "0002_users"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "audit_log",
        sa.Column("id",          sa.Integer,     primary_key=True, autoincrement=True),
        sa.Column("occurred_at", sa.DateTime,    nullable=False, server_default=sa.func.now()),
        sa.Column("actor_id",    sa.Integer,     sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("actor_name",  sa.String(120), nullable=True),
        sa.Column("action",      sa.String(64),  nullable=False),
        sa.Column("target_type", sa.String(32),  nullable=True),
        sa.Column("target_id",   sa.String(64),  nullable=True),
        sa.Column("metadata",    postgresql.JSONB, nullable=True),
        sa.Column("ip_address",  sa.String(45),  nullable=True),
    )
    op.create_index("ix_audit_log_occurred_at", "audit_log", ["occurred_at"])
    op.create_index("ix_audit_log_action",      "audit_log", ["action"])
    op.create_index("ix_audit_log_actor_id",    "audit_log", ["actor_id"])


def downgrade() -> None:
    op.drop_index("ix_audit_log_actor_id",    table_name="audit_log")
    op.drop_index("ix_audit_log_action",      table_name="audit_log")
    op.drop_index("ix_audit_log_occurred_at", table_name="audit_log")
    op.drop_table("audit_log")
