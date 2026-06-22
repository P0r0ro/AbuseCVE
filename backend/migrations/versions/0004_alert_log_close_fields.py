"""Add case-close attribution columns to alert_logs.

Revision ID: 0004_alert_log_close_fields
Revises: 0003_audit_log
Create Date: 2026-05-12
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0004_alert_log_close_fields"
down_revision: Union[str, None] = "0003_audit_log"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("alert_logs", sa.Column("closed_by_id",   sa.Integer,     nullable=True))
    op.add_column("alert_logs", sa.Column("closed_by_name", sa.String(120), nullable=True))
    op.add_column("alert_logs", sa.Column("closed_at",      sa.DateTime,    nullable=True))
    op.add_column("alert_logs", sa.Column("close_notes",    sa.Text,        nullable=True))
    op.create_foreign_key(
        "fk_alert_logs_closed_by_id_users",
        source_table="alert_logs",
        referent_table="users",
        local_cols=["closed_by_id"],
        remote_cols=["id"],
        ondelete="SET NULL",
    )


def downgrade() -> None:
    op.drop_constraint("fk_alert_logs_closed_by_id_users", "alert_logs", type_="foreignkey")
    op.drop_column("alert_logs", "close_notes")
    op.drop_column("alert_logs", "closed_at")
    op.drop_column("alert_logs", "closed_by_name")
    op.drop_column("alert_logs", "closed_by_id")
