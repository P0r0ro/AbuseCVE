"""users table + seed admin and legacy soc rows.

Revision ID: 0002_users
Revises: 0001_baseline
Create Date: 2026-05-12

The ``admin`` row is seeded with a bcrypt hash of
``ABUSECVE_ADMIN_PASSWORD`` (defaults to ``changeme`` for local dev,
matching the pre-DB behaviour). The ``soc`` row is seeded as a
passwordless legacy account — login for that username keeps working
without a password until admins migrate analysts onto named accounts
and disable the legacy entry from the Users page.
"""

from __future__ import annotations

import os
from datetime import datetime
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from passlib.context import CryptContext

revision: str = "0002_users"
down_revision: Union[str, None] = "0001_baseline"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_LEGACY_SOC_HASH_MARKER = "!"  # never matches any bcrypt verify call


def upgrade() -> None:
    op.create_table(
        "users",
        sa.Column("id",            sa.Integer,     primary_key=True, autoincrement=True),
        sa.Column("username",      sa.String(64),  nullable=False, unique=True),
        sa.Column("full_name",     sa.String(120), nullable=False),
        sa.Column("password_hash", sa.String(255), nullable=False),
        sa.Column("role",          sa.String(16),  nullable=False, server_default="SOC"),
        sa.Column("is_active",     sa.Boolean,     nullable=False, server_default=sa.true()),
        sa.Column("created_at",    sa.DateTime,    nullable=False, server_default=sa.func.now()),
        sa.Column("last_login_at", sa.DateTime,    nullable=True),
    )
    op.create_index("ix_users_username", "users", ["username"], unique=True)

    # ── Seed rows ─────────────────────────────────
    pwd_ctx = CryptContext(schemes=["bcrypt"], deprecated="auto")
    admin_pw_raw = os.environ.get("ABUSECVE_ADMIN_PASSWORD", "changeme")
    # bcrypt has a 72-byte hard limit; truncate without splitting a
    # multibyte char. Matches app.services.password._truncate_for_bcrypt
    # so runtime verification accepts the same input.
    admin_pw_bytes = admin_pw_raw.encode("utf-8")[:72]
    while admin_pw_bytes:
        try:
            admin_pw = admin_pw_bytes.decode("utf-8")
            break
        except UnicodeDecodeError:
            admin_pw_bytes = admin_pw_bytes[:-1]
    else:
        admin_pw = "changeme"
    admin_hash = pwd_ctx.hash(admin_pw)

    users = sa.table(
        "users",
        sa.column("username",      sa.String),
        sa.column("full_name",     sa.String),
        sa.column("password_hash", sa.String),
        sa.column("role",          sa.String),
        sa.column("is_active",     sa.Boolean),
        sa.column("created_at",    sa.DateTime),
    )

    op.execute(
        users.insert().values(
            username="admin",
            full_name="Administrator",
            password_hash=admin_hash,
            role="ADMIN",
            is_active=True,
            created_at=datetime.utcnow(),
        )
    )
    op.execute(
        users.insert().values(
            username="soc",
            full_name="SOC (legacy shared account)",
            password_hash=_LEGACY_SOC_HASH_MARKER,
            role="SOC",
            is_active=True,
            created_at=datetime.utcnow(),
        )
    )


def downgrade() -> None:
    op.drop_index("ix_users_username", table_name="users")
    op.drop_table("users")
