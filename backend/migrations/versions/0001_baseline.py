"""Baseline — no-op marker for the pre-Alembic schema.

Revision ID: 0001_baseline
Revises:
Create Date: 2026-05-12

Existing AbuseCVE deployments already have the full legacy schema (CVE,
filter_rules, alert_logs, knowledge_articles, integrations, vendors,
products, …) created by ``app.database.init_db`` on first boot. Treating
that as the Alembic starting point keeps this migration zero-risk: it
applies cleanly to both fresh installs (init_db runs *after* Alembic and
its CREATE TABLEs become no-ops thanks to ``checkfirst=True``) and to
existing installs (this revision is recorded without touching any data).

All schema changes from this point on are introduced via new
revisions — see 0002_users, 0003_alert_log_close_fields, 0004_audit_log.
"""

from __future__ import annotations

from typing import Sequence, Union

revision: str = "0001_baseline"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    pass


def downgrade() -> None:
    pass
