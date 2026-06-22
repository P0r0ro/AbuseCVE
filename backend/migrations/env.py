"""Alembic environment — async-engine variant for AbuseCVE.

Notes
-----
* Reads the database URL from ``app.config.settings`` so we keep a single
  source of truth instead of duplicating it in ``alembic.ini``.
* Uses the sync URL (``postgresql://``) for migrations even though the
  app itself runs on ``asyncpg``. Alembic's online mode requires a sync
  driver to acquire a real DB-API connection; psycopg2-binary is pulled
  in via ``requirements.txt``.
* The first migration (``0001_baseline``) is intentionally empty — the
  existing schema is bootstrapped by ``app.database.init_db()`` for
  backwards compatibility with pre-Alembic deployments. New tables and
  columns are introduced by subsequent migrations.
"""

from __future__ import annotations

import os
import sys
from logging.config import fileConfig

from alembic import context
from sqlalchemy import engine_from_config, pool

# Make the application package importable.
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__) + "/.."))

from app.config import settings  # noqa: E402
from app.database import Base    # noqa: E402

# Import every model module so SQLAlchemy registers its tables on Base.metadata
# *before* Alembic introspects target_metadata for autogenerate.
from app.models import (  # noqa: E402,F401
    alert_log,
    audit_log,
    cve,
    filter_rule,
    health_report,
    integration,
    knowledge_article,
    user,
    vendor_product,
    worker_log,
)

config = context.config
config.set_main_option("sqlalchemy.url", settings.sync_database_url)

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata


def run_migrations_offline() -> None:
    context.configure(
        url=settings.sync_database_url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            compare_type=True,
        )
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
