"""Sync helper to write structured worker logs to the WorkerLog DB table.

Celery tasks run in a synchronous context so we use a plain synchronous
SQLAlchemy session (psycopg2 / sync driver) instead of asyncpg.
"""

from __future__ import annotations

import logging
import traceback
from datetime import datetime
from typing import Optional

logger = logging.getLogger(__name__)


def write_log(
    worker_type: str,
    message: str,
    level: str = "INFO",
    task_id: Optional[str] = None,
    details: Optional[str] = None,
) -> None:
    """Insert a WorkerLog row synchronously. Silently swallows DB errors so
    that logging never crashes the actual task."""
    try:
        from sqlalchemy import create_engine, text
        from sqlalchemy.orm import sessionmaker
        from app.config import settings
        from app.models.worker_log import WorkerLog

        sync_url = settings.sync_database_url
        engine = create_engine(sync_url, pool_pre_ping=True)
        Session = sessionmaker(bind=engine)

        with Session() as session:
            log_entry = WorkerLog(
                worker_type=worker_type,
                level=level.upper(),
                message=message,
                timestamp=datetime.utcnow(),
                task_id=task_id,
                details=details,
            )
            session.add(log_entry)
            session.commit()

        engine.dispose()
    except Exception as exc:
        logger.warning(f"[worker_log_writer] Failed to write log: {exc}")
