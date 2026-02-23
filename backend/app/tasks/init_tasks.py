"""DB initialization Celery tasks – bulk import past CVEs."""

from __future__ import annotations

import asyncio
import logging

from app.tasks.celery_app import celery_app

logger = logging.getLogger(__name__)


def _run_async(coro):
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


@celery_app.task(
    bind=True,
    name="app.tasks.init_tasks.initialize_database",
    max_retries=1,
    soft_time_limit=3600,   # 1 hour soft limit
    time_limit=7200,        # 2 hour hard limit
)
def initialize_database(self, vendor_keyword: str = None):
    """Bulk-import past CVEs for a vendor into the database.

    This can take a long time for full NVD mirror, so has extended time limits.
    """
    logger.info(f"🗄️ Starting DB initialization" +
                (f" for vendor: {vendor_keyword}" if vendor_keyword else " (full mirror)"))

    async def _init():
        from app.engine.pipeline import CVEPipeline
        from app.database import async_session

        pipeline = CVEPipeline()

        async with async_session() as session:
            try:
                result = await pipeline.initialize_db(session, vendor_keyword)
                logger.info(f"DB Init result: {result}")
                return result
            except Exception as e:
                logger.error(f"DB Init failed: {e}", exc_info=True)
                await session.rollback()
                raise

    try:
        result = _run_async(_init())
        logger.info(f"✅ DB initialization complete: {result}")
        return result
    except Exception as exc:
        logger.error(f"❌ DB initialization failed: {exc}")
        raise self.retry(exc=exc)
