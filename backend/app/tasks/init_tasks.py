"""DB initialization Celery tasks – bulk import ALL past CVEs."""

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
    max_retries=0,
    soft_time_limit=14400,   # 4 hour soft limit
    time_limit=28800,        # 8 hour hard limit
)
def initialize_database(self):
    """Bulk-import ALL past CVEs from all sources into the database.

    Downloads from NVD, MITRE CVEListV5, CISA KEV, and RedHat.
    This can take a long time, so has extended time limits.
    """
    logger.info("🗄️ Starting DB initialization (full mirror from all sources)")

    async def _init():
        from app.engine.pipeline import CVEPipeline
        from app.database import async_session

        pipeline = CVEPipeline()

        async with async_session() as session:
            try:
                result = await pipeline.initialize_db(session)
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
        raise


@celery_app.task(
    bind=True,
    name="app.tasks.init_tasks.initialize_database_local",
    max_retries=1,
    soft_time_limit=7200,
    time_limit=14400,
)
def initialize_database_local(self, mitre_dir: str = None, nvd_dir: str = None):
    """Bulk-import CVEs from locally downloaded data directories.

    Steps:
    1. MITRE: git clone https://github.com/CVEProject/cvelistV5.git
       Pass the path to the `cves/` subdirectory.
    2. NVD: Download JSON feeds (optional)
    3. CISA KEV + RedHat: Always fetched from API (small/fast)
    """
    logger.info(f"🗄️ Starting DB init from local dirs: mitre={mitre_dir}, nvd={nvd_dir}")

    async def _init():
        from app.engine.pipeline import CVEPipeline
        from app.database import async_session

        pipeline = CVEPipeline()

        async with async_session() as session:
            try:
                result = await pipeline.initialize_db_from_directory(
                    session, mitre_dir=mitre_dir, nvd_dir=nvd_dir
                )
                logger.info(f"DB Init local result: {result}")
                return result
            except Exception as e:
                logger.error(
                    f"Local DB init failed: {type(e).__name__}: {e}\n"
                    f"Traceback: {traceback.format_exc()}"
                )
                await session.rollback()
                raise

    try:
        result = _run_async(_init())
        logger.info(f"✅ Local DB init complete: {result}")
        return result
    except Exception as exc:
        logger.error(f"❌ Local DB init failed: {exc}")
        raise self.retry(exc=exc)


@celery_app.task(
    bind=True,
    name="app.tasks.init_tasks.initialize_database_upload",
    max_retries=1,
    acks_late=True,
)
def initialize_database_upload(self, file_path: str):
    """Process uploaded MITRE CVE data file (ZIP).

    Called after user uploads a MITRE cvelistV5 ZIP through the UI.
    """
    logger.info(f"📤 Starting MITRE upload processing: {file_path}")

    async def _upload():
        from app.engine.pipeline import CVEPipeline
        from app.database import async_session

        pipeline = CVEPipeline()

        async with async_session() as session:
            try:
                result = await pipeline.initialize_db_from_upload(session, file_path)
                return result
            except Exception as e:
                logger.error(
                    f"Upload processing failed: {type(e).__name__}: {e}\n"
                    f"Traceback: {traceback.format_exc()}"
                )
                await session.rollback()
                raise
            finally:
                # Clean up temp file
                import os
                try:
                    if os.path.exists(file_path):
                        os.unlink(file_path)
                except Exception:
                    pass

    try:
        result = _run_async(_upload())
        logger.info(f"✅ MITRE upload complete: {result}")
        return result
    except Exception as exc:
        logger.error(f"❌ MITRE upload failed: {exc}")
        raise self.retry(exc=exc)
