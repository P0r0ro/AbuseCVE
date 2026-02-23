"""CVE scanning Celery tasks."""

from __future__ import annotations

import asyncio
import logging

from app.tasks.celery_app import celery_app
from app.config import settings

logger = logging.getLogger(__name__)


def _run_async(coro):
    """Run an async coroutine from sync Celery task."""
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


@celery_app.task(
    bind=True,
    name="app.tasks.cve_tasks.run_cve_scan",
    max_retries=3,
    default_retry_delay=60,
    acks_late=True,
)
def run_cve_scan(self):
    """Scheduled task: Run the full CVE pipeline cycle.

    1. Fetch CVEs from NVD and CISA KEV
    2. Push to Redis pool
    3. Apply filter rules
    4. Dedup against database
    5. Send alerts for new CVEs
    """
    logger.info("🔍 Starting CVE scan cycle...")

    async def _scan():
        from app.engine.pipeline import CVEPipeline
        from app.database import async_session
        from app.services.smtp_service import send_cve_alert
        from app.models.alert_log import AlertLog
        from datetime import datetime

        pipeline = CVEPipeline()

        async with async_session() as session:
            try:
                result = await pipeline.run_full_cycle(session)

                new_cves = result.get("new_cves", [])
                logger.info(f"Pipeline result: {len(new_cves)} new CVEs to alert")

                # Send alerts for new CVEs
                for cve_data in new_cves:
                    cve_dict = {
                        "cve_id": cve_data.cve_id,
                        "vendor": cve_data.vendor,
                        "product": cve_data.product,
                        "description": cve_data.description,
                        "severity": cve_data.severity,
                        "cvss_score": cve_data.cvss_score,
                        "source": cve_data.source,
                        "published_date": cve_data.published_date.isoformat() if cve_data.published_date else None,
                        "kev_flag": cve_data.kev_flag,
                    }

                    email_result = await send_cve_alert(cve_dict)

                    # Log the alert
                    alert_log = AlertLog(
                        cve_id=cve_data.cve_id,
                        sent_at=datetime.utcnow(),
                        recipient=settings.alert_recipients,
                        status=email_result.get("status", "unknown"),
                        error_message=email_result.get("error"),
                    )
                    session.add(alert_log)

                    # Mark CVE as alerted
                    from sqlalchemy import update as sql_update
                    from app.models.cve import CVE
                    await session.execute(
                        sql_update(CVE)
                        .where(CVE.cve_id == cve_data.cve_id)
                        .values(alert_sent=True)
                    )

                await session.commit()

                return {
                    "total_fetched": result.get("total_fetched", 0),
                    "filtered": result.get("filtered_count", 0),
                    "new_alerted": len(new_cves),
                    "existing": result.get("existing_count", 0),
                }

            except Exception as e:
                logger.error(f"CVE scan failed: {e}", exc_info=True)
                await session.rollback()
                raise

    try:
        result = _run_async(_scan())
        logger.info(f"✅ CVE scan complete: {result}")
        return result
    except Exception as exc:
        logger.error(f"❌ CVE scan failed, retrying: {exc}")
        raise self.retry(exc=exc)
