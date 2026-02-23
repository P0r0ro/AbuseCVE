"""Health report Celery tasks."""

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
    name="app.tasks.health_tasks.generate_and_send_health_report",
    max_retries=2,
    default_retry_delay=300,
)
def generate_and_send_health_report(self):
    """Generate and send the daily health report."""
    logger.info("📊 Generating daily health report...")

    async def _generate():
        from app.database import async_session
        from app.services.health_service import generate_daily_report
        from app.services.smtp_service import send_health_report
        from app.models.health_report import HealthReport
        from datetime import datetime

        async with async_session() as session:
            try:
                report_data = await generate_daily_report(session)
                email_result = await send_health_report(report_data)

                # Update report with sent status
                from sqlalchemy import update as sql_update
                if report_data.get("id"):
                    await session.execute(
                        sql_update(HealthReport)
                        .where(HealthReport.id == report_data["id"])
                        .values(
                            sent=email_result.get("status") == "sent",
                            sent_at=datetime.utcnow(),
                        )
                    )

                await session.commit()

                logger.info(f"Health report generated and {'sent' if email_result.get('status') == 'sent' else 'failed to send'}")
                return report_data
            except Exception as e:
                logger.error(f"Health report generation failed: {e}", exc_info=True)
                await session.rollback()
                raise

    try:
        result = _run_async(_generate())
        return result
    except Exception as exc:
        logger.error(f"Health report task failed: {exc}")
        raise self.retry(exc=exc)
