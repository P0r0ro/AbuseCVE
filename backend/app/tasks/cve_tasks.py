"""CVE scanning Celery tasks."""

from __future__ import annotations

import asyncio
import logging
import traceback

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

    1. Fetch CVEs from all 4 sources (NVD, CISA KEV, MITRE, RedHat)
    2. Push to Redis pool
    3. Apply filter rules
    4. Dedup against database (merge multi-source data)
    5. Send alerts for new matching CVEs
    """
    logger.info("🔍 Starting CVE scan cycle...")

    async def _scan():
        from app.engine.pipeline import CVEPipeline
        from app.database import async_session
        from app.services.smtp_service import send_cve_alert
        from app.models.alert_log import AlertLog
        from app.models.cve import CVE
        from datetime import datetime

        pipeline = CVEPipeline()

        async with async_session() as session:
            try:
                result = await pipeline.run_full_cycle(session)

                new_cves = result.get("new_cves", [])
                matches = result.get("matches", [])
                logger.info(f"Pipeline result: {len(new_cves)} new CVEs to alert")

                # Build rule name lookup from matches
                rule_names = {}
                for m in matches:
                    rule_names[m["cve_id"]] = m.get("rule_name", "")

                # Send alerts for new CVEs that matched filters
                alerts_sent = 0
                alerts_failed = 0
                for cve_data in new_cves:
                    cve_dict = {
                        "cve_id": cve_data.cve_id,
                        "vendor": cve_data.vendor,
                        "product": cve_data.product,
                        "description": cve_data.description,
                        "severity": cve_data.severity,
                        "cvss_score": cve_data.cvss_score,
                        "source": cve_data.source,
                        "sources": cve_data.sources,
                        "published_date": cve_data.published_date.isoformat() if cve_data.published_date else None,
                        "kev_flag": cve_data.kev_flag,
                        "cvss_scores": cve_data.cvss_scores,
                    }

                    rule_name = rule_names.get(cve_data.cve_id, "")

                    try:
                        email_result = await send_cve_alert(cve_dict, rule_name=rule_name)

                        # Log the alert
                        alert_log = AlertLog(
                            cve_id=cve_data.cve_id,
                            sent_at=datetime.utcnow(),
                            recipient=settings.alert_recipients,
                            status=email_result.get("status", "unknown"),
                            error_message=email_result.get("error"),
                        )
                        session.add(alert_log)

                        if email_result.get("status") == "sent":
                            alerts_sent += 1
                        else:
                            alerts_failed += 1
                            logger.error(
                                f"Alert failed for {cve_data.cve_id}: "
                                f"{email_result.get('error', 'unknown error')}"
                            )

                    except Exception as e:
                        alerts_failed += 1
                        logger.error(
                            f"Alert exception for {cve_data.cve_id}: "
                            f"{type(e).__name__}: {e}\n"
                            f"Traceback: {traceback.format_exc()}"
                        )
                        # Still log the failed alert
                        alert_log = AlertLog(
                            cve_id=cve_data.cve_id,
                            sent_at=datetime.utcnow(),
                            recipient=settings.alert_recipients,
                            status="failed",
                            error_message=f"{type(e).__name__}: {str(e)[:500]}",
                        )
                        session.add(alert_log)

                    # Mark CVE as alerted
                    from sqlalchemy import update as sql_update
                    await session.execute(
                        sql_update(CVE)
                        .where(CVE.cve_id == cve_data.cve_id)
                        .values(alert_sent=True)
                    )

                    # Dispatch to webhook/CRM integrations
                    try:
                        from app.services.webhook_service import dispatch_to_all_integrations
                        await dispatch_to_all_integrations(session, cve_dict, rule_name=rule_name)
                    except Exception as ie:
                        logger.warning(f"Integration dispatch failed for {cve_data.cve_id}: {ie}")

                await session.commit()

                return {
                    "total_fetched": result.get("total_fetched", 0),
                    "filtered": result.get("filtered_count", 0),
                    "new_alerted": alerts_sent,
                    "alerts_failed": alerts_failed,
                    "existing": result.get("existing_count", 0),
                    "total_new_stored": result.get("total_new_stored", 0),
                }

            except Exception as e:
                logger.error(
                    f"CVE scan failed: {type(e).__name__}: {e}\n"
                    f"Traceback: {traceback.format_exc()}"
                )
                await session.rollback()
                raise

    try:
        result = _run_async(_scan())
        logger.info(f"✅ CVE scan complete: {result}")
        return result
    except Exception as exc:
        logger.error(f"❌ CVE scan failed, retrying: {type(exc).__name__}: {exc}")
        raise self.retry(exc=exc)
