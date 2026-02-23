"""Health Service – generates daily health reports on all components."""

from __future__ import annotations

import logging
from datetime import datetime, timedelta

import redis.asyncio as aioredis
from sqlalchemy import select, func, and_
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.models.cve import CVE
from app.models.filter_rule import FilterRule
from app.models.alert_log import AlertLog
from app.models.health_report import HealthReport

logger = logging.getLogger(__name__)


async def check_component_health() -> dict:
    """Check the health of all platform components.

    Returns:
        dict with component name → status ("ok" or error message)
    """
    status = {}

    # Database
    try:
        from app.database import async_session
        async with async_session() as session:
            await session.execute(select(func.count()).select_from(CVE))
        status["database"] = "ok"
    except Exception as e:
        status["database"] = f"error: {str(e)[:100]}"

    # Redis
    try:
        r = aioredis.from_url(settings.redis_url, decode_responses=True)
        await r.ping()
        await r.aclose()
        status["redis"] = "ok"
    except Exception as e:
        status["redis"] = f"error: {str(e)[:100]}"

    # SMTP (check config, don't actually send)
    if settings.smtp_host and settings.smtp_user:
        status["smtp"] = "configured"
    else:
        status["smtp"] = "not_configured"

    # NVD API Key
    if settings.nvd_api_key:
        status["nvd_api"] = "key_configured"
    else:
        status["nvd_api"] = "keyless_mode"

    return status


async def generate_daily_report(session: AsyncSession) -> dict:
    """Generate the daily health report data."""
    today_start = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)

    # Component health
    components = await check_component_health()

    # Today's alert stats
    new_alerted_result = await session.execute(
        select(func.count()).select_from(AlertLog).where(
            AlertLog.sent_at >= today_start,
            AlertLog.status == "sent",
        )
    )
    new_alerted = new_alerted_result.scalar() or 0

    # CVEs seen today but already existed
    existing_seen_result = await session.execute(
        select(func.count()).select_from(CVE).where(
            CVE.last_seen >= today_start,
            CVE.first_seen < today_start,
        )
    )
    existing_seen = existing_seen_result.scalar() or 0

    # Total CVEs in DB
    total_result = await session.execute(
        select(func.count()).select_from(CVE)
    )
    total_cves = total_result.scalar() or 0

    # Active filters
    filters_result = await session.execute(
        select(func.count()).select_from(FilterRule).where(FilterRule.enabled == True)
    )
    active_filters = filters_result.scalar() or 0

    # Recent errors (from alert_logs)
    errors_result = await session.execute(
        select(AlertLog).where(
            AlertLog.sent_at >= today_start,
            AlertLog.status == "failed",
        ).limit(10)
    )
    errors = [
        {"cve_id": a.cve_id, "error": a.error_message}
        for a in errors_result.scalars().all()
    ]

    report_data = {
        "report_date": datetime.utcnow().isoformat(),
        "components_status": components,
        "new_cves_alerted": new_alerted,
        "existing_cves_seen": existing_seen,
        "total_cves_in_db": total_cves,
        "active_filters": active_filters,
        "errors": errors,
        "warnings": [],
    }

    # Save report to DB
    report = HealthReport(
        report_date=datetime.utcnow(),
        components_status=components,
        new_cves_alerted=new_alerted,
        existing_cves_seen=existing_seen,
        total_cves_in_db=total_cves,
        active_filters=active_filters,
        errors=errors,
    )
    session.add(report)
    await session.flush()

    report_data["id"] = report.id
    return report_data
