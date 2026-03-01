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
    """Check the health of all platform components."""
    status = {}

    # Database
    try:
        from app.database import async_session
        async with async_session() as session:
            total = (await session.execute(select(func.count()).select_from(CVE))).scalar() or 0
        status["database"] = f"ok ({total:,} CVEs)"
    except Exception as e:
        status["database"] = f"error: {str(e)[:100]}"

    # Redis — connectivity + data health
    try:
        r = aioredis.from_url(settings.redis_url, decode_responses=True)
        await r.ping()

        mem_info = await r.info("memory")
        used_mem = mem_info.get("used_memory_human", "?")

        # Count total keys
        total_keys = await r.dbsize()

        # Count CVE keys
        cve_key_count = 0
        celery_queue_len = 0
        cursor = 0
        cve_sample_keys = []
        while True:
            cursor, keys = await r.scan(cursor, match="cve:*", count=500)
            cve_key_count += len(keys)
            cve_sample_keys.extend(keys[:5])
            if cursor == 0:
                break

        # Celery default queue length
        try:
            celery_queue_len = await r.llen("celery")
        except Exception:
            celery_queue_len = 0

        await r.aclose()

        if total_keys == 0:
            status["redis"] = f"ok but empty (no keys) — memory: {used_mem}"
        elif cve_key_count > 0:
            status["redis"] = f"ok — {total_keys:,} total keys, {cve_key_count} CVE keys, memory: {used_mem}"
        else:
            status["redis"] = f"ok — {total_keys:,} total keys (no cve: keys yet), memory: {used_mem}"

        status["redis_details"] = {
            "total_keys": total_keys,
            "cve_keys": cve_key_count,
            "celery_queue_length": celery_queue_len,
            "used_memory": used_mem,
        }
    except Exception as e:
        status["redis"] = f"error: {str(e)[:100]}"
        status["redis_details"] = {}

    # SMTP
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


async def _test_filters_against_db(session: AsyncSession) -> list:
    """Run all enabled filters against a sample of recent DB CVEs, return per-filter stats."""
    from app.engine.filter_engine import match_cve_against_rule
    from app.engine.sources.base import NormalizedCVE

    # Load enabled filters
    filters_result = await session.execute(
        select(FilterRule).where(FilterRule.enabled == True)
    )
    rules = filters_result.scalars().all()
    if not rules:
        return []

    # Sample recent 5000 CVEs for the health check (fast, not full scan)
    SAMPLE_SIZE = 5000
    cve_result = await session.execute(
        select(CVE).order_by(CVE.published_date.desc()).limit(SAMPLE_SIZE)
    )
    db_cves = cve_result.scalars().all()

    if not db_cves:
        return [{"id": r.id, "name": r.name, "matches": 0, "sample_size": 0, "status": "no_data"} for r in rules]

    # Convert to NormalizedCVE once
    cves = []
    for c in db_cves:
        cves.append(NormalizedCVE(
            cve_id=c.cve_id, vendor=c.vendor, product=c.product,
            description=c.description, severity=c.severity,
            cvss_score=c.cvss_score, cvss_vector=c.cvss_vector,
            source=c.source, sources=c.sources or [],
            published_date=c.published_date, modified_date=c.modified_date,
            kev_flag=c.kev_flag, cpe_names=c.cpe_names or [],
            references=c.references or [], weaknesses=c.weaknesses or [],
            affected_products=c.affected_products or [],
        ))

    filter_stats = []
    for rule in rules:
        rule_dict = {
            "id": rule.id, "name": rule.name, "enabled": True,
            "vendor": rule.vendor, "products": rule.products or [],
            "min_cvss": rule.min_cvss, "max_cvss": rule.max_cvss,
            "severity_filter": rule.severity_filter or [],
            "keywords_include": rule.keywords_include or [],
            "keywords_exclude": rule.keywords_exclude or [],
            "cpe_vendor": rule.cpe_vendor,
            "alert_on_modified": rule.alert_on_modified,
            "conditions": rule.conditions,
            "pql_query": getattr(rule, 'pql_query', None),
            "severity_mapping": getattr(rule, 'severity_mapping', None),
            "include_unknown": getattr(rule, 'include_unknown', False),
        }
        match_count = sum(1 for cve in cves if match_cve_against_rule(cve, rule_dict))
        filter_stats.append({
            "id": rule.id,
            "name": rule.name,
            "matches": match_count,
            "sample_size": len(cves),
            "match_rate": round(match_count / len(cves) * 100, 2) if cves else 0,
            "status": "matching" if match_count > 0 else "no_matches",
        })

    return filter_stats


async def generate_daily_report(session: AsyncSession) -> dict:
    """Generate the daily health report data."""
    today_start = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)

    # Component health (includes Redis detail)
    components = await check_component_health()

    # Today's alert stats
    new_alerted = (await session.execute(
        select(func.count()).select_from(AlertLog).where(
            AlertLog.sent_at >= today_start, AlertLog.status == "sent",
        )
    )).scalar() or 0

    # CVEs seen today but already existed
    existing_seen = (await session.execute(
        select(func.count()).select_from(CVE).where(
            CVE.last_seen >= today_start, CVE.first_seen < today_start,
        )
    )).scalar() or 0

    # Total CVEs in DB
    total_cves = (await session.execute(select(func.count()).select_from(CVE))).scalar() or 0

    # CVEs added today
    new_cves_today = (await session.execute(
        select(func.count()).select_from(CVE).where(CVE.first_seen >= today_start)
    )).scalar() or 0

    # Active filters
    active_filters = (await session.execute(
        select(func.count()).select_from(FilterRule).where(FilterRule.enabled == True)
    )).scalar() or 0

    # Per-filter test results
    try:
        filter_test_results = await _test_filters_against_db(session)
    except Exception as e:
        logger.error(f"Health filter test failed: {e}")
        filter_test_results = []

    # Recent errors from alert logs
    errors_result = await session.execute(
        select(AlertLog).where(
            AlertLog.sent_at >= today_start, AlertLog.status == "failed",
        ).limit(10)
    )
    errors = [{"cve_id": a.cve_id, "error": a.error_message} for a in errors_result.scalars().all()]

    # Build warnings
    warnings = []
    if total_cves == 0:
        warnings.append("Database is empty — run DB initialization.")
    if active_filters == 0:
        warnings.append("No active filter rules configured.")
    filters_with_no_match = [f["name"] for f in filter_test_results if f["status"] == "no_matches"]
    if filters_with_no_match:
        warnings.append(f"Filters with 0 matches in last 5000 CVEs: {', '.join(filters_with_no_match)}")
    redis_detail = components.get("redis_details", {})
    if isinstance(redis_detail, dict) and redis_detail.get("total_keys", 0) == 0:
        warnings.append("Redis appears empty — Celery broker may not be processing tasks.")

    report_data = {
        "report_date": datetime.utcnow().isoformat(),
        "components_status": components,
        "new_cves_alerted": new_alerted,
        "existing_cves_seen": existing_seen,
        "new_cves_today": new_cves_today,
        "total_cves_in_db": total_cves,
        "active_filters": active_filters,
        "filter_test_results": filter_test_results,
        "errors": errors,
        "warnings": warnings,
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

