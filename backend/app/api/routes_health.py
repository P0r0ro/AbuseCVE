"""Health report API routes."""

from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.health_report import HealthReport
from app.services.health_service import generate_daily_report, check_component_health

router = APIRouter(prefix="/api/health-reports", tags=["Health Reports"])


@router.get("")
async def list_reports(db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(HealthReport).order_by(HealthReport.report_date.desc()).limit(30)
    )
    return [r.to_dict() for r in result.scalars().all()]


@router.get("/status")
async def component_status():
    """Get current component health status."""
    return await check_component_health()


@router.post("/generate")
async def generate_report(db: AsyncSession = Depends(get_db)):
    """Manually trigger a health report."""
    report = await generate_daily_report(db)
    return report


@router.post("/send")
async def generate_and_send(db: AsyncSession = Depends(get_db)):
    """Generate and send a health report via email."""
    report = await generate_daily_report(db)
    from app.services.smtp_service import send_health_report
    email_result = await send_health_report(report)
    return {"report": report, "email": email_result}


@router.get("/scheduler")
async def scheduler_status():
    """Check Celery beat schedule, worker status, and SMTP config."""
    from app.tasks.celery_app import celery_app
    from app.config import settings
    import redis.asyncio as aioredis

    result = {
        "beat_schedule": {},
        "workers": {},
        "smtp_configured": False,
        "redis_status": "unknown",
    }

    # Beat schedule
    for name, entry in celery_app.conf.beat_schedule.items():
        schedule = entry.get("schedule")
        if hasattr(schedule, "human_readable"):
            sched_str = schedule.human_readable
        else:
            sched_str = f"every {schedule}s" if isinstance(schedule, (int, float)) else str(schedule)
        result["beat_schedule"][name] = {
            "task": entry["task"],
            "schedule": sched_str,
        }

    # Worker inspection
    try:
        inspector = celery_app.control.inspect(timeout=3)
        active = inspector.active()
        registered = inspector.registered()
        stats = inspector.stats()

        if active:
            for worker_name, tasks in active.items():
                result["workers"][worker_name] = {
                    "active_tasks": len(tasks),
                    "registered": len(registered.get(worker_name, [])) if registered else 0,
                }
        else:
            result["workers"] = {"error": "No workers responding (are they running?)"}

        if stats:
            for worker_name, worker_stats in stats.items():
                if worker_name in result["workers"] and isinstance(result["workers"][worker_name], dict):
                    result["workers"][worker_name]["uptime"] = worker_stats.get("clock", "?")
                    result["workers"][worker_name]["total_tasks"] = worker_stats.get("total", {})
    except Exception as e:
        result["workers"] = {"error": f"Cannot reach workers: {str(e)[:200]}"}

    # SMTP config check
    result["smtp_configured"] = bool(settings.smtp_host and settings.smtp_user and settings.smtp_password)
    result["smtp_details"] = {
        "host": settings.smtp_host or "(empty)",
        "port": settings.smtp_port,
        "user": settings.smtp_user[:3] + "***" if settings.smtp_user else "(empty)",
        "from": settings.smtp_from or "(empty)",
        "tls": settings.smtp_tls,
        "recipients": settings.alert_recipients or "(empty)",
    }

    # Redis check
    try:
        r = aioredis.from_url(settings.redis_url, decode_responses=True)
        await r.ping()
        celery_queue_len = await r.llen("celery")
        pool_len = await r.llen("abusecve:cve_pool")
        last_sync = await r.get("abusecve:last_sync")
        await r.aclose()
        result["redis_status"] = "ok"
        result["redis_details"] = {
            "celery_queue_length": celery_queue_len,
            "cve_pool_length": pool_len,
            "last_sync": last_sync,
        }
    except Exception as e:
        result["redis_status"] = f"error: {str(e)[:100]}"

    return result
