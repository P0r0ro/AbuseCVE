"""Dashboard API routes – overview stats and init controls."""

from __future__ import annotations

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from typing import Optional
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.cve import CVE
from app.models.filter_rule import FilterRule
from app.models.alert_log import AlertLog

router = APIRouter(prefix="/api/dashboard", tags=["Dashboard"])


@router.get("/overview")
async def dashboard_overview(db: AsyncSession = Depends(get_db)):
    """Get dashboard overview statistics."""
    from datetime import datetime, timedelta
    today_start = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)

    total_cves = (await db.execute(select(func.count()).select_from(CVE))).scalar() or 0
    today_alerts = (await db.execute(
        select(func.count()).select_from(AlertLog).where(AlertLog.sent_at >= today_start)
    )).scalar() or 0
    active_filters = (await db.execute(
        select(func.count()).select_from(FilterRule).where(FilterRule.enabled == True)
    )).scalar() or 0
    kev_count = (await db.execute(
        select(func.count()).select_from(CVE).where(CVE.kev_flag == True)
    )).scalar() or 0

    # Severity distribution
    severity_result = await db.execute(
        select(CVE.severity, func.count()).group_by(CVE.severity)
    )
    severity_dist = {row[0] or "UNKNOWN": row[1] for row in severity_result.all()}

    # Source distribution
    source_result = await db.execute(
        select(CVE.source, func.count()).group_by(CVE.source)
    )
    source_dist = {row[0] or "UNKNOWN": row[1] for row in source_result.all()}

    # Recent CVEs
    recent_result = await db.execute(
        select(CVE).order_by(CVE.first_seen.desc()).limit(10)
    )
    recent_cves = [c.to_dict() for c in recent_result.scalars().all()]

    # Recent alerts
    recent_alerts_result = await db.execute(
        select(AlertLog).order_by(AlertLog.sent_at.desc()).limit(10)
    )
    recent_alerts = [a.to_dict() for a in recent_alerts_result.scalars().all()]

    return {
        "total_cves": total_cves,
        "today_alerts": today_alerts,
        "active_filters": active_filters,
        "kev_count": kev_count,
        "severity_distribution": severity_dist,
        "source_distribution": source_dist,
        "recent_cves": recent_cves,
        "recent_alerts": recent_alerts,
    }


@router.post("/initialize-db")
async def initialize_database():
    """Trigger full bulk import of ALL past CVEs from all sources."""
    from app.tasks.init_tasks import initialize_database as init_db_task
    task = init_db_task.delay()
    return {
        "message": "Full database initialization started (NVD + MITRE + CISA KEV + RedHat)",
        "task_id": task.id,
    }


class LocalInitRequest(BaseModel):
    mitre_dir: Optional[str] = None
    nvd_dir: Optional[str] = None


@router.post("/initialize-db-local")
async def initialize_database_local(data: LocalInitRequest):
    """Trigger bulk import from locally downloaded data directories.

    Steps for manual setup:
    1. git clone https://github.com/CVEProject/cvelistV5.git
    2. Pass the path to the cves/ subdirectory as mitre_dir
    """
    from app.tasks.init_tasks import initialize_database_local as init_local_task
    task = init_local_task.delay(mitre_dir=data.mitre_dir, nvd_dir=data.nvd_dir)
    return {
        "message": "Local database initialization started",
        "task_id": task.id,
        "mitre_dir": data.mitre_dir,
    }


@router.post("/trigger-scan")
async def trigger_scan():
    """Manually trigger a CVE scan cycle."""
    from app.tasks.cve_tasks import run_cve_scan
    task = run_cve_scan.delay()
    return {
        "message": "CVE scan triggered",
        "task_id": task.id,
    }


@router.get("/task-status/{task_id}")
async def get_task_status(task_id: str):
    """Check status of an async task (init, scan, etc.)."""
    from app.tasks.celery_app import celery_app
    result = celery_app.AsyncResult(task_id)
    return {
        "task_id": task_id,
        "status": result.status,
        "result": result.result if result.ready() else None,
    }


class ClearDataRequest(BaseModel):
    clear_alerts: bool = True
    clear_health_reports: bool = True
    clear_cves: bool = False
    clear_knowledge_articles: bool = False


@router.post("/clear-data")
async def clear_old_data(data: ClearDataRequest, db: AsyncSession = Depends(get_db)):
    """Clear old data from the database while preserving filter rules and config.

    Use this for a clean start after updates without losing your filter rules.
    """
    from sqlalchemy import delete as sql_delete
    cleared = []

    if data.clear_alerts:
        await db.execute(sql_delete(AlertLog))
        cleared.append("alerts")

    if data.clear_health_reports:
        try:
            from app.models.health_report import HealthReport
            await db.execute(sql_delete(HealthReport))
            cleared.append("health_reports")
        except Exception:
            cleared.append("health_reports (skipped — table may not exist)")

    if data.clear_cves:
        await db.execute(sql_delete(CVE))
        cleared.append("cves")

    if data.clear_knowledge_articles:
        try:
            from app.models.knowledge_article import KnowledgeArticle
            await db.execute(sql_delete(KnowledgeArticle))
            cleared.append("knowledge_articles")
        except Exception:
            cleared.append("knowledge_articles (skipped)")

    await db.commit()

    return {
        "message": f"Cleared: {', '.join(cleared)}",
        "cleared": cleared,
    }

