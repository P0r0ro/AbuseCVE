"""Alerts API routes – view alert history and logs."""

from __future__ import annotations

from datetime import datetime, timedelta
from fastapi import APIRouter, Depends, Query
from typing import Optional
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.alert_log import AlertLog
from app.models.cve import CVE

router = APIRouter(prefix="/api/alerts", tags=["Alerts"])


def _period_start(period: Optional[str]) -> Optional[datetime]:
    """Return the UTC start datetime for the given period string."""
    now = datetime.utcnow()
    if period == "today":
        return now.replace(hour=0, minute=0, second=0, microsecond=0)
    if period == "week":
        return (now - timedelta(days=now.weekday())).replace(hour=0, minute=0, second=0, microsecond=0)
    if period == "month":
        return now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    if period == "year":
        return now.replace(month=1, day=1, hour=0, minute=0, second=0, microsecond=0)
    return None


@router.get("")
async def list_alerts(
    page: int = Query(1, ge=1),
    per_page: int = Query(50, ge=1, le=200),
    status: Optional[str] = None,
    period: Optional[str] = Query(None, description="today | week | month | year"),
    is_new: Optional[str] = Query(None, description="true | false"),
    pql: Optional[str] = Query(None, description="PQL expression to filter CVEs (same syntax as CVE database)"),
    db: AsyncSession = Depends(get_db),
):
    query = select(AlertLog).order_by(AlertLog.sent_at.desc())

    if status:
        query = query.where(AlertLog.status == status)

    start = _period_start(period)
    if start:
        query = query.where(AlertLog.sent_at >= start)

    if is_new is not None:
        flag = is_new.lower() == "true"
        query = query.where(AlertLog.is_new_cve == flag)

    # PQL filter: resolve matching CVE IDs then scope to those
    if pql and pql.strip():
        try:
            from app.engine.query_engine import condition_to_sql_filter, parse_pql_to_conditions
            conditions = parse_pql_to_conditions(pql)
            if conditions:
                sql_filter = condition_to_sql_filter(CVE, conditions)
                cve_query = select(CVE.cve_id)
                if sql_filter is not None:
                    cve_query = cve_query.where(sql_filter)
                cve_id_result = await db.execute(cve_query)
                matching_ids = [row[0] for row in cve_id_result.all()]
                if matching_ids:
                    query = query.where(AlertLog.cve_id.in_(matching_ids))
                else:
                    # PQL matched nothing — return empty
                    return {"items": [], "total": 0, "page": page, "per_page": per_page, "pql_matched": 0}
        except Exception as e:
            import logging
            logging.getLogger(__name__).warning(f"Alerts PQL filter failed: {e}")
            # Fall through without PQL filter on parse error

    count_query = select(func.count()).select_from(query.subquery())
    total = (await db.execute(count_query)).scalar() or 0

    offset = (page - 1) * per_page
    result = await db.execute(query.offset(offset).limit(per_page))
    alerts = result.scalars().all()

    return {
        "items": [a.to_dict() for a in alerts],
        "total": total,
        "page": page,
        "per_page": per_page,
    }


@router.get("/stats")
async def alert_stats(db: AsyncSession = Depends(get_db)):
    today = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)

    async def _count(*where_clauses):
        q = select(func.count()).select_from(AlertLog)
        for clause in where_clauses:
            q = q.where(clause)
        return (await db.execute(q)).scalar() or 0

    total = await _count()
    sent = await _count(AlertLog.status == "sent")
    failed = await _count(AlertLog.status == "failed")
    stored = await _count(AlertLog.status == "stored")
    new_cves = await _count(AlertLog.is_new_cve == True)
    today_sent = await _count(AlertLog.sent_at >= today, AlertLog.status == "sent")
    today_failed = await _count(AlertLog.sent_at >= today, AlertLog.status == "failed")
    today_stored = await _count(AlertLog.sent_at >= today, AlertLog.status == "stored")

    return {
        "total": total,
        "sent": sent,
        "failed": failed,
        "stored": stored,
        "new_cves": new_cves,
        "today_sent": today_sent,
        "today_failed": today_failed,
        "today_stored": today_stored,
    }
