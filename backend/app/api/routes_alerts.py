"""Alerts API routes – view alert history and logs."""

from __future__ import annotations

from datetime import datetime, timedelta
from fastapi import APIRouter, Depends, Query
from typing import Optional
from sqlalchemy import select, func, or_
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.alert_log import AlertLog

router = APIRouter(prefix="/api/alerts", tags=["Alerts"])


def _apply_period(query, period: Optional[str]):
    """Filter AlertLog query by time period."""
    now = datetime.utcnow()
    if period == "today":
        cutoff = now.replace(hour=0, minute=0, second=0, microsecond=0)
    elif period == "week":
        cutoff = now - timedelta(days=7)
    elif period == "month":
        cutoff = now - timedelta(days=30)
    elif period == "year":
        cutoff = now - timedelta(days=365)
    else:
        return query
    return query.where(AlertLog.sent_at >= cutoff)


@router.get("")
async def list_alerts(
    page: int = Query(1, ge=1),
    per_page: int = Query(50, ge=1, le=200),
    status: Optional[str] = None,
    period: Optional[str] = Query(None, description="today|week|month|year"),
    pql: Optional[str] = Query(None, description="Search CVE ID or rule name"),
    is_new: Optional[bool] = Query(None, description="Filter by new vs duplicate CVEs"),
    db: AsyncSession = Depends(get_db),
):
    query = select(AlertLog).order_by(AlertLog.sent_at.desc())

    if status:
        query = query.where(AlertLog.status == status)
    if period:
        query = _apply_period(query, period)
    if pql:
        search = f"%{pql}%"
        query = query.where(
            or_(
                AlertLog.cve_id.ilike(search),
                AlertLog.rule_name.ilike(search),
            )
        )
    if is_new is not None:
        query = query.where(AlertLog.is_new_cve == is_new)

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
    today_start = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)

    total = (await db.execute(select(func.count()).select_from(AlertLog))).scalar() or 0
    sent = (await db.execute(
        select(func.count()).select_from(AlertLog).where(AlertLog.status == "sent")
    )).scalar() or 0
    failed = (await db.execute(
        select(func.count()).select_from(AlertLog).where(AlertLog.status == "failed")
    )).scalar() or 0
    stored = (await db.execute(
        select(func.count()).select_from(AlertLog).where(AlertLog.status == "stored")
    )).scalar() or 0
    sent_today = (await db.execute(
        select(func.count()).select_from(AlertLog).where(
            AlertLog.status == "sent", AlertLog.sent_at >= today_start
        )
    )).scalar() or 0
    new_cve_alerts = (await db.execute(
        select(func.count()).select_from(AlertLog).where(AlertLog.is_new_cve == True)
    )).scalar() or 0

    return {
        "total": total,
        "sent": sent,
        "failed": failed,
        "stored": stored,
        "sent_today": sent_today,
        "new_cve_alerts": new_cve_alerts,
    }
