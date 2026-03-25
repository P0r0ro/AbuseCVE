"""Alerts API routes – view alert history and logs."""

from __future__ import annotations

import re
from datetime import datetime, timedelta
from fastapi import APIRouter, Depends, Query
from typing import Optional, Tuple
from sqlalchemy import select, func, or_
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.alert_log import AlertLog

router = APIRouter(prefix="/api/alerts", tags=["Alerts"])


def _parse_period(period: Optional[str]) -> Optional[datetime]:
    """Parse period string to a cutoff datetime.

    Supports:
    - Wazuh-style: Nd (days), Nw (weeks), Nm (months), Ny (years)
    - Legacy names: today, week, month, year
    """
    if not period:
        return None
    now = datetime.utcnow()

    # Wazuh-style: Nd, Nw, Nm, Ny
    match = re.match(r'^(\d+)([dwmy])$', period)
    if match:
        n = int(match.group(1))
        unit = match.group(2)
        if unit == 'd':
            return now - timedelta(days=n)
        elif unit == 'w':
            return now - timedelta(weeks=n)
        elif unit == 'm':
            return now - timedelta(days=n * 30)
        elif unit == 'y':
            return now - timedelta(days=n * 365)

    # Legacy period names
    if period == "today":
        return now.replace(hour=0, minute=0, second=0, microsecond=0)
    elif period == "week":
        return now - timedelta(days=7)
    elif period == "month":
        return now - timedelta(days=30)
    elif period == "year":
        return now - timedelta(days=365)

    return None


def _apply_period(query, period: Optional[str], date_from: Optional[str] = None, date_to: Optional[str] = None):
    """Filter AlertLog query by time period or explicit date range."""
    if date_from or date_to:
        if date_from:
            try:
                dt = datetime.strptime(date_from, "%Y-%m-%d")
                query = query.where(AlertLog.sent_at >= dt)
            except ValueError:
                pass
        if date_to:
            try:
                dt = datetime.strptime(date_to, "%Y-%m-%d").replace(hour=23, minute=59, second=59)
                query = query.where(AlertLog.sent_at <= dt)
            except ValueError:
                pass
        return query
    cutoff = _parse_period(period)
    if cutoff:
        return query.where(AlertLog.sent_at >= cutoff)
    return query


@router.get("")
async def list_alerts(
    page: int = Query(1, ge=1),
    per_page: int = Query(50, ge=1, le=200),
    status: Optional[str] = None,
    period: Optional[str] = Query(None, description="today|week|month|year"),
    date_from: Optional[str] = Query(None, description="Start date YYYY-MM-DD"),
    date_to: Optional[str] = Query(None, description="End date YYYY-MM-DD"),
    pql: Optional[str] = Query(None, description="Search CVE ID or rule name"),
    is_new: Optional[bool] = Query(None, description="Filter by new vs duplicate CVEs"),
    db: AsyncSession = Depends(get_db),
):
    query = select(AlertLog).order_by(AlertLog.sent_at.desc())

    if status:
        query = query.where(AlertLog.status == status)
    if date_from or date_to or period:
        query = _apply_period(query, period, date_from, date_to)
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
async def alert_stats(
    period: Optional[str] = Query("1d", description="Time period: Nd, Nw, Nm, Ny or today/week/month/year"),
    date_from: Optional[str] = Query(None, description="Start date YYYY-MM-DD"),
    date_to: Optional[str] = Query(None, description="End date YYYY-MM-DD"),
    db: AsyncSession = Depends(get_db),
):
    """Get alert stats scoped to the selected period or date range.

    All counts are filtered by period/date range. Default is 1d (today).
    The 'sent_in_period' count tracks emails sent within the period.
    """
    # Build scoping function based on date range or period
    dt_from = None
    dt_to = None
    cutoff = None

    if date_from or date_to:
        if date_from:
            try:
                dt_from = datetime.strptime(date_from, "%Y-%m-%d")
            except ValueError:
                pass
        if date_to:
            try:
                dt_to = datetime.strptime(date_to, "%Y-%m-%d").replace(hour=23, minute=59, second=59)
            except ValueError:
                pass
    else:
        cutoff = _parse_period(period)

    def scoped(base_query):
        q = base_query
        if dt_from or dt_to:
            if dt_from:
                q = q.where(AlertLog.sent_at >= dt_from)
            if dt_to:
                q = q.where(AlertLog.sent_at <= dt_to)
        elif cutoff:
            q = q.where(AlertLog.sent_at >= cutoff)
        return q

    total = (await db.execute(
        scoped(select(func.count()).select_from(AlertLog))
    )).scalar() or 0

    sent = (await db.execute(
        scoped(select(func.count()).select_from(AlertLog).where(AlertLog.status == "sent"))
    )).scalar() or 0

    failed = (await db.execute(
        scoped(select(func.count()).select_from(AlertLog).where(AlertLog.status == "failed"))
    )).scalar() or 0

    stored = (await db.execute(
        scoped(select(func.count()).select_from(AlertLog).where(AlertLog.status == "stored"))
    )).scalar() or 0

    new_cve_alerts = (await db.execute(
        scoped(select(func.count()).select_from(AlertLog).where(AlertLog.is_new_cve == True))
    )).scalar() or 0

    # "Sent in period" — same as sent but explicitly named for clarity
    sent_in_period = sent

    return {
        "total": total,
        "sent": sent,
        "failed": failed,
        "stored": stored,
        "sent_in_period": sent_in_period,
        "new_cve_alerts": new_cve_alerts,
        "period": period or "all",
    }
