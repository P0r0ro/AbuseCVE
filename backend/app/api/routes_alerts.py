"""Alerts API routes – view alert history and logs."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from typing import Optional
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.alert_log import AlertLog

router = APIRouter(prefix="/api/alerts", tags=["Alerts"])


@router.get("")
async def list_alerts(
    page: int = Query(1, ge=1),
    per_page: int = Query(50, ge=1, le=200),
    status: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
):
    query = select(AlertLog).order_by(AlertLog.sent_at.desc())
    if status:
        query = query.where(AlertLog.status == status)

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
    total = (await db.execute(select(func.count()).select_from(AlertLog))).scalar() or 0
    sent = (await db.execute(
        select(func.count()).select_from(AlertLog).where(AlertLog.status == "sent")
    )).scalar() or 0
    failed = (await db.execute(
        select(func.count()).select_from(AlertLog).where(AlertLog.status == "failed")
    )).scalar() or 0

    return {"total": total, "sent": sent, "failed": failed}
