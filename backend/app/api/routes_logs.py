"""Logs API routes – list/filter/clear worker activity logs."""

from __future__ import annotations

import logging
from fastapi import APIRouter, Depends, Query
from typing import Optional
from sqlalchemy import select, func, desc, delete as sql_delete
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.worker_log import WorkerLog

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/logs", tags=["Logs"])


@router.get("")
async def list_logs(
    page: int = Query(1, ge=1),
    per_page: int = Query(50, ge=1, le=200),
    worker_type: Optional[str] = None,
    level: Optional[str] = None,
    search: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
):
    """List worker logs with filtering and pagination."""
    query = select(WorkerLog)

    if worker_type:
        query = query.where(WorkerLog.worker_type == worker_type)
    if level:
        query = query.where(WorkerLog.level == level.upper())
    if search:
        from sqlalchemy import or_
        pattern = f"%{search}%"
        query = query.where(
            or_(
                WorkerLog.message.ilike(pattern),
                WorkerLog.details.ilike(pattern),
                WorkerLog.task_id.ilike(pattern),
            )
        )

    # Count
    count_q = select(func.count()).select_from(query.subquery())
    total = (await db.execute(count_q)).scalar() or 0

    # Sort by newest first
    query = query.order_by(desc(WorkerLog.timestamp))
    query = query.offset((page - 1) * per_page).limit(per_page)

    result = await db.execute(query)
    logs = [l.to_dict() for l in result.scalars().all()]

    return {
        "items": logs,
        "total": total,
        "page": page,
        "per_page": per_page,
        "pages": (total + per_page - 1) // per_page if per_page else 0,
    }


@router.get("/worker-types")
async def get_worker_types(db: AsyncSession = Depends(get_db)):
    """Get distinct worker types in logs."""
    result = await db.execute(
        select(WorkerLog.worker_type, func.count())
        .group_by(WorkerLog.worker_type)
        .order_by(desc(func.count()))
    )
    return [{"type": row[0], "count": row[1]} for row in result.all()]


@router.delete("/clear")
async def clear_logs(
    worker_type: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
):
    """Clear worker logs, optionally filtered by type."""
    if worker_type:
        await db.execute(sql_delete(WorkerLog).where(WorkerLog.worker_type == worker_type))
    else:
        await db.execute(sql_delete(WorkerLog))
    await db.commit()
    return {"message": f"Logs cleared{f' for {worker_type}' if worker_type else ''}"}
