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


@router.get("/redis")
async def inspect_redis():
    """Inspect the current Redis pool — Celery queues, cached CVEs, key counts, memory."""
    import redis.asyncio as aioredis
    from app.config import settings

    try:
        r = aioredis.from_url(settings.redis_url, decode_responses=True)

        # Basic connectivity + memory
        info = await r.info("memory")
        keyspace = await r.info("keyspace")
        server_info = await r.info("server")

        used_mem = info.get("used_memory_human", "?")
        redis_version = server_info.get("redis_version", "?")

        # Celery queue lengths (default queues)
        celery_queues = {}
        for queue_name in ["celery", "cve_tasks", "health_tasks", "default"]:
            try:
                qlen = await r.llen(queue_name)
                if qlen > 0:
                    celery_queues[queue_name] = qlen
            except Exception:
                pass

        # Count keys by prefix/category
        key_categories: dict = {}
        cursor = 0
        total_keys = 0
        sample_cve_keys: list = []

        while True:
            cursor, keys = await r.scan(cursor, count=500)
            for k in keys:
                total_keys += 1
                # Categorize by prefix
                prefix = k.split(":")[0] if ":" in k else k[:20]
                key_categories[prefix] = key_categories.get(prefix, 0) + 1
                # Collect a few CVE key samples
                if k.startswith("cve:") and len(sample_cve_keys) < 20:
                    sample_cve_keys.append(k)
            if cursor == 0:
                break

        # Fetch sample CVE data (just IDs + severity)
        cve_samples = []
        for key in sample_cve_keys[:10]:
            try:
                val = await r.get(key)
                if val:
                    import json as _json
                    obj = _json.loads(val)
                    cve_samples.append({
                        "key": key,
                        "cve_id": obj.get("cve_id", key),
                        "severity": obj.get("severity"),
                        "source": obj.get("source"),
                    })
            except Exception:
                cve_samples.append({"key": key})

        # Recent Celery task results (celery-task-meta-*)
        task_meta_count = key_categories.get("celery-task-meta-*", 0)
        # Count via scan is already in key_categories under "celery-task-meta-"
        task_meta_count = key_categories.get("celery-task-meta-", 0)

        await r.aclose()

        return {
            "status": "ok",
            "redis_version": redis_version,
            "used_memory": used_mem,
            "total_keys": total_keys,
            "key_categories": dict(sorted(key_categories.items(), key=lambda x: -x[1])),
            "celery_queues": celery_queues,
            "cve_keys_found": len(sample_cve_keys),
            "cve_samples": cve_samples,
            "keyspace_info": keyspace,
        }

    except Exception as e:
        logger.error(f"Redis inspection error: {e}", exc_info=True)
        return {
            "status": "error",
            "error": str(e),
        }

