"""Logs API routes – worker log viewer and Redis pool inspector."""

from __future__ import annotations

import json
import logging
import pickle
from datetime import datetime, timezone
from typing import Optional

import redis as redis_lib
from fastapi import APIRouter, Depends, Query
from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.database import get_db
from app.models.worker_log import WorkerLog

router = APIRouter(prefix="/api/logs", tags=["Logs"])

logger = logging.getLogger(__name__)


# ── Worker Logs ──────────────────────────────────────────────────────────────

@router.get("")
async def list_logs(
    page: int = Query(1, ge=1),
    per_page: int = Query(50, ge=1, le=500),
    worker_type: Optional[str] = Query(None),
    level: Optional[str] = Query(None),
    search: Optional[str] = Query(None),
    db: AsyncSession = Depends(get_db),
):
    """Paginated, filterable list of worker logs."""
    query = select(WorkerLog).order_by(WorkerLog.timestamp.desc())

    if worker_type:
        query = query.where(WorkerLog.worker_type == worker_type)
    if level:
        query = query.where(WorkerLog.level == level.upper())
    if search:
        query = query.where(WorkerLog.message.ilike(f"%{search}%"))

    count_q = select(func.count()).select_from(query.subquery())
    total = (await db.execute(count_q)).scalar() or 0

    offset = (page - 1) * per_page
    result = await db.execute(query.offset(offset).limit(per_page))
    logs = result.scalars().all()

    return {
        "items": [log.to_dict() for log in logs],
        "total": total,
        "page": page,
        "per_page": per_page,
    }


@router.get("/worker-types")
async def list_worker_types(db: AsyncSession = Depends(get_db)):
    """Return distinct worker types with their log counts."""
    result = await db.execute(
        select(WorkerLog.worker_type, func.count(WorkerLog.id).label("count"))
        .group_by(WorkerLog.worker_type)
        .order_by(func.count(WorkerLog.id).desc())
    )
    rows = result.all()
    return [{"type": row.worker_type, "count": row.count} for row in rows]


@router.delete("/clear")
async def clear_logs(
    worker_type: Optional[str] = Query(None),
    db: AsyncSession = Depends(get_db),
):
    """Delete worker logs, optionally scoped to a specific worker_type."""
    stmt = delete(WorkerLog)
    if worker_type:
        stmt = stmt.where(WorkerLog.worker_type == worker_type)
    await db.execute(stmt)
    await db.commit()
    return {"status": "ok", "worker_type": worker_type or "all"}


# ── Redis Pool Inspector ──────────────────────────────────────────────────────

@router.get("/redis")
async def redis_info():
    """Inspect the Redis connection pool and key distribution."""
    try:
        r = redis_lib.from_url(settings.redis_url, decode_responses=True, socket_timeout=5)
        r.ping()

        info = r.info()
        redis_version = info.get("redis_version", "?")
        used_memory = info.get("used_memory_human", "?")

        # Total key count
        total_keys = r.dbsize()

        # Categorise keys by prefix (scan is non-blocking)
        key_categories: dict[str, int] = {}
        cve_keys: list[str] = []
        cursor = 0
        while True:
            cursor, keys = r.scan(cursor, count=500)
            for key in keys:
                prefix = key.split(":")[0] if ":" in key else key
                key_categories[prefix] = key_categories.get(prefix, 0) + 1
                if key.startswith("cve:"):
                    cve_keys.append(key)
            if cursor == 0:
                break

        # Celery queue lengths
        celery_queues: dict[str, int] = {}
        for queue_name in ["celery", "default", "cve_scan", "health"]:
            length = r.llen(queue_name)
            if length > 0:
                celery_queues[queue_name] = length

        # Sample CVE entries (up to 10)
        cve_samples = []
        for key in cve_keys[:10]:
            try:
                raw = r.get(key)
                if raw:
                    data = json.loads(raw)
                    cve_samples.append({
                        "key": key,
                        "cve_id": data.get("cve_id") or data.get("id", key),
                        "severity": data.get("severity"),
                        "source": data.get("source"),
                    })
            except Exception:
                cve_samples.append({"key": key, "cve_id": key, "severity": None, "source": None})

        r.close()

        return {
            "status": "ok",
            "redis_version": redis_version,
            "used_memory": used_memory,
            "total_keys": total_keys,
            "key_categories": key_categories,
            "cve_keys_found": len(cve_keys),
            "cve_samples": cve_samples,
            "celery_queues": celery_queues,
        }

    except Exception as exc:
        logger.warning(f"Redis inspect failed: {exc}")
        raise


# ── Schedule ──────────────────────────────────────────────────────────────────

@router.get("/schedule")
async def get_schedule():
    """Return the Celery beat schedule with next-run estimates."""
    from app.config import settings as s
    from app.tasks.celery_app import celery_app

    now = datetime.now(timezone.utc)
    schedule = celery_app.conf.beat_schedule or {}

    items = []
    for name, entry in schedule.items():
        sched = entry.get("schedule")
        task = entry.get("task", "")

        # Human-readable label
        label_map = {
            "app.tasks.cve_tasks.run_cve_scan": "CVE Scan",
            "app.tasks.health_tasks.generate_and_send_health_report": "Daily Health Report",
            "app.tasks.init_tasks.initialize_database": "DB Initialization",
        }
        label = label_map.get(task, name)

        # Try to compute interval in seconds + next run
        interval_seconds = None
        next_run_iso = None
        schedule_desc = str(sched)

        try:
            # Plain interval (seconds)
            if isinstance(sched, (int, float)):
                interval_seconds = int(sched)
                schedule_desc = f"every {interval_seconds // 60} min"
            elif hasattr(sched, "seconds"):
                # celery timedelta schedule
                interval_seconds = int(sched.seconds)
                schedule_desc = f"every {interval_seconds // 60} min"
            elif hasattr(sched, "hour"):
                # crontab – daily at fixed time
                h = sched.hour
                m = sched.minute
                # stringify crontab fields
                h_str = list(h)[0] if h else 0
                m_str = list(m)[0] if m else 0
                schedule_desc = f"daily at {int(h_str):02d}:{int(m_str):02d} UTC"
                # Next occurrence
                candidate = now.replace(hour=int(h_str), minute=int(m_str), second=0, microsecond=0)
                if candidate <= now:
                    from datetime import timedelta
                    candidate = candidate + timedelta(days=1)
                next_run_iso = candidate.isoformat()

            if interval_seconds and not next_run_iso:
                # Try to read last-run from Celery beat Redis key
                try:
                    r = redis_lib.from_url(s.redis_url, decode_responses=False, socket_timeout=3)
                    raw = r.get("celery-beat-schedule")
                    r.close()
                    if raw:
                        data = pickle.loads(raw)
                        entry_data = data.get("entries", {}).get(name) or data.get(name)
                        if entry_data and hasattr(entry_data, "last_run_at") and entry_data.last_run_at:
                            last = entry_data.last_run_at
                            if last.tzinfo is None:
                                last = last.replace(tzinfo=timezone.utc)
                            from datetime import timedelta
                            next_run = last + timedelta(seconds=interval_seconds)
                            if next_run < now:
                                next_run = now
                            next_run_iso = next_run.isoformat()
                except Exception:
                    pass

        except Exception:
            pass

        items.append({
            "name": name,
            "label": label,
            "task": task,
            "schedule_desc": schedule_desc,
            "interval_seconds": interval_seconds,
            "next_run": next_run_iso,
        })

    return {"schedule": items, "server_time": now.isoformat()}
