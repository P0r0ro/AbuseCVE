"""Audit log read endpoint — admin-only.

Single GET with optional filters. Pagination is offset-based and capped
at 500 rows per page so the UI can stream the full table without
crushing Postgres.
"""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from fastapi import APIRouter, HTTPException, Query, Request
from sqlalchemy import select, func

from app.api.routes_auth import require_admin
from app.database import async_session
from app.models.audit_log import AuditLog

router = APIRouter(prefix="/api/auth/audit-log", tags=["Audit"])

MAX_LIMIT = 500


@router.get("")
async def list_audit(
    request: Request,
    action: Optional[str]   = Query(None, description="Exact action match (e.g. auth.login.success)"),
    actor_id: Optional[int] = Query(None),
    since: Optional[datetime] = Query(None, description="Only rows with occurred_at >= since"),
    until: Optional[datetime] = Query(None, description="Only rows with occurred_at <= until"),
    limit: int  = Query(100, ge=1, le=MAX_LIMIT),
    offset: int = Query(0,   ge=0),
):
    require_admin(request)

    async with async_session() as session:
        stmt = select(AuditLog)
        count_stmt = select(func.count()).select_from(AuditLog)

        if action:
            stmt       = stmt.where(AuditLog.action == action)
            count_stmt = count_stmt.where(AuditLog.action == action)
        if actor_id is not None:
            stmt       = stmt.where(AuditLog.actor_id == actor_id)
            count_stmt = count_stmt.where(AuditLog.actor_id == actor_id)
        if since:
            stmt       = stmt.where(AuditLog.occurred_at >= since)
            count_stmt = count_stmt.where(AuditLog.occurred_at >= since)
        if until:
            stmt       = stmt.where(AuditLog.occurred_at <= until)
            count_stmt = count_stmt.where(AuditLog.occurred_at <= until)

        total = (await session.execute(count_stmt)).scalar_one()

        stmt = stmt.order_by(AuditLog.occurred_at.desc()).limit(limit).offset(offset)
        rows = list((await session.execute(stmt)).scalars().all())

    return {
        "total":   total,
        "limit":   limit,
        "offset":  offset,
        "entries": [r.to_dict() for r in rows],
    }
