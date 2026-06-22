"""Alerts API routes – view alert history, logs, and case-close flow."""

from __future__ import annotations

import logging
import re
from datetime import datetime, timedelta
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field
from typing import Optional, Tuple
from sqlalchemy import select, func, or_, update as sql_update
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.routes_auth import require_auth
from app.database import get_db
from app.models.alert_log import AlertLog
from app.models.cve import CVE
from app.services.audit_service import audit, audit_actions
from app.services.webhook_service import dispatch_case_close

logger = logging.getLogger(__name__)

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


# ══════════════════════════════════════════════════════
#  Case-close flow
# ══════════════════════════════════════════════════════
class CloseAlertRequest(BaseModel):
    notes: Optional[str] = Field(None, max_length=4000)


@router.post("/{alert_id}/close")
async def close_alert(
    alert_id: int,
    data: CloseAlertRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Close an alert and fire a CRM webhook stamped with the analyst's identity.

    The acting user's ``full_name`` (and ``username``/``id``) are written
    into the outbound webhook payload under ``user.*`` so the receiving
    CRM can attribute the case. The same identity is denormalized onto
    ``alert_logs.closed_by_name`` for historical attribution.
    """
    user = require_auth(request)

    result = await db.execute(select(AlertLog).where(AlertLog.id == alert_id))
    alert: Optional[AlertLog] = result.scalar_one_or_none()
    if alert is None:
        raise HTTPException(status_code=404, detail=f"Alert {alert_id} not found")

    if alert.status == "closed":
        raise HTTPException(status_code=409, detail="Alert already closed")

    closed_at = datetime.utcnow()
    notes = (data.notes or "").strip() or None

    await db.execute(
        sql_update(AlertLog)
        .where(AlertLog.id == alert_id)
        .values(
            status="closed",
            closed_by_id   = user["id"],
            closed_by_name = user.get("full_name") or user["username"],
            closed_at      = closed_at,
            close_notes    = notes,
        )
    )
    await db.commit()

    # Refresh so the response carries the full closed state.
    result = await db.execute(select(AlertLog).where(AlertLog.id == alert_id))
    alert = result.scalar_one()

    # ── Fire the CRM webhook synchronously ──────────
    # Synchronous (vs background task) so the analyst sees an explicit
    # error if the CRM is down rather than discovering it via the
    # Integrations page later.
    cve_dict: dict = {}
    cve_row = (
        await db.execute(select(CVE).where(CVE.cve_id == alert.cve_id))
    ).scalar_one_or_none()
    if cve_row is not None:
        try:
            cve_dict = cve_row.to_dict()
        except Exception as e:  # noqa: BLE001
            logger.warning(f"close_alert: cve.to_dict failed for {alert.cve_id}: {e}")
            cve_dict = {"cve_id": alert.cve_id}
    else:
        cve_dict = {"cve_id": alert.cve_id}

    webhook_error: Optional[str] = None
    try:
        await dispatch_case_close(
            db,
            cve_dict,
            user={
                "id":        user["id"],
                "username":  user["username"],
                "full_name": user.get("full_name"),
            },
            case={
                "alert_id":  alert.id,
                "closed_at": closed_at.isoformat(),
                "notes":     notes,
            },
            rule_name=alert.rule_name or "",
        )
    except Exception as e:  # noqa: BLE001
        webhook_error = f"{type(e).__name__}: {str(e)[:300]}"
        logger.error(f"close_alert: webhook dispatch failed for alert {alert_id}: {e}")

    await audit(
        action=audit_actions.ALERT_CLOSE,
        actor=user,
        target_type="alert",
        target_id=alert_id,
        metadata={
            "cve_id":        alert.cve_id,
            "rule_name":     alert.rule_name,
            "notes_present": notes is not None,
            "webhook_error": webhook_error,
        },
        request=request,
    )

    return {
        "alert": alert.to_dict(),
        "webhook_error": webhook_error,
    }
