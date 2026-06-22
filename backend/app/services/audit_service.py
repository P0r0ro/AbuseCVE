"""Audit log helpers — fire-and-forget recording of sensitive actions.

Two entry points:

* ``audit()`` — the canonical helper. Opens its own short-lived session,
  inserts one row, swallows errors (we never want an audit failure to
  break the actual user action). Call this from inside a route handler.

* ``audit_actions`` — string constants for the actions we record, so
  routes don't sprinkle magic strings around.

The session/actor handling is deliberately self-contained: callers
don't need to thread a session through, and they don't need to worry
about commit/rollback semantics in the main flow. If audit writes ever
become a hot-path concern, swap this for a Redis queue + worker without
touching call sites.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Mapping, Optional

from fastapi import Request

from app.database import async_session
from app.models.audit_log import AuditLog

logger = logging.getLogger(__name__)


class audit_actions:
    # Auth
    LOGIN_SUCCESS  = "auth.login.success"
    LOGIN_FAILURE  = "auth.login.failure"
    LOGOUT         = "auth.logout"
    # User management
    USER_CREATE       = "user.create"
    USER_UPDATE       = "user.update"
    USER_DEACTIVATE   = "user.deactivate"
    USER_REACTIVATE   = "user.reactivate"
    USER_PASSWORD_RESET = "user.password_reset"
    # Access control toggles
    TOGGLE_CHANGE  = "toggle.change"
    # Filter rules
    RULE_CREATE = "rule.create"
    RULE_UPDATE = "rule.update"
    RULE_DELETE = "rule.delete"
    RULE_REFINE = "rule.refine"
    # Alerts / case management (Phase 4)
    ALERT_CLOSE = "alert.close"


def _request_ip(request: Optional[Request]) -> Optional[str]:
    if request is None:
        return None
    try:
        # honor X-Forwarded-For when behind the master nginx proxy
        fwd = request.headers.get("x-forwarded-for")
        if fwd:
            return fwd.split(",")[0].strip()
        return request.client.host if request.client else None
    except Exception:  # noqa: BLE001
        return None


async def audit(
    *,
    action: str,
    actor: Optional[Mapping[str, Any]] = None,
    target_type: Optional[str] = None,
    target_id: Optional[Any] = None,
    metadata: Optional[Dict[str, Any]] = None,
    request: Optional[Request] = None,
) -> None:
    """Persist one audit row. Never raises."""
    try:
        row = AuditLog(
            actor_id    = (actor or {}).get("id"),
            actor_name  = (actor or {}).get("full_name") or (actor or {}).get("username"),
            action      = action,
            target_type = target_type,
            target_id   = str(target_id) if target_id is not None else None,
            event_meta  = metadata,
            ip_address  = _request_ip(request),
        )
        async with async_session() as session:
            session.add(row)
            await session.commit()
    except Exception as e:  # noqa: BLE001
        # Audit failures must never block the main action.
        logger.warning(f"audit({action}) write failed: {e}")
