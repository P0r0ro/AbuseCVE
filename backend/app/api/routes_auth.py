"""AbuseSuite Authentication & RBAC routes.

Lightweight role-based access control for the suite. Two built-in
users are supported:

    admin  — ADMIN role, password-protected. Full access.
    soc    — SOC role, password-less login. Read-mostly.

The admin password is sourced from the ``ABUSECVE_ADMIN_PASSWORD``
environment variable (default ``changeme`` for local dev).

Tokens are opaque random strings stored in an in-memory session map.
For deployments that require persistence across restarts, swap this
for a Redis-backed store — the public surface stays the same.

SOC restrictions (enforced in the middleware helper and in route
guards):
    • DELETE on knowledge articles
    • DELETE on filter rules (and rule create/refine)
    • All webhook / integration management
    • Admin toggle mutation
"""

from __future__ import annotations

import logging
import os
import secrets
from datetime import datetime, timedelta
from typing import Dict, Optional

from fastapi import APIRouter, Header, HTTPException, Request
from pydantic import BaseModel

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/auth", tags=["Auth"])

# ── Config ─────────────────────────────────────
ADMIN_USERNAME = "admin"
SOC_USERNAME = "soc"
ADMIN_PASSWORD = os.environ.get("ABUSECVE_ADMIN_PASSWORD", "changeme")
SESSION_TTL = timedelta(hours=12)

# ── In-memory session store (token → {user, expires_at}) ──
_sessions: Dict[str, dict] = {}

# ── Admin toggles (component → enabled) ───────────────────
# Admins can enable / disable critical suite components for SOC users.
# SOC users read this map to decide which nav items to hide.
_admin_toggles: Dict[str, bool] = {
    "dashboard": True,
    "rules_manager": True,
    "alerts": True,
    "cve_database": True,
    "knowledge": True,
    "logs": True,
    "integrations": True,
    "test": True,
    "health": True,
}


class LoginRequest(BaseModel):
    username: str
    password: Optional[str] = ""


class ToggleRequest(BaseModel):
    component: str
    enabled: bool


def _issue_token(user: dict) -> str:
    token = secrets.token_urlsafe(32)
    _sessions[token] = {
        "user": user,
        "expires_at": datetime.utcnow() + SESSION_TTL,
    }
    return token


def _get_session(token: Optional[str]) -> Optional[dict]:
    if not token:
        return None
    record = _sessions.get(token)
    if not record:
        return None
    if record["expires_at"] < datetime.utcnow():
        _sessions.pop(token, None)
        return None
    return record


def resolve_user(request: Request) -> Optional[dict]:
    """Helper used by middleware to attach the user to request.state."""
    token = request.headers.get("x-auth-token") or request.headers.get("X-Auth-Token")
    record = _get_session(token)
    return record["user"] if record else None


def require_admin(request: Request) -> dict:
    """Raise 403 unless the caller is an ADMIN."""
    user = resolve_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    if user.get("role") != "ADMIN":
        raise HTTPException(status_code=403, detail="Admin privileges required")
    return user


def require_auth(request: Request) -> dict:
    user = resolve_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    return user


@router.post("/login")
async def login(data: LoginRequest):
    """Authenticate a user and return a bearer token.

    admin → requires ``ABUSECVE_ADMIN_PASSWORD``
    soc   → no password required
    """
    uname = (data.username or "").strip().lower()

    if uname == ADMIN_USERNAME:
        if not data.password or data.password != ADMIN_PASSWORD:
            raise HTTPException(status_code=401, detail="Invalid admin password")
        user = {"username": "admin", "role": "ADMIN"}
    elif uname == SOC_USERNAME:
        user = {"username": "soc", "role": "SOC"}
    else:
        raise HTTPException(status_code=401, detail="Unknown user")

    token = _issue_token(user)
    logger.info(f"Auth: {user['username']} signed in")
    return {"token": token, "user": user}


@router.post("/logout")
async def logout(request: Request):
    token = request.headers.get("x-auth-token") or request.headers.get("X-Auth-Token")
    if token:
        _sessions.pop(token, None)
    return {"status": "ok"}


@router.get("/me")
async def me(request: Request):
    user = resolve_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    return user


@router.get("/toggles")
async def list_toggles(request: Request):
    """Return the admin toggle map. Any authenticated user may read this."""
    user = resolve_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    return {"toggles": _admin_toggles}


@router.post("/toggles")
async def set_toggle(data: ToggleRequest, request: Request):
    """Admin-only endpoint for enabling/disabling suite components for SOC."""
    require_admin(request)
    _admin_toggles[data.component] = bool(data.enabled)
    logger.info(f"Admin toggle: {data.component} → {data.enabled}")
    return {"status": "ok", "toggles": _admin_toggles}
