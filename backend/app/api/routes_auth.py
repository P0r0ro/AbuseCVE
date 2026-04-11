"""AbuseSuite Authentication & RBAC routes.

Lightweight role-based access control for the suite. Two built-in
users are supported:

    admin  — ADMIN role, password-protected. Full access.
    soc    — SOC role, password-less login. Read-mostly.

The admin password is sourced from the ``ABUSECVE_ADMIN_PASSWORD``
environment variable (default ``changeme`` for local dev).

Session storage is Redis-backed so that multiple uvicorn workers share
the same session state. The keys live under ``abusecve:session:<token>``
with a 12-hour TTL, and admin toggles under ``abusecve:toggles``.

SOC restrictions (enforced centrally by the middleware helper):
    • DELETE on knowledge articles
    • Writes to filter rules (create / refine / delete)
    • All webhook / integration management
    • Admin toggle mutation
"""

from __future__ import annotations

import json
import logging
import os
import secrets
from datetime import timedelta
from typing import Dict, Optional

import redis
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

from app.config import settings

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/auth", tags=["Auth"])

# ── Config ─────────────────────────────────────
ADMIN_USERNAME = "admin"
SOC_USERNAME = "soc"
ADMIN_PASSWORD = os.environ.get("ABUSECVE_ADMIN_PASSWORD", "changeme")
SESSION_TTL_SECONDS = int(timedelta(hours=12).total_seconds())

SESSION_KEY_PREFIX = "abusecve:session:"
TOGGLES_KEY = "abusecve:toggles"

# ── Redis client (sync — used only inside route handlers / middleware) ──
# A sync client is fine here because sessions are read once per request
# and the payload is a single ~100-byte string. Using the async client
# would require awaiting inside the middleware and would offer no
# measurable benefit at this traffic level.
_redis = redis.Redis.from_url(
    settings.redis_url,
    decode_responses=True,
    socket_connect_timeout=5,
    socket_timeout=5,
)

# Default toggle state — seeded on first boot if Redis has no record.
DEFAULT_TOGGLES: Dict[str, bool] = {
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


def _ensure_toggles_seeded() -> None:
    """Populate the toggles hash on first use so reads never see None."""
    try:
        if not _redis.exists(TOGGLES_KEY):
            _redis.hset(
                TOGGLES_KEY,
                mapping={k: "1" if v else "0" for k, v in DEFAULT_TOGGLES.items()},
            )
    except redis.RedisError as e:
        logger.warning(f"Toggle seed skipped: {e}")


def _load_toggles() -> Dict[str, bool]:
    try:
        _ensure_toggles_seeded()
        raw = _redis.hgetall(TOGGLES_KEY)
        if not raw:
            return dict(DEFAULT_TOGGLES)
        return {k: v == "1" for k, v in raw.items()}
    except redis.RedisError as e:
        logger.warning(f"Toggle load fell back to defaults: {e}")
        return dict(DEFAULT_TOGGLES)


class LoginRequest(BaseModel):
    username: str
    password: Optional[str] = ""


class ToggleRequest(BaseModel):
    component: str
    enabled: bool


def _issue_token(user: dict) -> str:
    token = secrets.token_urlsafe(32)
    _redis.setex(
        f"{SESSION_KEY_PREFIX}{token}",
        SESSION_TTL_SECONDS,
        json.dumps(user),
    )
    return token


def _get_user(token: Optional[str]) -> Optional[dict]:
    if not token:
        return None
    try:
        raw = _redis.get(f"{SESSION_KEY_PREFIX}{token}")
    except redis.RedisError as e:
        logger.error(f"Redis session lookup failed: {e}")
        return None
    if not raw:
        return None
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return None


def resolve_user(request: Request) -> Optional[dict]:
    """Helper used by middleware to attach the user to request.state."""
    token = request.headers.get("x-auth-token") or request.headers.get("X-Auth-Token")
    return _get_user(token)


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
        try:
            _redis.delete(f"{SESSION_KEY_PREFIX}{token}")
        except redis.RedisError:
            pass
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
    return {"toggles": _load_toggles()}


@router.post("/toggles")
async def set_toggle(data: ToggleRequest, request: Request):
    """Admin-only endpoint for enabling/disabling suite components for SOC."""
    require_admin(request)
    try:
        _ensure_toggles_seeded()
        _redis.hset(TOGGLES_KEY, data.component, "1" if data.enabled else "0")
    except redis.RedisError as e:
        raise HTTPException(status_code=503, detail=f"Redis unavailable: {e}")
    logger.info(f"Admin toggle: {data.component} -> {data.enabled}")
    return {"status": "ok", "toggles": _load_toggles()}
