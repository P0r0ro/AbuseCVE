"""AbuseSuite Authentication & RBAC routes.

Per-analyst login backed by the ``users`` table (Postgres). The legacy
``soc`` shared account is preserved as a passwordless fallback during
rollout — admins flip ``is_active=False`` on it from the Users page
once every analyst has their own login.

Sessions live in Redis under ``abusecve:session:<token>`` with a 12-hour
TTL. The session JSON now carries ``{id, username, full_name, role}``
so downstream code (webhooks, audit log) can attribute actions without
re-hitting the DB.

SOC restrictions (enforced centrally by middleware in ``main.py``):
    • DELETE on knowledge articles
    • Writes to filter rules (create / refine / delete / edit)
    • All webhook / integration management
    • Admin toggle mutation
"""

from __future__ import annotations

import json
import logging
import secrets
from datetime import datetime, timedelta
from typing import Dict, Optional

import redis
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy import select, update as sql_update

from app.config import settings
from app.database import async_session
from app.models.user import User
from app.services.audit_service import audit, audit_actions
from app.services.password import verify_password

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/auth", tags=["Auth"])

# ── Config ─────────────────────────────────────
SESSION_TTL_SECONDS = int(timedelta(hours=12).total_seconds())
SESSION_KEY_PREFIX = "abusecve:session:"
TOGGLES_KEY = "abusecve:toggles"

# Sentinel value the migration writes for the legacy ``soc`` row.
# verify_password() can never match it (passlib rejects "!" as malformed),
# so the only way ``soc`` logs in is via the legacy passwordless branch.
LEGACY_SOC_HASH_MARKER = "!"

# ── Redis client ───────────────────────────────
_redis = redis.Redis.from_url(
    settings.redis_url,
    decode_responses=True,
    socket_connect_timeout=5,
    socket_timeout=5,
)

# Default toggle state — seeded on first boot if Redis has no record.
DEFAULT_TOGGLES: Dict[str, bool] = {
    # Visibility (true = SOC can see the page)
    "dashboard": True,
    "rules_manager": True,
    "alerts": True,
    "cve_database": True,
    "knowledge": True,
    "logs": True,
    "integrations": True,
    "test": True,
    "health": True,
    # Privileged actions (true = SOC may perform the write)
    "soc_rule_create": False,
    "soc_rule_refine": False,
    "soc_rule_delete": False,
    "soc_rule_edit": False,
    "soc_ka_delete": False,
}


def _ensure_toggles_seeded() -> None:
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


def _session_payload(user: User) -> dict:
    """Shape stored in Redis — kept minimal, no password fields ever."""
    return {
        "id":        user.id,
        "username":  user.username,
        "full_name": user.full_name,
        "role":      user.role,
    }


def _issue_token(payload: dict) -> str:
    token = secrets.token_urlsafe(32)
    _redis.setex(
        f"{SESSION_KEY_PREFIX}{token}",
        SESSION_TTL_SECONDS,
        json.dumps(payload),
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
async def login(data: LoginRequest, request: Request):
    """Authenticate against the ``users`` table.

    Login rules:
        - Unknown / inactive username → 401.
        - Legacy ``soc`` account (``password_hash == "!"``) accepts any
          password (including empty) — this preserves pre-DB behaviour.
        - Every other account requires the correct bcrypt password.
    """
    uname = (data.username or "").strip().lower()
    if not uname:
        raise HTTPException(status_code=400, detail="Username required")

    async with async_session() as session:
        result = await session.execute(select(User).where(User.username == uname))
        user: Optional[User] = result.scalar_one_or_none()

        if not user or not user.is_active:
            logger.info(f"Auth: failed login for '{uname}' (unknown/inactive)")
            await audit(
                action=audit_actions.LOGIN_FAILURE,
                metadata={"username": uname, "reason": "unknown_or_inactive"},
                request=request,
            )
            raise HTTPException(status_code=401, detail="Invalid credentials")

        is_legacy_soc = user.password_hash == LEGACY_SOC_HASH_MARKER
        password_ok = is_legacy_soc or verify_password(data.password or "", user.password_hash)

        if not password_ok:
            logger.info(f"Auth: failed login for '{uname}' (bad password)")
            await audit(
                action=audit_actions.LOGIN_FAILURE,
                metadata={"username": uname, "reason": "bad_password"},
                request=request,
            )
            raise HTTPException(status_code=401, detail="Invalid credentials")

        # Stamp last_login_at so admins can see stale accounts.
        await session.execute(
            sql_update(User).where(User.id == user.id).values(last_login_at=datetime.utcnow())
        )
        await session.commit()

        payload = _session_payload(user)

    token = _issue_token(payload)
    logger.info(f"Auth: {payload['username']} signed in (role={payload['role']})")
    await audit(
        action=audit_actions.LOGIN_SUCCESS,
        actor=payload,
        metadata={"legacy_soc": is_legacy_soc},
        request=request,
    )
    return {"token": token, "user": payload}


@router.post("/logout")
async def logout(request: Request):
    user = resolve_user(request)
    token = request.headers.get("x-auth-token") or request.headers.get("X-Auth-Token")
    if token:
        try:
            _redis.delete(f"{SESSION_KEY_PREFIX}{token}")
        except redis.RedisError:
            pass
    if user:
        await audit(action=audit_actions.LOGOUT, actor=user, request=request)
    return {"status": "ok"}


@router.get("/me")
async def me(request: Request):
    user = resolve_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    return user


@router.get("/toggles")
async def list_toggles(request: Request):
    user = resolve_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    return {"toggles": _load_toggles()}


@router.post("/toggles")
async def set_toggle(data: ToggleRequest, request: Request):
    admin = require_admin(request)
    try:
        _ensure_toggles_seeded()
        _redis.hset(TOGGLES_KEY, data.component, "1" if data.enabled else "0")
    except redis.RedisError as e:
        raise HTTPException(status_code=503, detail=f"Redis unavailable: {e}")
    logger.info(f"Admin toggle: {data.component} -> {data.enabled}")
    await audit(
        action=audit_actions.TOGGLE_CHANGE,
        actor=admin,
        target_type="toggle",
        target_id=data.component,
        metadata={"enabled": data.enabled},
        request=request,
    )
    return {"status": "ok", "toggles": _load_toggles()}
