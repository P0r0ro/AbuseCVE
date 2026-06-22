"""User management — admin-only CRUD.

Soft-delete only: deactivation flips ``is_active=False`` so the row stays
queryable from historical FKs (alert close attribution, audit log). The
``soc`` legacy account is special-cased: admins can deactivate it once
every analyst is migrated, but they cannot delete it from the API.

Password resets are admin-driven — there is intentionally no
self-service password-change endpoint while RBAC is being rolled out.
"""

from __future__ import annotations

import logging
import re
from datetime import datetime
from typing import List, Optional

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import select, update as sql_update

from app.api.routes_auth import (
    SESSION_KEY_PREFIX,
    _redis,
    require_admin,
)
from app.database import async_session
from app.models.user import User
from app.services.audit_service import audit, audit_actions
from app.services.password import hash_password

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/auth/users", tags=["Users"])

USERNAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{1,62}[a-z0-9]$")
MIN_PASSWORD_LEN = 8
VALID_ROLES = {"ADMIN", "SOC"}


class CreateUserRequest(BaseModel):
    username:  str
    full_name: str = Field(..., min_length=1, max_length=120)
    password:  str
    role:      str = "SOC"


class UpdateUserRequest(BaseModel):
    full_name: Optional[str]  = Field(None, min_length=1, max_length=120)
    role:      Optional[str]  = None
    is_active: Optional[bool] = None
    password:  Optional[str]  = None    # admin-driven password reset


def _validate_username(value: str) -> str:
    uname = (value or "").strip().lower()
    if not USERNAME_RE.match(uname):
        raise HTTPException(
            status_code=400,
            detail="username must be 3–64 chars, lowercase alphanumeric plus . _ -",
        )
    return uname


def _validate_password(value: str) -> None:
    if not value or len(value) < MIN_PASSWORD_LEN:
        raise HTTPException(
            status_code=400,
            detail=f"password must be at least {MIN_PASSWORD_LEN} characters",
        )


def _validate_role(value: str) -> str:
    role = (value or "").strip().upper()
    if role not in VALID_ROLES:
        raise HTTPException(status_code=400, detail=f"role must be one of {sorted(VALID_ROLES)}")
    return role


def _invalidate_sessions_for(user_id: int) -> None:
    """Drop every active Redis session that belongs to this user.

    Called after a deactivation, role change, or password reset so the
    affected analyst is forced to re-authenticate immediately.
    """
    try:
        import json
        for key in _redis.scan_iter(match=f"{SESSION_KEY_PREFIX}*"):
            raw = _redis.get(key)
            if not raw:
                continue
            try:
                payload = json.loads(raw)
            except json.JSONDecodeError:
                continue
            if payload.get("id") == user_id:
                _redis.delete(key)
    except Exception as e:  # noqa: BLE001
        logger.warning(f"Session invalidation skipped for user {user_id}: {e}")


@router.get("")
async def list_users(request: Request):
    require_admin(request)
    async with async_session() as session:
        result = await session.execute(select(User).order_by(User.created_at.asc()))
        users: List[User] = list(result.scalars().all())
    return {"users": [u.to_dict() for u in users]}


@router.post("")
async def create_user(data: CreateUserRequest, request: Request):
    admin = require_admin(request)

    uname = _validate_username(data.username)
    role = _validate_role(data.role)
    _validate_password(data.password)
    full_name = data.full_name.strip()
    if not full_name:
        raise HTTPException(status_code=400, detail="full_name required")

    async with async_session() as session:
        existing = await session.execute(select(User.id).where(User.username == uname))
        if existing.scalar_one_or_none() is not None:
            raise HTTPException(status_code=409, detail="username already exists")

        user = User(
            username=uname,
            full_name=full_name,
            password_hash=hash_password(data.password),
            role=role,
            is_active=True,
            created_at=datetime.utcnow(),
        )
        session.add(user)
        await session.commit()
        await session.refresh(user)

    logger.info(f"Admin created user '{uname}' (role={role})")
    await audit(
        action=audit_actions.USER_CREATE,
        actor=admin,
        target_type="user",
        target_id=user.id,
        metadata={"username": uname, "role": role, "full_name": full_name},
        request=request,
    )
    return {"user": user.to_dict()}


@router.patch("/{user_id}")
async def update_user(user_id: int, data: UpdateUserRequest, request: Request):
    admin = require_admin(request)

    async with async_session() as session:
        result = await session.execute(select(User).where(User.id == user_id))
        user: Optional[User] = result.scalar_one_or_none()
        if user is None:
            raise HTTPException(status_code=404, detail="user not found")

        changes: dict = {}

        if data.full_name is not None:
            name = data.full_name.strip()
            if not name:
                raise HTTPException(status_code=400, detail="full_name cannot be empty")
            changes["full_name"] = name

        if data.role is not None:
            new_role = _validate_role(data.role)
            # Refuse to demote yourself — easy way to lock everyone out.
            if user.id == admin["id"] and new_role != "ADMIN":
                raise HTTPException(status_code=400, detail="cannot demote your own account")
            changes["role"] = new_role

        if data.is_active is not None:
            # Refuse to deactivate yourself.
            if user.id == admin["id"] and data.is_active is False:
                raise HTTPException(status_code=400, detail="cannot deactivate your own account")
            changes["is_active"] = data.is_active

        if data.password is not None:
            _validate_password(data.password)
            changes["password_hash"] = hash_password(data.password)

        if not changes:
            raise HTTPException(status_code=400, detail="no changes supplied")

        await session.execute(sql_update(User).where(User.id == user.id).values(**changes))
        await session.commit()
        result = await session.execute(select(User).where(User.id == user_id))
        user = result.scalar_one()

    # Anything that affects the session payload (role, deactivation, password)
    # forces the affected user to log back in.
    if any(k in changes for k in ("role", "is_active", "password_hash")):
        _invalidate_sessions_for(user.id)

    logger.info(f"Admin updated user '{user.username}' fields={sorted(changes.keys())}")

    # Decide which audit action(s) to record. Each path is fine to coexist —
    # the admin page does one PATCH per change, so usually just one fires.
    if "password_hash" in changes:
        await audit(
            action=audit_actions.USER_PASSWORD_RESET,
            actor=admin,
            target_type="user",
            target_id=user.id,
            metadata={"username": user.username},
            request=request,
        )
    if "is_active" in changes:
        await audit(
            action=audit_actions.USER_REACTIVATE if changes["is_active"] else audit_actions.USER_DEACTIVATE,
            actor=admin,
            target_type="user",
            target_id=user.id,
            metadata={"username": user.username},
            request=request,
        )
    # General catch-all for any non-sensitive change (rename, role flip)
    if any(k in changes for k in ("full_name", "role")):
        await audit(
            action=audit_actions.USER_UPDATE,
            actor=admin,
            target_type="user",
            target_id=user.id,
            metadata={
                "username":  user.username,
                "full_name": changes.get("full_name"),
                "role":      changes.get("role"),
            },
            request=request,
        )
    return {"user": user.to_dict()}


@router.delete("/{user_id}")
async def deactivate_user(user_id: int, request: Request):
    """Soft-delete: flips is_active=False. Hard delete is not exposed."""
    admin = require_admin(request)
    if user_id == admin["id"]:
        raise HTTPException(status_code=400, detail="cannot deactivate your own account")

    async with async_session() as session:
        result = await session.execute(select(User).where(User.id == user_id))
        user: Optional[User] = result.scalar_one_or_none()
        if user is None:
            raise HTTPException(status_code=404, detail="user not found")

        await session.execute(
            sql_update(User).where(User.id == user.id).values(is_active=False)
        )
        await session.commit()

    _invalidate_sessions_for(user_id)
    logger.info(f"Admin deactivated user '{user.username}'")
    await audit(
        action=audit_actions.USER_DEACTIVATE,
        actor=admin,
        target_type="user",
        target_id=user.id,
        metadata={"username": user.username},
        request=request,
    )
    return {"status": "ok"}
