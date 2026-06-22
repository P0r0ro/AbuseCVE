"""User model — per-analyst accounts.

Soft-delete only: ``is_active=False`` blocks login and hides the user
from non-admin lists, but the row stays in Postgres so foreign keys
(e.g. ``alert_logs.closed_by_id``, ``audit_log.actor_id``) remain
resolvable. Hard deletes are intentionally not exposed via the API —
do them manually if compliance ever demands it.

Roles are intentionally minimal for now: ``ADMIN`` and ``SOC``. The
existing Redis-toggle permission model continues to gate SOC writes,
so adding a new analyst is just "create another SOC row." A future
phase can layer groups + per-group permissions on top without breaking
this model.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import Boolean, Column, DateTime, Integer, String

from app.database import Base


class User(Base):
    __tablename__ = "users"

    id            = Column(Integer, primary_key=True, autoincrement=True)
    username      = Column(String(64),  unique=True, nullable=False, index=True)
    full_name     = Column(String(120), nullable=False)
    password_hash = Column(String(255), nullable=False)
    role          = Column(String(16),  nullable=False, default="SOC")  # ADMIN | SOC
    is_active     = Column(Boolean,     nullable=False, default=True)
    created_at    = Column(DateTime,    default=datetime.utcnow, nullable=False)
    last_login_at = Column(DateTime,    nullable=True)

    def to_dict(self, *, include_sensitive: bool = False) -> dict:
        data = {
            "id":            self.id,
            "username":      self.username,
            "full_name":     self.full_name,
            "role":          self.role,
            "is_active":     self.is_active,
            "created_at":    self.created_at.isoformat() if self.created_at else None,
            "last_login_at": self.last_login_at.isoformat() if self.last_login_at else None,
        }
        if include_sensitive:
            data["password_hash"] = self.password_hash
        return data
