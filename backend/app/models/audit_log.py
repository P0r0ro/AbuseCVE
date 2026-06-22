"""Audit log — append-only record of sensitive actions.

Captures who-did-what-when across the suite. Used by the admin Audit
Log page and (later) by compliance exports.

Design choices
--------------
* ``actor_id`` is a nullable FK to ``users.id`` so failed-login rows
  (no authenticated actor yet) and system-generated events can still be
  recorded.
* ``actor_name`` is denormalized so a deactivated/renamed user still
  shows the right name on historical rows. Same trick we used for
  ``alert_logs.closed_by_name``.
* ``metadata`` (JSONB) holds free-form context: rule diffs, IP, the
  attempted username on a failed login, etc. Don't store secrets here.
* No update / delete API — admins can only read or export. If you ever
  need to prune, do it as a manual SQL DELETE with a date filter.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import Column, DateTime, ForeignKey, Integer, String
from sqlalchemy.dialects.postgresql import JSONB

from app.database import Base


class AuditLog(Base):
    __tablename__ = "audit_log"

    id          = Column(Integer, primary_key=True, autoincrement=True)
    occurred_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)

    actor_id    = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    actor_name  = Column(String(120), nullable=True)

    action      = Column(String(64), nullable=False, index=True)
    target_type = Column(String(32), nullable=True)
    target_id   = Column(String(64), nullable=True)

    event_meta  = Column("metadata", JSONB, nullable=True)
    ip_address  = Column(String(45), nullable=True)

    def to_dict(self) -> dict:
        return {
            "id":          self.id,
            "occurred_at": self.occurred_at.isoformat() if self.occurred_at else None,
            "actor_id":    self.actor_id,
            "actor_name":  self.actor_name,
            "action":      self.action,
            "target_type": self.target_type,
            "target_id":   self.target_id,
            "metadata":    self.event_meta,
            "ip_address":  self.ip_address,
        }
