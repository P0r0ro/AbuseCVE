"""Alert Log model – tracks every alert email sent + case-close attribution.

Case-close fields (``closed_by_id``, ``closed_by_name``, ``closed_at``,
``close_notes``) are populated by ``POST /api/alerts/{id}/close``. The
denormalized ``closed_by_name`` survives soft-deletion of the analyst's
account so historical close attribution stays readable in the CRM and
in the Alerts list.
"""

from __future__ import annotations

from datetime import datetime
from sqlalchemy import Column, Integer, String, DateTime, Text, Boolean, ForeignKey
from app.database import Base


class AlertLog(Base):
    __tablename__ = "alert_logs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    cve_id = Column(String(30), nullable=False, index=True)
    sent_at = Column(DateTime, default=datetime.utcnow)
    recipient = Column(String(500), nullable=True)
    # sent | failed | stored | closed
    status = Column(String(20), default="sent")
    error_message = Column(Text, nullable=True)
    filter_rule_id = Column(Integer, nullable=True)
    rule_name = Column(String(255), nullable=True)
    is_new_cve = Column(Boolean, nullable=True)

    # ── Case-close attribution ─────────────────────────────
    closed_by_id   = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    closed_by_name = Column(String(120), nullable=True)
    closed_at      = Column(DateTime, nullable=True)
    close_notes    = Column(Text, nullable=True)

    def to_dict(self):
        return {
            "id": self.id,
            "cve_id": self.cve_id,
            "sent_at": self.sent_at.isoformat() if self.sent_at else None,
            "recipient": self.recipient,
            "status": self.status,
            "error_message": self.error_message,
            "filter_rule_id": self.filter_rule_id,
            "rule_name": self.rule_name,
            "is_new_cve": self.is_new_cve,
            "closed_by_id":   self.closed_by_id,
            "closed_by_name": self.closed_by_name,
            "closed_at":      self.closed_at.isoformat() if self.closed_at else None,
            "close_notes":    self.close_notes,
        }
