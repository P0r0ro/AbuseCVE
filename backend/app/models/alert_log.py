"""Alert Log model – tracks every alert email sent."""

from __future__ import annotations

from datetime import datetime
from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Text, Boolean
from app.database import Base


class AlertLog(Base):
    __tablename__ = "alert_logs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    cve_id = Column(String(30), ForeignKey("cves.cve_id"), nullable=False, index=True)
    sent_at = Column(DateTime, default=datetime.utcnow)
    recipient = Column(String(500), nullable=True)
    status = Column(String(20), default="sent")  # sent, failed, stored (no rule match)
    error_message = Column(Text, nullable=True)
    filter_rule_id = Column(Integer, ForeignKey("filter_rules.id"), nullable=True)
    rule_name = Column(String(255), nullable=True)   # which filter triggered the alert
    is_new_cve = Column(Boolean, nullable=True)       # True = brand new CVE, False = duplicate/update

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
        }
