"""Health Report model – daily system health snapshots."""

from __future__ import annotations

from datetime import datetime
from sqlalchemy import Column, Integer, DateTime, JSON, Text, Boolean
from app.database import Base


class HealthReport(Base):
    __tablename__ = "health_reports"

    id = Column(Integer, primary_key=True, autoincrement=True)
    report_date = Column(DateTime, nullable=False, index=True)
    components_status = Column(JSON, nullable=True)  # {"db": "ok", "redis": "ok", ...}
    new_cves_alerted = Column(Integer, default=0)
    existing_cves_seen = Column(Integer, default=0)
    total_cves_in_db = Column(Integer, default=0)
    active_filters = Column(Integer, default=0)
    errors = Column(JSON, nullable=True, default=list)
    warnings = Column(JSON, nullable=True, default=list)
    report_html = Column(Text, nullable=True)
    sent = Column(Boolean, default=False)
    sent_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            "id": self.id,
            "report_date": self.report_date.isoformat() if self.report_date else None,
            "components_status": self.components_status,
            "new_cves_alerted": self.new_cves_alerted,
            "existing_cves_seen": self.existing_cves_seen,
            "total_cves_in_db": self.total_cves_in_db,
            "active_filters": self.active_filters,
            "errors": self.errors or [],
            "warnings": self.warnings or [],
            "sent": self.sent,
            "sent_at": self.sent_at.isoformat() if self.sent_at else None,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }
