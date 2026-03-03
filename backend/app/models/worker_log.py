"""Worker Log model – stores structured logs from Celery workers."""

from __future__ import annotations

from datetime import datetime
from sqlalchemy import Column, Integer, String, Text, DateTime, Index
from app.database import Base


class WorkerLog(Base):
    __tablename__ = "worker_logs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    worker_type = Column(String(50), nullable=False, index=True)  # cve_scan, init, health, alert, system
    level = Column(String(20), nullable=False, default="INFO")  # DEBUG, INFO, WARNING, ERROR
    message = Column(Text, nullable=False)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    task_id = Column(String(255), nullable=True)
    details = Column(Text, nullable=True)  # Extra context, JSON string, traceback, etc.

    __table_args__ = (
        Index("ix_worker_logs_type_ts", "worker_type", "timestamp"),
    )

    def to_dict(self):
        return {
            "id": self.id,
            "worker_type": self.worker_type,
            "level": self.level,
            "message": self.message,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "task_id": self.task_id,
            "details": self.details,
        }
