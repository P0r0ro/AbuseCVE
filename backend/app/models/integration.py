"""Integration model – stores webhook/CRM configurations for alert dispatch."""

from __future__ import annotations

from datetime import datetime
from sqlalchemy import Column, Integer, String, Text, Boolean, DateTime, JSON
from app.database import Base


class Integration(Base):
    __tablename__ = "integrations"

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(255), nullable=False)
    type = Column(String(50), nullable=False, default="webhook")  # webhook, ms_crm, jira, custom
    url = Column(String(1024), nullable=False)
    method = Column(String(10), default="POST")  # POST, PUT
    headers = Column(JSON, nullable=True, default=dict)  # Custom headers
    auth_type = Column(String(50), nullable=True)  # none, bearer, basic, api_key
    auth_token = Column(String(1024), nullable=True)  # Bearer token or API key
    payload_template = Column(Text, nullable=True)  # Custom JSON template
    enabled = Column(Boolean, default=True)
    last_used = Column(DateTime, nullable=True)
    last_status = Column(String(20), nullable=True)  # success, failed
    last_error = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def to_dict(self):
        return {
            "id": self.id,
            "name": self.name,
            "type": self.type,
            "url": self.url,
            "method": self.method,
            "headers": self.headers or {},
            "auth_type": self.auth_type,
            "auth_token": f"***{self.auth_token[-4:]}" if self.auth_token and len(self.auth_token) > 4 else ("***" if self.auth_token else None),
            "payload_template": self.payload_template,
            "enabled": self.enabled,
            "last_used": self.last_used.isoformat() if self.last_used else None,
            "last_status": self.last_status,
            "last_error": self.last_error,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }
