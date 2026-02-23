"""Filter Rule model – defines vendor/product filters for CVE monitoring."""

from __future__ import annotations

from datetime import datetime
from sqlalchemy import Column, Integer, String, Boolean, Float, DateTime, JSON, Text
from app.database import Base


class FilterRule(Base):
    __tablename__ = "filter_rules"

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(255), nullable=False)
    vendor = Column(String(255), nullable=False, index=True)
    products = Column(JSON, nullable=False, default=list)  # ["FortiGate", "FortiEDR", ...]
    enabled = Column(Boolean, default=True)
    min_cvss = Column(Float, nullable=True)  # minimum CVSS score to alert on
    max_cvss = Column(Float, nullable=True)
    severity_filter = Column(JSON, nullable=True, default=list)  # ["HIGH", "CRITICAL"]
    keywords_include = Column(JSON, nullable=True, default=list)  # keywords that MUST appear
    keywords_exclude = Column(JSON, nullable=True, default=list)  # keywords to EXCLUDE
    cpe_vendor = Column(String(255), nullable=True)  # CPE vendor string (e.g. "fortinet")
    description = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def to_dict(self):
        return {
            "id": self.id,
            "name": self.name,
            "vendor": self.vendor,
            "products": self.products or [],
            "enabled": self.enabled,
            "min_cvss": self.min_cvss,
            "max_cvss": self.max_cvss,
            "severity_filter": self.severity_filter or [],
            "keywords_include": self.keywords_include or [],
            "keywords_exclude": self.keywords_exclude or [],
            "cpe_vendor": self.cpe_vendor,
            "description": self.description,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }
