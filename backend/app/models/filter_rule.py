"""Filter Rule model – defines vendor/product filters for CVE monitoring."""

from __future__ import annotations

from datetime import datetime
from sqlalchemy import Column, Integer, String, Boolean, Float, DateTime, JSON, Text
from app.database import Base


class FilterRule(Base):
    __tablename__ = "filter_rules"

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(255), nullable=False)
    vendor = Column(String(255), nullable=True, index=True)  # Made nullable for advanced mode
    products = Column(JSON, nullable=False, default=list)  # ["FortiGate", "FortiEDR", ...]
    enabled = Column(Boolean, default=True)
    min_cvss = Column(Float, nullable=True)  # minimum CVSS score to alert on
    max_cvss = Column(Float, nullable=True)
    severity_filter = Column(JSON, nullable=True, default=list)  # ["HIGH", "CRITICAL"]
    keywords_include = Column(JSON, nullable=True, default=list)  # keywords that MUST appear
    keywords_exclude = Column(JSON, nullable=True, default=list)  # keywords to EXCLUDE
    cpe_vendor = Column(String(255), nullable=True)  # CPE vendor string (e.g. "fortinet")
    description = Column(Text, nullable=True)
    alert_on_modified = Column(Boolean, default=False)  # Alert when CVE is updated/modified
    conditions = Column(JSON, nullable=True)  # Advanced query conditions (nested)
    severity_mapping = Column(JSON, nullable=True)  # {"low": [0, 3], "medium": [3, 7], "high": [7, 10], "critical": [9, 10]}
    include_unknown = Column(Boolean, default=False)  # Include CVEs without CVSS scores
    pql_query = Column(Text, nullable=True)  # Raw PQL query string for PQL mode
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
            "alert_on_modified": self.alert_on_modified,
            "conditions": self.conditions,
            "severity_mapping": self.severity_mapping,
            "include_unknown": self.include_unknown,
            "pql_query": self.pql_query,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }
