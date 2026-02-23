"""CVE model – stores every tracked CVE record."""

from __future__ import annotations

from datetime import datetime
from sqlalchemy import (
    Column, Integer, String, Text, Float, Boolean, DateTime, JSON, Index
)
from app.database import Base


class CVE(Base):
    __tablename__ = "cves"

    id = Column(Integer, primary_key=True, autoincrement=True)
    cve_id = Column(String(30), unique=True, nullable=False, index=True)  # e.g. CVE-2024-12345
    vendor = Column(String(255), nullable=True, index=True)
    product = Column(String(255), nullable=True, index=True)
    description = Column(Text, nullable=True)
    severity = Column(String(20), nullable=True)  # LOW, MEDIUM, HIGH, CRITICAL
    cvss_score = Column(Float, nullable=True)
    cvss_vector = Column(String(255), nullable=True)
    source = Column(String(50), nullable=True)  # NVD, CISA_KEV, MITRE
    published_date = Column(DateTime, nullable=True)
    modified_date = Column(DateTime, nullable=True)
    kev_flag = Column(Boolean, default=False)  # in CISA KEV catalog
    seen_count = Column(Integer, default=1)
    first_seen = Column(DateTime, default=datetime.utcnow)
    last_seen = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    alert_sent = Column(Boolean, default=False)
    cpe_names = Column(JSON, nullable=True)  # list of CPE strings
    references = Column(JSON, nullable=True)  # list of reference URLs
    raw_json = Column(JSON, nullable=True)

    __table_args__ = (
        Index("ix_cves_vendor_product", "vendor", "product"),
        Index("ix_cves_severity", "severity"),
        Index("ix_cves_cvss", "cvss_score"),
        Index("ix_cves_published", "published_date"),
    )

    def to_dict(self):
        return {
            "id": self.id,
            "cve_id": self.cve_id,
            "vendor": self.vendor,
            "product": self.product,
            "description": self.description,
            "severity": self.severity,
            "cvss_score": self.cvss_score,
            "cvss_vector": self.cvss_vector,
            "source": self.source,
            "published_date": self.published_date.isoformat() if self.published_date else None,
            "modified_date": self.modified_date.isoformat() if self.modified_date else None,
            "kev_flag": self.kev_flag,
            "seen_count": self.seen_count,
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
            "alert_sent": self.alert_sent,
            "references": self.references,
        }
