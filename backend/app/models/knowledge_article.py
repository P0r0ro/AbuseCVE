"""Knowledge Article model – human-composed vulnerability reports.

Supports both single-CVE and batch (multi-CVE) reports with structured
category groupings, analyst-provided analysis, and CRM-ready formatting.
"""

from __future__ import annotations

from datetime import datetime
from sqlalchemy import Column, Integer, String, Text, DateTime, JSON, Boolean


from app.database import Base


class KnowledgeArticle(Base):
    __tablename__ = "knowledge_articles"

    id = Column(Integer, primary_key=True, autoincrement=True)
    title = Column(String(500), nullable=False)
    cve_ids = Column(JSON, nullable=False, default=list)
    content = Column(Text, nullable=True)           # rendered HTML for CRM
    summary = Column(Text, nullable=True)
    severity_assessment = Column(String(50), nullable=True)  # e.g. "9.8" or "4.3 - 8.6"
    affected_products = Column(JSON, nullable=True)
    recommendations = Column(Text, nullable=True)
    author = Column(String(255), nullable=True)
    status = Column(String(20), default="draft")    # draft, published

    # New structured wizard data
    report_data = Column(JSON, nullable=True)       # full wizard payload
    is_batch = Column(Boolean, default=False)
    poc_available = Column(Boolean, default=False)
    user_interaction = Column(Boolean, default=False)
    categories = Column(JSON, nullable=True)        # list of category dicts
    references = Column(JSON, nullable=True)        # list of reference URLs
    mitigation = Column(Text, nullable=True)

    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def to_dict(self):
        return {
            "id": self.id,
            "title": self.title,
            "cve_ids": self.cve_ids or [],
            "content": self.content,
            "summary": self.summary,
            "severity_assessment": self.severity_assessment,
            "affected_products": self.affected_products or [],
            "recommendations": self.recommendations,
            "author": self.author,
            "status": self.status,
            "report_data": self.report_data,
            "is_batch": self.is_batch,
            "poc_available": self.poc_available,
            "user_interaction": self.user_interaction,
            "categories": self.categories or [],
            "references": self.references or [],
            "mitigation": self.mitigation,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }
