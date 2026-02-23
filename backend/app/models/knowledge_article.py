"""Knowledge Article model – CVE analysis reports."""

from __future__ import annotations

from datetime import datetime
from sqlalchemy import Column, Integer, String, Text, DateTime, JSON
from app.database import Base


class KnowledgeArticle(Base):
    __tablename__ = "knowledge_articles"

    id = Column(Integer, primary_key=True, autoincrement=True)
    title = Column(String(500), nullable=False)
    cve_ids = Column(JSON, nullable=False, default=list)  # list of CVE IDs
    content = Column(Text, nullable=True)  # markdown content
    summary = Column(Text, nullable=True)
    severity_assessment = Column(String(20), nullable=True)
    affected_products = Column(JSON, nullable=True)
    recommendations = Column(Text, nullable=True)
    author = Column(String(255), nullable=True)
    status = Column(String(20), default="draft")  # draft, published
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
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }
