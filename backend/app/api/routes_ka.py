"""Knowledge Articles API routes – human-composed vulnerability reports."""

from __future__ import annotations

import logging
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import Response
from pydantic import BaseModel
from typing import List, Optional
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.knowledge_article import KnowledgeArticle
from app.services.ka_service import (
    save_knowledge_article,
    update_knowledge_article,
    get_cves_by_ids,
    render_existing_ka,
    render_report_html,
    render_report_html_dark,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/knowledge-articles", tags=["Knowledge Articles"])


# ── Request Models ────────────────────────────────────────

class CategoryData(BaseModel):
    name: str = ""
    component: str = ""
    cve_ids: List[str] = []
    analysis: str = ""


class KASaveRequest(BaseModel):
    """Full wizard payload for creating/updating a KA."""
    title: str
    cve_ids: List[str]
    severity: str = ""
    poc_available: bool = False
    user_interaction: bool = False
    is_batch: bool = False
    categories: List[CategoryData] = []
    mitigation: str = ""
    references: List[str] = []
    author: str = "Analyst"


class KAUpdateRequest(BaseModel):
    """Partial update — same as KASaveRequest but all optional."""
    title: Optional[str] = None
    cve_ids: Optional[List[str]] = None
    severity: Optional[str] = None
    poc_available: Optional[bool] = None
    user_interaction: Optional[bool] = None
    is_batch: Optional[bool] = None
    categories: Optional[List[CategoryData]] = None
    mitigation: Optional[str] = None
    references: Optional[List[str]] = None
    author: Optional[str] = None
    status: Optional[str] = None


class CVELookupRequest(BaseModel):
    cve_ids: List[str]


class PreviewRequest(BaseModel):
    """Preview without saving."""
    title: str = "Vulnerability Report"
    cve_ids: List[str] = []
    severity: str = ""
    poc_available: bool = False
    user_interaction: bool = False
    is_batch: bool = False
    categories: List[CategoryData] = []
    mitigation: str = ""
    references: List[str] = []


# ── Routes ────────────────────────────────────────────────

@router.get("")
async def list_kas(db: AsyncSession = Depends(get_db)):
    """List all saved Knowledge Articles."""
    result = await db.execute(
        select(KnowledgeArticle).order_by(KnowledgeArticle.created_at.desc())
    )
    return [ka.to_dict() for ka in result.scalars().all()]


@router.get("/{ka_id}")
async def get_ka(ka_id: int, db: AsyncSession = Depends(get_db)):
    """Get a single KA with rendered HTML."""
    ka_dict = await render_existing_ka(db, ka_id)
    if not ka_dict:
        raise HTTPException(status_code=404, detail="Knowledge Article not found")
    return ka_dict


@router.post("", status_code=201)
async def create_ka(data: KASaveRequest, db: AsyncSession = Depends(get_db)):
    """Create a new Knowledge Article from the wizard."""
    payload = data.model_dump()
    # Convert CategoryData to dicts
    payload["categories"] = [c.model_dump() for c in data.categories]
    result = await save_knowledge_article(db, payload)
    return result


@router.put("/{ka_id}")
async def update_ka(ka_id: int, data: KAUpdateRequest, db: AsyncSession = Depends(get_db)):
    """Update an existing KA."""
    # If full report_data update (categories present), re-render
    update_data = data.model_dump(exclude_unset=True)
    if "categories" in update_data and update_data["categories"] is not None:
        update_data["categories"] = [
            c.model_dump() if hasattr(c, "model_dump") else c
            for c in data.categories
        ]

    # Check if this is a full wizard update or partial field update
    if "categories" in update_data:
        # Full re-render: merge with existing report_data
        result = await db.execute(
            select(KnowledgeArticle).where(KnowledgeArticle.id == ka_id)
        )
        ka = result.scalar_one_or_none()
        if not ka:
            raise HTTPException(status_code=404, detail="Knowledge Article not found")

        existing = ka.report_data or {}
        existing.update(update_data)
        result_dict = await update_knowledge_article(db, ka_id, existing)
    else:
        # Simple field update (e.g., status change)
        result = await db.execute(
            select(KnowledgeArticle).where(KnowledgeArticle.id == ka_id)
        )
        ka = result.scalar_one_or_none()
        if not ka:
            raise HTTPException(status_code=404, detail="Knowledge Article not found")
        for key, value in update_data.items():
            setattr(ka, key, value)
        await db.flush()
        result_dict = ka.to_dict()

    if "error" in result_dict:
        raise HTTPException(status_code=404, detail=result_dict["error"])
    return result_dict


@router.delete("/{ka_id}")
async def delete_ka(ka_id: int, db: AsyncSession = Depends(get_db)):
    """Delete a KA."""
    result = await db.execute(
        select(KnowledgeArticle).where(KnowledgeArticle.id == ka_id)
    )
    ka = result.scalar_one_or_none()
    if not ka:
        raise HTTPException(status_code=404, detail="Knowledge Article not found")
    await db.delete(ka)
    return {"message": "Knowledge Article deleted"}


@router.post("/preview")
async def preview_report(data: PreviewRequest):
    """Render a report preview without saving to the database."""
    payload = data.model_dump()
    payload["categories"] = [c.model_dump() for c in data.categories]
    return {
        "html_content": render_report_html(payload),
        "preview_html": render_report_html_dark(payload),
    }


@router.post("/lookup-cves")
async def lookup_cves(data: CVELookupRequest, db: AsyncSession = Depends(get_db)):
    """Look up CVE details for populating the wizard form."""
    cves = await get_cves_by_ids(db, data.cve_ids)
    found_ids = {c["cve_id"] for c in cves}
    missing = [cid for cid in data.cve_ids if cid not in found_ids]
    return {"cves": cves, "missing": missing}


@router.get("/{ka_id}/export")
async def export_ka(ka_id: int, db: AsyncSession = Depends(get_db)):
    """Export a KA as an HTML file preserving fonts."""
    ka_dict = await render_existing_ka(db, ka_id)
    if not ka_dict:
        raise HTTPException(status_code=404, detail="Knowledge Article not found")

    html_content = ka_dict.get("html_content", "")

    # Wrap in full HTML document for standalone viewing
    full_html = f"""<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>{ka_dict.get('title', 'Vulnerability Report')}</title>
<style>
body {{ margin: 20px; background: #fff; }}
</style>
</head>
<body>
{html_content}
</body>
</html>"""

    cve_tag = ka_dict["cve_ids"][0] if ka_dict.get("cve_ids") else "report"
    filename = f"KA_{cve_tag}_{ka_id}.html"

    return Response(
        content=full_html,
        media_type="text/html",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )
