"""Knowledge Articles API routes."""

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
from app.services.ka_service import create_knowledge_article, generate_ka_for_cve, generate_batch_ka, check_ai_keys_status

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/knowledge-articles", tags=["Knowledge Articles"])


class KACreate(BaseModel):
    title: str
    cve_ids: List[str]
    content: Optional[str] = None
    summary: Optional[str] = None
    recommendations: Optional[str] = None
    author: Optional[str] = None


class KAUpdate(BaseModel):
    title: Optional[str] = None
    content: Optional[str] = None
    summary: Optional[str] = None
    recommendations: Optional[str] = None
    status: Optional[str] = None


class GenerateKARequest(BaseModel):
    ai_provider: Optional[str] = "auto"  # "mistral", "gemini", "template", "auto"


class BatchGenerateKARequest(BaseModel):
    cve_ids: List[str]
    ai_provider: Optional[str] = "auto"


@router.get("/ai-status")
async def ai_status():
    """Check which AI providers have API keys configured."""
    return check_ai_keys_status()


@router.get("")
async def list_kas(db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(KnowledgeArticle).order_by(KnowledgeArticle.created_at.desc())
    )
    return [ka.to_dict() for ka in result.scalars().all()]


@router.get("/{ka_id}")
async def get_ka(ka_id: int, db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(KnowledgeArticle).where(KnowledgeArticle.id == ka_id)
    )
    ka = result.scalar_one_or_none()
    if not ka:
        raise HTTPException(status_code=404, detail="Knowledge Article not found")
    return ka.to_dict()


@router.post("", status_code=201)
async def create_ka(data: KACreate, db: AsyncSession = Depends(get_db)):
    result = await create_knowledge_article(
        session=db,
        title=data.title,
        cve_ids=data.cve_ids,
        content=data.content,
        summary=data.summary,
        recommendations=data.recommendations,
        author=data.author,
    )
    return result


@router.post("/generate/{cve_id}", status_code=201)
async def generate_ka(
    cve_id: str,
    data: Optional[GenerateKARequest] = None,
    db: AsyncSession = Depends(get_db),
):
    """Auto-generate a Knowledge Article for a specific CVE.

    Uses AI (Mistral or Gemini) if configured, falls back to template.
    """
    provider = data.ai_provider if data else "auto"
    try:
        result = await generate_ka_for_cve(
            session=db,
            cve_id=cve_id,
            ai_provider=provider,
        )
        if "error" in result:
            raise HTTPException(status_code=404, detail=result["error"])
        return result
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"KA generation failed for {cve_id}: {e}")
        raise HTTPException(status_code=500, detail=f"Generation failed: {str(e)}")


@router.post("/generate-batch", status_code=201)
async def generate_batch(
    data: BatchGenerateKARequest,
    db: AsyncSession = Depends(get_db),
):
    """Generate a batch Knowledge Article for multiple CVEs.

    Useful for vendor batch releases (e.g., Cisco semi-annual patches).
    Groups related CVEs into one consolidated report.
    """
    if not data.cve_ids:
        raise HTTPException(status_code=400, detail="No CVE IDs provided")
    if len(data.cve_ids) > 50:
        raise HTTPException(status_code=400, detail="Maximum 50 CVEs per batch")

    try:
        result = await generate_batch_ka(
            session=db,
            cve_ids=data.cve_ids,
            ai_provider=data.ai_provider or "auto",
        )
        if "error" in result:
            raise HTTPException(status_code=404, detail=result["error"])
        return result
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Batch KA generation failed: {e}")
        raise HTTPException(status_code=500, detail=f"Batch generation failed: {str(e)}")


@router.put("/{ka_id}")
async def update_ka(ka_id: int, data: KAUpdate, db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(KnowledgeArticle).where(KnowledgeArticle.id == ka_id)
    )
    ka = result.scalar_one_or_none()
    if not ka:
        raise HTTPException(status_code=404, detail="Knowledge Article not found")

    update_data = data.model_dump(exclude_unset=True)
    for key, value in update_data.items():
        setattr(ka, key, value)

    await db.flush()
    return ka.to_dict()


@router.delete("/{ka_id}")
async def delete_ka(ka_id: int, db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(KnowledgeArticle).where(KnowledgeArticle.id == ka_id)
    )
    ka = result.scalar_one_or_none()
    if not ka:
        raise HTTPException(status_code=404, detail="Knowledge Article not found")
    await db.delete(ka)
    return {"message": "Knowledge Article deleted"}


@router.get("/{ka_id}/export")
async def export_ka(ka_id: int, db: AsyncSession = Depends(get_db)):
    """Export a Knowledge Article as a text document."""
    result = await db.execute(
        select(KnowledgeArticle).where(KnowledgeArticle.id == ka_id)
    )
    ka = result.scalar_one_or_none()
    if not ka:
        raise HTTPException(status_code=404, detail="Knowledge Article not found")

    content = ka.content or "No content available."
    filename = f"KA_{ka.cve_ids[0] if ka.cve_ids else 'report'}_{ka.id}.txt"

    return Response(
        content=content,
        media_type="text/plain",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )
