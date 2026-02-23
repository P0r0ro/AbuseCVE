"""Knowledge Articles API routes."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from typing import List, Optional
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.knowledge_article import KnowledgeArticle
from app.services.ka_service import create_knowledge_article

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
