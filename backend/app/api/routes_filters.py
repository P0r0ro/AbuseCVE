"""Filter rules API routes – CRUD for vendor/product monitoring filters."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from typing import List, Optional
from sqlalchemy import select, delete
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.filter_rule import FilterRule

router = APIRouter(prefix="/api/filters", tags=["Filters"])


class FilterRuleCreate(BaseModel):
    name: str
    vendor: str
    products: List[str] = []
    enabled: bool = True
    min_cvss: Optional[float] = None
    max_cvss: Optional[float] = None
    severity_filter: List[str] = []
    keywords_include: List[str] = []
    keywords_exclude: List[str] = []
    cpe_vendor: Optional[str] = None
    description: Optional[str] = None


class FilterRuleUpdate(BaseModel):
    name: Optional[str] = None
    vendor: Optional[str] = None
    products: Optional[List[str]] = None
    enabled: Optional[bool] = None
    min_cvss: Optional[float] = None
    max_cvss: Optional[float] = None
    severity_filter: Optional[List[str]] = None
    keywords_include: Optional[List[str]] = None
    keywords_exclude: Optional[List[str]] = None
    cpe_vendor: Optional[str] = None
    description: Optional[str] = None


@router.get("")
async def list_filters(db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(FilterRule).order_by(FilterRule.created_at.desc()))
    filters = result.scalars().all()
    return [f.to_dict() for f in filters]


@router.get("/{filter_id}")
async def get_filter(filter_id: int, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(FilterRule).where(FilterRule.id == filter_id))
    rule = result.scalar_one_or_none()
    if not rule:
        raise HTTPException(status_code=404, detail="Filter rule not found")
    return rule.to_dict()


@router.post("", status_code=201)
async def create_filter(data: FilterRuleCreate, db: AsyncSession = Depends(get_db)):
    rule = FilterRule(
        name=data.name,
        vendor=data.vendor,
        products=data.products,
        enabled=data.enabled,
        min_cvss=data.min_cvss,
        max_cvss=data.max_cvss,
        severity_filter=data.severity_filter,
        keywords_include=data.keywords_include,
        keywords_exclude=data.keywords_exclude,
        cpe_vendor=data.cpe_vendor,
        description=data.description,
    )
    db.add(rule)
    await db.flush()
    return rule.to_dict()


@router.put("/{filter_id}")
async def update_filter(filter_id: int, data: FilterRuleUpdate, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(FilterRule).where(FilterRule.id == filter_id))
    rule = result.scalar_one_or_none()
    if not rule:
        raise HTTPException(status_code=404, detail="Filter rule not found")

    update_data = data.model_dump(exclude_unset=True)
    for key, value in update_data.items():
        setattr(rule, key, value)

    await db.flush()
    return rule.to_dict()


@router.delete("/{filter_id}")
async def delete_filter(filter_id: int, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(FilterRule).where(FilterRule.id == filter_id))
    rule = result.scalar_one_or_none()
    if not rule:
        raise HTTPException(status_code=404, detail="Filter rule not found")
    await db.delete(rule)
    return {"message": "Filter rule deleted"}


@router.post("/{filter_id}/toggle")
async def toggle_filter(filter_id: int, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(FilterRule).where(FilterRule.id == filter_id))
    rule = result.scalar_one_or_none()
    if not rule:
        raise HTTPException(status_code=404, detail="Filter rule not found")
    rule.enabled = not rule.enabled
    await db.flush()
    return rule.to_dict()
