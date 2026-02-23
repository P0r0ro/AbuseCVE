"""CVE database API routes – search, browse, and detail views."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from typing import Optional
from sqlalchemy import select, func, or_
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.cve import CVE

router = APIRouter(prefix="/api/cves", tags=["CVEs"])


@router.get("")
async def list_cves(
    page: int = Query(1, ge=1),
    per_page: int = Query(50, ge=1, le=200),
    vendor: Optional[str] = None,
    product: Optional[str] = None,
    severity: Optional[str] = None,
    min_cvss: Optional[float] = None,
    max_cvss: Optional[float] = None,
    kev_only: bool = False,
    search: Optional[str] = None,
    sort_by: str = "published_date",
    sort_order: str = "desc",
    db: AsyncSession = Depends(get_db),
):
    """List CVEs with filtering, pagination, and sorting."""
    query = select(CVE)

    # Filters
    if vendor:
        query = query.where(CVE.vendor.ilike(f"%{vendor}%"))
    if product:
        query = query.where(CVE.product.ilike(f"%{product}%"))
    if severity:
        query = query.where(CVE.severity == severity.upper())
    if min_cvss is not None:
        query = query.where(CVE.cvss_score >= min_cvss)
    if max_cvss is not None:
        query = query.where(CVE.cvss_score <= max_cvss)
    if kev_only:
        query = query.where(CVE.kev_flag == True)
    if search:
        query = query.where(
            or_(
                CVE.cve_id.ilike(f"%{search}%"),
                CVE.description.ilike(f"%{search}%"),
                CVE.vendor.ilike(f"%{search}%"),
                CVE.product.ilike(f"%{search}%"),
            )
        )

    # Count
    count_query = select(func.count()).select_from(query.subquery())
    total_result = await db.execute(count_query)
    total = total_result.scalar() or 0

    # Sort
    sort_column = getattr(CVE, sort_by, CVE.published_date)
    if sort_order == "asc":
        query = query.order_by(sort_column.asc())
    else:
        query = query.order_by(sort_column.desc())

    # Paginate
    offset = (page - 1) * per_page
    query = query.offset(offset).limit(per_page)

    result = await db.execute(query)
    cves = result.scalars().all()

    return {
        "items": [c.to_dict() for c in cves],
        "total": total,
        "page": page,
        "per_page": per_page,
        "pages": (total + per_page - 1) // per_page,
    }


@router.get("/stats")
async def cve_stats(db: AsyncSession = Depends(get_db)):
    """Get CVE database statistics."""
    total = (await db.execute(select(func.count()).select_from(CVE))).scalar() or 0
    kev_count = (await db.execute(
        select(func.count()).select_from(CVE).where(CVE.kev_flag == True)
    )).scalar() or 0

    severity_result = await db.execute(
        select(CVE.severity, func.count()).group_by(CVE.severity)
    )
    severity_counts = {row[0] or "UNKNOWN": row[1] for row in severity_result.all()}

    vendor_result = await db.execute(
        select(CVE.vendor, func.count())
        .where(CVE.vendor.isnot(None))
        .group_by(CVE.vendor)
        .order_by(func.count().desc())
        .limit(20)
    )
    top_vendors = [{"vendor": row[0], "count": row[1]} for row in vendor_result.all()]

    return {
        "total_cves": total,
        "kev_count": kev_count,
        "severity_counts": severity_counts,
        "top_vendors": top_vendors,
    }


@router.get("/{cve_id}")
async def get_cve(cve_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(CVE).where(CVE.cve_id == cve_id))
    cve = result.scalar_one_or_none()
    if not cve:
        raise HTTPException(status_code=404, detail="CVE not found")
    return cve.to_dict()
