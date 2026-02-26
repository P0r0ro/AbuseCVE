"""CVE Database API routes – search, list, detail."""

from __future__ import annotations

import logging
from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
from typing import Optional, List, Dict, Any
from sqlalchemy import select, func, desc, asc
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.cve import CVE
from app.engine.query_engine import condition_to_sql_filter

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/cves", tags=["CVEs"])


@router.get("")
async def list_cves(
    page: int = Query(1, ge=1),
    per_page: int = Query(50, ge=1, le=500),
    sort_by: str = Query("published_date"),
    sort_order: str = Query("desc"),
    severity: Optional[str] = None,
    vendor: Optional[str] = None,
    product: Optional[str] = None,
    search: Optional[str] = None,
    source: Optional[str] = None,
    kev_only: bool = False,
    db: AsyncSession = Depends(get_db),
):
    """List CVEs with filtering and pagination."""
    query = select(CVE)

    # Basic filters
    if severity:
        # Support comma-separated severities
        sev_list = [s.strip().upper() for s in severity.split(",")]
        query = query.where(CVE.severity.in_(sev_list))

    if vendor:
        query = query.where(CVE.vendor.ilike(f"%{vendor}%"))

    if product:
        query = query.where(CVE.product.ilike(f"%{product}%"))

    if source:
        query = query.where(CVE.source == source)

    if kev_only:
        query = query.where(CVE.kev_flag == True)

    if search:
        search_pattern = f"%{search}%"
        from sqlalchemy import or_
        query = query.where(
            or_(
                CVE.cve_id.ilike(search_pattern),
                CVE.vendor.ilike(search_pattern),
                CVE.product.ilike(search_pattern),
                CVE.description.ilike(search_pattern),
            )
        )

    # Count
    count_query = select(func.count()).select_from(query.subquery())
    total = (await db.execute(count_query)).scalar() or 0

    # Sort
    sort_column = getattr(CVE, sort_by, CVE.published_date)
    if sort_order == "asc":
        query = query.order_by(asc(sort_column))
    else:
        query = query.order_by(desc(sort_column))

    # Paginate
    query = query.offset((page - 1) * per_page).limit(per_page)

    result = await db.execute(query)
    cves = [c.to_dict() for c in result.scalars().all()]

    return {
        "cves": cves,
        "total": total,
        "page": page,
        "per_page": per_page,
        "pages": (total + per_page - 1) // per_page if per_page else 0,
    }


@router.get("/{cve_id}")
async def get_cve(cve_id: str, db: AsyncSession = Depends(get_db)):
    """Get detailed CVE information."""
    result = await db.execute(select(CVE).where(CVE.cve_id == cve_id))
    cve = result.scalar_one_or_none()
    if not cve:
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail=f"CVE {cve_id} not found")
    return cve.to_dict()


class AdvancedSearchRequest(BaseModel):
    """Advanced search using the query engine."""
    query: Dict[str, Any]
    page: int = 1
    per_page: int = 50
    sort_by: str = "published_date"
    sort_order: str = "desc"


@router.post("/search")
async def advanced_search(
    data: AdvancedSearchRequest,
    db: AsyncSession = Depends(get_db),
):
    """Advanced CVE search using the query engine.

    Supports all operators: equal, not_equal, contains, not_contains,
    blank, not_blank, starts_with, ends_with, regex, wildcards, nested queries.
    """
    base_query = select(CVE)

    # Translate query conditions to SQL
    try:
        sql_filter = condition_to_sql_filter(CVE, data.query)
        if sql_filter is not None:
            base_query = base_query.where(sql_filter)
    except Exception as e:
        logger.error(f"Query translation failed: {e}")
        return {
            "error": f"Invalid query: {str(e)}",
            "cves": [],
            "total": 0,
        }

    # Count
    count_query = select(func.count()).select_from(base_query.subquery())
    total = (await db.execute(count_query)).scalar() or 0

    # Sort
    sort_column = getattr(CVE, data.sort_by, CVE.published_date)
    if data.sort_order == "asc":
        base_query = base_query.order_by(asc(sort_column))
    else:
        base_query = base_query.order_by(desc(sort_column))

    # Paginate
    base_query = base_query.offset((data.page - 1) * data.per_page).limit(data.per_page)

    result = await db.execute(base_query)
    cves = [c.to_dict() for c in result.scalars().all()]

    return {
        "cves": cves,
        "total": total,
        "page": data.page,
        "per_page": data.per_page,
        "pages": (total + data.per_page - 1) // data.per_page if data.per_page else 0,
    }
