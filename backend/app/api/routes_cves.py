"""CVE Database API routes – search, list, detail."""

from __future__ import annotations

import logging
from fastapi import APIRouter, Depends, Query, BackgroundTasks
from pydantic import BaseModel
from typing import Optional, List, Dict, Any
from sqlalchemy import select, func, desc, asc, update, or_, and_
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.cve import CVE
from app.engine.query_engine import condition_to_sql_filter, parse_pql_to_conditions

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


@router.get("/diagnostics/missing-vendor-product")
async def diagnose_missing_vendor_product(
    db: AsyncSession = Depends(get_db),
):
    """Diagnose why vendor/product fields are missing — shows what data is available."""
    from sqlalchemy import text

    # Count totals
    total = (await db.execute(select(func.count()).select_from(CVE))).scalar() or 0
    missing_vendor = (await db.execute(
        select(func.count()).select_from(CVE).where(CVE.vendor.is_(None))
    )).scalar() or 0
    missing_product = (await db.execute(
        select(func.count()).select_from(CVE).where(CVE.product.is_(None))
    )).scalar() or 0
    missing_both = (await db.execute(
        select(func.count()).select_from(CVE).where(
            and_(CVE.vendor.is_(None), CVE.product.is_(None))
        )
    )).scalar() or 0

    # Breakdown by source
    source_breakdown = (await db.execute(
        select(CVE.source, func.count()).where(
            or_(CVE.vendor.is_(None), CVE.product.is_(None))
        ).group_by(CVE.source)
    )).all()

    # Sample 10 CVEs missing vendor/product — show what data they DO have
    sample_result = await db.execute(
        select(
            CVE.cve_id, CVE.source, CVE.sources, CVE.vendor, CVE.product,
            CVE.cpe_names, CVE.affected_products, CVE.description,
        ).where(
            or_(CVE.vendor.is_(None), CVE.product.is_(None))
        ).limit(10)
    )
    samples = []
    for row in sample_result.all():
        samples.append({
            "cve_id": row[0],
            "source": row[1],
            "sources": row[2],
            "vendor": row[3],
            "product": row[4],
            "has_cpe_names": bool(row[5]) and len(row[5]) > 0 if row[5] else False,
            "cpe_names_count": len(row[5]) if row[5] else 0,
            "cpe_sample": (row[5] or [])[:3],
            "has_affected_products": bool(row[6]) and len(row[6]) > 0 if row[6] else False,
            "affected_products_sample": (row[6] or [])[:3],
            "description_preview": (row[7] or "")[:200],
        })

    # Check how many have raw_json with useful data
    has_raw_json = (await db.execute(
        select(func.count()).select_from(CVE).where(
            and_(
                or_(CVE.vendor.is_(None), CVE.product.is_(None)),
                CVE.raw_json.isnot(None),
            )
        )
    )).scalar() or 0

    has_cpe = (await db.execute(
        select(func.count()).select_from(CVE).where(
            and_(
                or_(CVE.vendor.is_(None), CVE.product.is_(None)),
                CVE.cpe_names.isnot(None),
                func.json_array_length(CVE.cpe_names) > 0,
            )
        )
    )).scalar() or 0

    has_affected = (await db.execute(
        select(func.count()).select_from(CVE).where(
            and_(
                or_(CVE.vendor.is_(None), CVE.product.is_(None)),
                CVE.affected_products.isnot(None),
                func.json_array_length(CVE.affected_products) > 0,
            )
        )
    )).scalar() or 0

    return {
        "total_cves": total,
        "missing_vendor": missing_vendor,
        "missing_product": missing_product,
        "missing_both": missing_both,
        "by_source": {row[0]: row[1] for row in source_breakdown},
        "data_availability": {
            "has_raw_json": has_raw_json,
            "has_cpe_names": has_cpe,
            "has_affected_products": has_affected,
            "has_none_of_above": missing_both - has_cpe - has_affected,
        },
        "samples": samples,
    }


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


class PQLSearchRequest(BaseModel):
    """Search CVEs using PQL (Policy Query Language)."""
    pql: str
    page: int = 1
    per_page: int = 50
    sort_by: str = "published_date"
    sort_order: str = "desc"


@router.post("/search/pql")
async def pql_search(
    data: PQLSearchRequest,
    db: AsyncSession = Depends(get_db),
):
    """Search CVEs using PQL (Policy Query Language).

    Examples:
      vendor:fortinet AND severity:CRITICAL,HIGH
      (vendor:~"(?i)forti" OR description:~"(?i)fortinet") AND cvss:>=7.0
      kev:true AND NOT severity:LOW
    """
    if not data.pql.strip():
        return {"error": "PQL query cannot be empty", "cves": [], "total": 0}

    # Parse PQL to conditions dict
    try:
        conditions = parse_pql_to_conditions(data.pql)
        if not conditions:
            return {"error": "PQL query parsed to empty conditions", "cves": [], "total": 0}
    except Exception as e:
        logger.error(f"PQL parse failed: {e}")
        return {"error": f"Invalid PQL syntax: {str(e)}", "cves": [], "total": 0}

    # Translate to SQL
    base_query = select(CVE)
    try:
        sql_filter = condition_to_sql_filter(CVE, conditions)
        if sql_filter is not None:
            base_query = base_query.where(sql_filter)
    except Exception as e:
        logger.error(f"PQL to SQL translation failed: {e}")
        return {"error": f"Query translation error: {str(e)}", "cves": [], "total": 0}

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
        "pql": data.pql,
        "parsed_conditions": conditions,
    }


@router.post("/backfill-vendor-product")
async def backfill_vendor_product(
    batch_size: int = Query(500, ge=100, le=5000),
    db: AsyncSession = Depends(get_db),
):
    """Backfill missing vendor/product fields for existing CVEs.

    Processes CVEs that have NULL vendor or product and attempts to extract
    them from cpe_names, affected_products, and raw_json data.
    """
    from app.engine.vendor_product_extractor import extract_vendor_product

    # Count how many need backfill
    count_result = await db.execute(
        select(func.count()).select_from(
            select(CVE.id).where(
                or_(CVE.vendor.is_(None), CVE.product.is_(None))
            ).subquery()
        )
    )
    total_missing = count_result.scalar() or 0

    if total_missing == 0:
        return {"status": "ok", "message": "All CVEs already have vendor/product", "updated": 0}

    # Process in batches
    updated_count = 0
    offset = 0

    while offset < total_missing:
        result = await db.execute(
            select(CVE)
            .where(or_(CVE.vendor.is_(None), CVE.product.is_(None)))
            .limit(batch_size)
            .offset(0)  # Always 0 because we update as we go
        )
        cves = result.scalars().all()
        if not cves:
            break

        batch_updated = 0
        for cve in cves:
            new_vendor, new_product = extract_vendor_product(
                vendor=cve.vendor,
                product=cve.product,
                cpe_names=cve.cpe_names,
                affected_products=cve.affected_products,
                raw_json=cve.raw_json,
                source=cve.source,
                sources=cve.sources,
            )

            updates = {}
            if new_vendor and not cve.vendor:
                updates["vendor"] = new_vendor
            if new_product and not cve.product:
                updates["product"] = new_product

            if updates:
                await db.execute(
                    update(CVE).where(CVE.id == cve.id).values(**updates)
                )
                batch_updated += 1

        await db.commit()
        updated_count += batch_updated
        offset += batch_size
        logger.info(f"Vendor/product backfill: {updated_count} updated so far ({offset}/{total_missing} processed)")

        # If no more CVEs to process (all remaining ones couldn't be backfilled)
        if not cves or len(cves) < batch_size:
            break

    # Final count of still-missing
    remaining_result = await db.execute(
        select(func.count()).select_from(
            select(CVE.id).where(
                and_(CVE.vendor.is_(None), CVE.product.is_(None))
            ).subquery()
        )
    )
    still_missing_both = remaining_result.scalar() or 0

    return {
        "status": "ok",
        "total_missing_before": total_missing,
        "updated": updated_count,
        "still_missing_both": still_missing_both,
        "message": f"Backfilled {updated_count} CVEs. {still_missing_both} still missing both vendor and product.",
    }
