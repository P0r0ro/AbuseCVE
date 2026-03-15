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


@router.get("/diagnostics/missing-vendor-product")
async def diagnose_missing_vendor_product(
    db: AsyncSession = Depends(get_db),
):
    """Diagnose why vendor/product fields are missing — shows what data is available."""
    from sqlalchemy import text, cast
    from sqlalchemy.types import Text

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
        select(CVE).where(
            or_(CVE.vendor.is_(None), CVE.product.is_(None))
        ).limit(10)
    )
    samples = []
    for cve in sample_result.scalars().all():
        cpe_list = cve.cpe_names or []
        affected_list = cve.affected_products or []
        raw = cve.raw_json or {}

        # Check what keys raw_json has
        raw_keys = list(raw.keys())[:10] if isinstance(raw, dict) else []

        samples.append({
            "cve_id": cve.cve_id,
            "source": cve.source,
            "sources": cve.sources,
            "vendor": cve.vendor,
            "product": cve.product,
            "cpe_names_count": len(cpe_list),
            "cpe_sample": cpe_list[:3],
            "affected_products_count": len(affected_list),
            "affected_products_sample": affected_list[:3],
            "raw_json_keys": raw_keys,
            "raw_json_has_configurations": "configurations" in raw if isinstance(raw, dict) else False,
            "raw_json_has_affected": bool(raw.get("containers", {}).get("cna", {}).get("affected")) if isinstance(raw, dict) else False,
            "raw_json_has_affected_release": "affected_release" in raw if isinstance(raw, dict) else False,
            "raw_json_has_bugzilla_desc": "bugzilla_description" in raw if isinstance(raw, dict) else False,
            "description_preview": (cve.description or "")[:200],
        })

    # Check how many have raw_json
    has_raw_json = (await db.execute(
        select(func.count()).select_from(CVE).where(
            and_(
                or_(CVE.vendor.is_(None), CVE.product.is_(None)),
                CVE.raw_json.isnot(None),
            )
        )
    )).scalar() or 0

    # Use text() for PostgreSQL-specific JSON queries to avoid ORM issues
    has_cpe = (await db.execute(text(
        "SELECT COUNT(*) FROM cves WHERE (vendor IS NULL OR product IS NULL) "
        "AND cpe_names IS NOT NULL AND cpe_names::text != '[]' AND cpe_names::text != 'null'"
    ))).scalar() or 0

    has_affected = (await db.execute(text(
        "SELECT COUNT(*) FROM cves WHERE (vendor IS NULL OR product IS NULL) "
        "AND affected_products IS NOT NULL AND affected_products::text != '[]' AND affected_products::text != 'null'"
    ))).scalar() or 0

    # Breakdown by vulnStatus in raw_json
    vuln_status_breakdown = (await db.execute(text(
        "SELECT raw_json->>'vulnStatus' as status, COUNT(*) "
        "FROM cves WHERE (vendor IS NULL OR product IS NULL) "
        "GROUP BY raw_json->>'vulnStatus' ORDER BY COUNT(*) DESC"
    ))).all()

    # Count rejected (description starts with 'Rejected reason:')
    rejected_count = (await db.execute(text(
        "SELECT COUNT(*) FROM cves WHERE (vendor IS NULL OR product IS NULL) "
        "AND description LIKE 'Rejected reason:%'"
    ))).scalar() or 0

    # Sample NON-REJECTED CVEs missing vendor/product
    non_rejected_sample = await db.execute(
        select(CVE).where(
            and_(
                or_(CVE.vendor.is_(None), CVE.product.is_(None)),
                CVE.description.notlike("Rejected reason:%"),
            )
        ).limit(10)
    )
    nr_samples = []
    for cve in non_rejected_sample.scalars().all():
        raw = cve.raw_json or {}
        nr_samples.append({
            "cve_id": cve.cve_id,
            "source": cve.source,
            "vulnStatus": raw.get("vulnStatus") if isinstance(raw, dict) else None,
            "sourceIdentifier": raw.get("sourceIdentifier") if isinstance(raw, dict) else None,
            "description_preview": (cve.description or "")[:300],
        })

    return {
        "total_cves": total,
        "missing_vendor": missing_vendor,
        "missing_product": missing_product,
        "missing_both": missing_both,
        "rejected_cves": rejected_count,
        "real_cves_missing": missing_both - rejected_count,
        "by_source": {row[0]: row[1] for row in source_breakdown},
        "by_vuln_status": {row[0]: row[1] for row in vuln_status_breakdown},
        "data_availability": {
            "has_raw_json": has_raw_json,
            "has_cpe_names": has_cpe,
            "has_affected_products": has_affected,
        },
        "non_rejected_samples": nr_samples,
        "rejected_samples": samples[:3],
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
    batch_size: int = Query(500, ge=100, le=2000),
):
    """Backfill missing vendor/product fields for existing CVEs.

    Processes ALL CVEs with NULL vendor or product using:
    - CPE names, affected_products, raw_json (source-specific parsing)
    - Description text parsing (pattern-based)
    - sourceIdentifier CNA email → vendor mapping
    - Rejected CVEs are marked as [rejected]

    Uses its own DB sessions per batch to avoid memory/timeout issues.
    """
    from app.engine.vendor_product_extractor import extract_vendor_product
    from app.database import async_session
    from sqlalchemy import text

    # Count how many need backfill
    async with async_session() as session:
        total_missing = (await session.execute(
            select(func.count()).select_from(
                select(CVE.id).where(
                    or_(CVE.vendor.is_(None), CVE.product.is_(None))
                ).subquery()
            )
        )).scalar() or 0

    if total_missing == 0:
        return {"status": "ok", "message": "All CVEs already have vendor/product", "updated": 0}

    # Process using ID-based cursor with fresh session per batch
    updated_count = 0
    processed_count = 0
    last_id = 0

    while True:
        async with async_session() as session:
            try:
                # Only select needed columns to reduce memory (raw_json can be large)
                result = await session.execute(
                    select(
                        CVE.id, CVE.vendor, CVE.product, CVE.cpe_names,
                        CVE.affected_products, CVE.raw_json, CVE.source,
                        CVE.sources, CVE.description,
                    )
                    .where(
                        and_(
                            CVE.id > last_id,
                            or_(CVE.vendor.is_(None), CVE.product.is_(None)),
                        )
                    )
                    .order_by(asc(CVE.id))
                    .limit(batch_size)
                )
                rows = result.all()
                if not rows:
                    break

                batch_updated = 0
                for row in rows:
                    cve_id, cur_vendor, cur_product = row[0], row[1], row[2]
                    cpe_names, affected_prods, raw_json = row[3], row[4], row[5]
                    source, sources, description = row[6], row[7], row[8]

                    last_id = cve_id
                    processed_count += 1

                    new_vendor, new_product = extract_vendor_product(
                        vendor=cur_vendor,
                        product=cur_product,
                        cpe_names=cpe_names,
                        affected_products=affected_prods,
                        raw_json=raw_json,
                        source=source,
                        sources=sources,
                        description=description,
                    )

                    updates = {}
                    if new_vendor and not cur_vendor:
                        updates["vendor"] = new_vendor
                    if new_product and not cur_product:
                        updates["product"] = new_product

                    if updates:
                        await session.execute(
                            update(CVE).where(CVE.id == cve_id).values(**updates)
                        )
                        batch_updated += 1

                await session.commit()
                updated_count += batch_updated
                logger.info(
                    f"Vendor/product backfill: {updated_count} updated, "
                    f"{processed_count}/{total_missing} processed"
                )

            except Exception as e:
                logger.error(f"Backfill batch error at id>{last_id}: {e}")
                await session.rollback()
                # Skip this batch and continue from next ID
                last_id += batch_size
                continue

    # Final counts with fresh session
    async with async_session() as session:
        remaining_both = (await session.execute(
            select(func.count()).select_from(
                select(CVE.id).where(
                    and_(CVE.vendor.is_(None), CVE.product.is_(None))
                ).subquery()
            )
        )).scalar() or 0

        remaining_vendor = (await session.execute(
            select(func.count()).select_from(
                select(CVE.id).where(CVE.vendor.is_(None)).subquery()
            )
        )).scalar() or 0

        remaining_product = (await session.execute(
            select(func.count()).select_from(
                select(CVE.id).where(CVE.product.is_(None)).subquery()
            )
        )).scalar() or 0

    return {
        "status": "ok",
        "total_missing_before": total_missing,
        "processed": processed_count,
        "updated": updated_count,
        "still_missing_vendor": remaining_vendor,
        "still_missing_product": remaining_product,
        "still_missing_both": remaining_both,
        "message": (
            f"Backfilled {updated_count} of {processed_count} processed CVEs. "
            f"{remaining_both} still missing both vendor and product."
        ),
    }
