"""Vendor/Product entity API routes — Golden List management & enrichment."""

from __future__ import annotations

import logging
from typing import Optional
from fastapi import APIRouter, Depends, Query
from sqlalchemy import select, func, desc
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.vendor_product import Vendor, Product, CPESyncStatus

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/vendor-product", tags=["Vendor/Product"])


@router.get("/vendors")
async def list_vendors(
    page: int = Query(1, ge=1),
    per_page: int = Query(50, ge=1, le=500),
    search: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
):
    """List vendors from the Golden List with optional search."""
    query = select(Vendor)
    if search:
        query = query.where(Vendor.name.ilike(f"%{search}%"))

    count_q = select(func.count()).select_from(query.subquery())
    total = (await db.execute(count_q)).scalar() or 0

    query = query.order_by(Vendor.name).offset((page - 1) * per_page).limit(per_page)
    result = await db.execute(query)
    vendors = [v.to_dict() for v in result.scalars().all()]

    return {"vendors": vendors, "total": total, "page": page, "per_page": per_page}


@router.get("/vendors/{vendor_id}/products")
async def list_vendor_products(
    vendor_id: int,
    page: int = Query(1, ge=1),
    per_page: int = Query(100, ge=1, le=500),
    db: AsyncSession = Depends(get_db),
):
    """List products for a specific vendor."""
    query = select(Product).where(Product.vendor_id == vendor_id)
    count_q = select(func.count()).select_from(query.subquery())
    total = (await db.execute(count_q)).scalar() or 0

    query = query.order_by(Product.name).offset((page - 1) * per_page).limit(per_page)
    result = await db.execute(query)
    products = [p.to_dict() for p in result.scalars().all()]

    return {"products": products, "total": total, "page": page, "per_page": per_page}


@router.get("/stats")
async def vendor_product_stats(db: AsyncSession = Depends(get_db)):
    """Get stats about the Golden List and CVE enrichment coverage."""
    from app.models.cve import CVE
    from sqlalchemy import and_

    total_vendors = (await db.execute(select(func.count()).select_from(Vendor))).scalar() or 0
    total_products = (await db.execute(select(func.count()).select_from(Product))).scalar() or 0

    total_cves = (await db.execute(select(func.count()).select_from(CVE))).scalar() or 0
    linked_cves = (await db.execute(
        select(func.count()).select_from(CVE).where(CVE.vendor_id.isnot(None))
    )).scalar() or 0
    unlinked_cves = total_cves - linked_cves

    # Breakdown by extraction method
    from sqlalchemy import text
    method_breakdown = (await db.execute(text(
        "SELECT extraction_method, COUNT(*) FROM cves "
        "WHERE extraction_method IS NOT NULL "
        "GROUP BY extraction_method ORDER BY COUNT(*) DESC"
    ))).all()

    # Last sync status
    last_sync = (await db.execute(
        select(CPESyncStatus).order_by(desc(CPESyncStatus.id)).limit(1)
    )).scalar_one_or_none()

    return {
        "golden_list": {
            "total_vendors": total_vendors,
            "total_products": total_products,
        },
        "enrichment": {
            "total_cves": total_cves,
            "linked_cves": linked_cves,
            "unlinked_cves": unlinked_cves,
            "coverage_pct": round(linked_cves / total_cves * 100, 1) if total_cves else 0,
            "by_method": {row[0]: row[1] for row in method_breakdown},
        },
        "last_cpe_sync": {
            "status": last_sync.status if last_sync else "never",
            "synced_at": last_sync.last_sync_at.isoformat() if last_sync and last_sync.last_sync_at else None,
            "vendors": last_sync.total_vendors if last_sync else 0,
            "products": last_sync.total_products if last_sync else 0,
            "duration_seconds": last_sync.duration_seconds if last_sync else None,
            "error": last_sync.error_message if last_sync else None,
        },
    }


@router.post("/sync-cpe")
async def trigger_cpe_sync(use_api: bool = Query(False)):
    """Trigger a CPE Dictionary sync task (runs in background via Celery).

    - Default: Downloads the XML dictionary (~30MB, fast)
    - use_api=True: Uses NVD API 2.0 (slower, works if XML unavailable)
    """
    from app.tasks.cve_tasks import sync_cpe_dictionary
    task = sync_cpe_dictionary.delay(use_api=use_api)
    return {
        "status": "queued",
        "task_id": task.id,
        "message": f"CPE Dictionary sync queued ({'API' if use_api else 'XML'} mode)",
    }


@router.post("/enrich")
async def trigger_enrichment(
    batch_size: int = Query(500, ge=100, le=2000),
    use_llm: bool = Query(False),
):
    """Trigger CVE vendor/product enrichment task (runs in background via Celery).

    Links existing CVEs to normalized Vendor/Product entities using the 4-tier pipeline.
    Set use_llm=True to enable LLM fallback for CVEs where all other methods fail.
    """
    from app.tasks.cve_tasks import enrich_cve_vendor_product
    task = enrich_cve_vendor_product.delay(batch_size=batch_size, use_llm=use_llm)
    return {
        "status": "queued",
        "task_id": task.id,
        "message": f"CVE enrichment queued (batch={batch_size}, llm={use_llm})",
    }


@router.post("/cleanup")
async def trigger_cleanup(
    batch_size: int = Query(500, ge=100, le=2000),
    use_llm: bool = Query(False),
):
    """Deep cleanup: fix ALL inaccurate vendor/product values in the database.

    Phase 1: NULL out sentence fragments, bad vendors, GitHub usernames
    Phase 2: Re-extract with Golden List quality validation
    Phase 3: Re-link all valid vendors to Golden List FKs

    Set use_llm=True to use Groq/Gemini for CVEs where heuristics fail.
    """
    from app.tasks.cve_tasks import cleanup_vendor_product
    task = cleanup_vendor_product.delay(batch_size=batch_size, use_llm=use_llm)
    return {
        "status": "queued",
        "task_id": task.id,
        "message": f"Deep cleanup queued (batch={batch_size}, llm={use_llm})",
    }


@router.get("/llm-status")
async def llm_extraction_status():
    """Check LLM API key configuration for vendor/product extraction."""
    from app.services.llm_extraction_service import check_llm_keys_status
    return check_llm_keys_status()
