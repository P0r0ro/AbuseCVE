"""Deduplication logic – checks CVEs against the database.

Multi-source merge: when same CVE comes from different providers,
merge sources, CVSS scores, references, and other fields.
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import List, Tuple, Dict, Any

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.engine.sources.base import NormalizedCVE
from app.models.cve import CVE
from app.models import vendor_product as _vp_models  # noqa: F401 – register Vendor/Product tables for FK resolution

logger = logging.getLogger(__name__)


def _merge_sources(existing: list, new: list) -> list:
    """Merge source lists without duplicates."""
    merged = list(existing or [])
    for s in (new or []):
        if s not in merged:
            merged.append(s)
    return merged


def _merge_cvss_scores(existing: dict, new: dict) -> dict:
    """Merge CVSS score dicts from multiple providers."""
    merged = dict(existing or {})
    for provider, score_data in (new or {}).items():
        if provider not in merged:
            merged[provider] = score_data
        else:
            # Keep the newer/higher version score
            existing_version = merged[provider].get("version", "0")
            new_version = score_data.get("version", "0")
            if new_version >= existing_version:
                merged[provider] = score_data
    return merged


def _merge_references(existing: list, new: list) -> list:
    """Merge reference URL lists without duplicates."""
    merged = list(existing or [])
    for ref in (new or []):
        if ref and ref not in merged:
            merged.append(ref)
    return merged


def _merge_weaknesses(existing: list, new: list) -> list:
    """Merge CWE lists without duplicates."""
    merged = list(existing or [])
    for w in (new or []):
        if w and w not in merged:
            merged.append(w)
    return merged


def _merge_affected_products(existing: list, new: list) -> list:
    """Merge affected product lists without duplicates."""
    merged = list(existing or [])
    for p in (new or []):
        if p and p not in merged:
            merged.append(p)
    return merged[:50]  # Cap at 50 entries


def _best_description(existing: str, new: str) -> str:
    """Return the longest/best description."""
    if not existing:
        return new or ""
    if not new:
        return existing
    return new if len(new) > len(existing) else existing


async def dedup_and_store(
    session: AsyncSession,
    cves: List[NormalizedCVE],
) -> Tuple[List[NormalizedCVE], int]:
    """Check CVEs against DB. Store new ones, merge data for existing.

    Returns:
        (new_cves, existing_count) - list of truly new CVEs and count of existing
    """
    new_cves: List[NormalizedCVE] = []
    existing_count = 0
    updated_cves: List[NormalizedCVE] = []

    for cve_data in cves:
        # Check if CVE exists
        result = await session.execute(
            select(CVE).where(CVE.cve_id == cve_data.cve_id)
        )
        existing = result.scalar_one_or_none()

        if existing:
            # CVE exists → merge data from new source
            existing.seen_count = (existing.seen_count or 0) + 1
            existing.last_seen = datetime.utcnow()

            # Merge sources
            existing.sources = _merge_sources(existing.sources, cve_data.sources)

            # Update KEV flag if newly flagged
            if cve_data.kev_flag and not existing.kev_flag:
                existing.kev_flag = True

            # Merge CVSS scores (multi-provider)
            existing.cvss_scores = _merge_cvss_scores(
                existing.cvss_scores, cve_data.cvss_scores
            )

            # Update primary CVSS if we now have a score and didn't before
            if cve_data.cvss_score and not existing.cvss_score:
                existing.cvss_score = cve_data.cvss_score
                existing.severity = cve_data.severity
                existing.cvss_vector = cve_data.cvss_vector

            # Merge references
            existing.references = _merge_references(
                existing.references, cve_data.references
            )

            # Merge weaknesses
            existing.weaknesses = _merge_weaknesses(
                existing.weaknesses, cve_data.weaknesses
            )

            # Merge affected products
            existing.affected_products = _merge_affected_products(
                existing.affected_products, cve_data.affected_products
            )

            # Keep best description
            existing.description = _best_description(
                existing.description, cve_data.description
            )

            # Update vendor/product if missing — use full extraction pipeline
            if not existing.vendor or not existing.product:
                from app.engine.vendor_product_extractor import extract_vendor_product
                new_vendor, new_product = extract_vendor_product(
                    vendor=existing.vendor or cve_data.vendor,
                    product=existing.product or cve_data.product,
                    cpe_names=existing.cpe_names,
                    affected_products=existing.affected_products,
                    raw_json=cve_data.raw_json or existing.raw_json,
                    source=existing.source,
                    sources=existing.sources,
                )
                if new_vendor and not existing.vendor:
                    existing.vendor = new_vendor
                if new_product and not existing.product:
                    existing.product = new_product

            # Check if modified_date changed (for update detection)
            was_modified = False
            if cve_data.modified_date and existing.modified_date:
                if cve_data.modified_date > existing.modified_date:
                    existing.modified_date = cve_data.modified_date
                    was_modified = True
            elif cve_data.modified_date and not existing.modified_date:
                existing.modified_date = cve_data.modified_date
                was_modified = True

            if was_modified:
                updated_cves.append(cve_data)

            # Merge CPE names
            if cve_data.cpe_names:
                existing_cpes = existing.cpe_names or []
                for cpe in cve_data.cpe_names:
                    if cpe not in existing_cpes:
                        existing_cpes.append(cpe)
                existing.cpe_names = existing_cpes

            existing_count += 1
            logger.debug(
                f"CVE {cve_data.cve_id} merged from {cve_data.source} "
                f"(seen {existing.seen_count}x, sources: {existing.sources})"
            )
        else:
            # New CVE → insert
            new_record = CVE(
                cve_id=cve_data.cve_id,
                vendor=cve_data.vendor,
                product=cve_data.product,
                description=cve_data.description,
                severity=cve_data.severity,
                cvss_score=cve_data.cvss_score,
                cvss_vector=cve_data.cvss_vector,
                source=cve_data.source,
                sources=cve_data.sources,
                published_date=cve_data.published_date,
                modified_date=cve_data.modified_date,
                kev_flag=cve_data.kev_flag,
                seen_count=1,
                first_seen=datetime.utcnow(),
                last_seen=datetime.utcnow(),
                alert_sent=False,
                cpe_names=cve_data.cpe_names,
                references=cve_data.references,
                raw_json=cve_data.raw_json,
                cvss_scores=cve_data.cvss_scores,
                weaknesses=cve_data.weaknesses,
                affected_products=cve_data.affected_products,
            )
            session.add(new_record)
            new_cves.append(cve_data)
            logger.debug(f"CVE {cve_data.cve_id} is NEW — queued for alert")

    await session.flush()
    logger.info(
        f"Dedup: {len(new_cves)} new, {existing_count} existing, "
        f"{len(updated_cves)} modified"
    )
    return new_cves, existing_count


async def dedup_and_store_bulk(
    session: AsyncSession,
    cves: List[NormalizedCVE],
) -> Tuple[List[NormalizedCVE], int]:
    """Fast bulk dedup for DB init — batch SELECT + bulk INSERT.

    Instead of one SELECT per CVE (~280K roundtrips), this does:
    1. One SELECT to get all existing CVE IDs in the batch
    2. One bulk INSERT for all new CVEs
    3. One bulk UPDATE for existing CVEs (seen_count, sources, kev_flag)

    ~1000x faster than dedup_and_store() for large batches.
    Use this ONLY during init; incremental syncs should use dedup_and_store()
    which does full multi-source field merging.
    """
    if not cves:
        return [], 0

    # 1. Batch lookup: get existing CVEs (including vendor/product for backfill)
    cve_ids = [c.cve_id for c in cves]
    result = await session.execute(
        select(CVE.cve_id, CVE.id, CVE.vendor, CVE.product).where(CVE.cve_id.in_(cve_ids))
    )
    existing_rows = {row[0]: {"id": row[1], "vendor": row[2], "product": row[3]} for row in result.all()}
    existing_ids = set(existing_rows.keys())

    # 2. Split into new vs existing
    new_cves: List[NormalizedCVE] = []
    existing_cves: List[NormalizedCVE] = []

    for cve_data in cves:
        if cve_data.cve_id in existing_ids:
            existing_cves.append(cve_data)
        else:
            new_cves.append(cve_data)

    # 3. Bulk insert new CVEs
    if new_cves:
        now = datetime.utcnow()
        new_records = []
        for cve_data in new_cves:
            new_records.append({
                "cve_id": cve_data.cve_id,
                "vendor": cve_data.vendor,
                "product": cve_data.product,
                "description": cve_data.description,
                "severity": cve_data.severity,
                "cvss_score": cve_data.cvss_score,
                "cvss_vector": cve_data.cvss_vector,
                "source": cve_data.source,
                "sources": cve_data.sources,
                "published_date": cve_data.published_date,
                "modified_date": cve_data.modified_date,
                "kev_flag": cve_data.kev_flag,
                "seen_count": 1,
                "first_seen": now,
                "last_seen": now,
                "alert_sent": False,
                "cpe_names": cve_data.cpe_names,
                "references": cve_data.references,
                "raw_json": cve_data.raw_json,
                "cvss_scores": cve_data.cvss_scores,
                "weaknesses": cve_data.weaknesses,
                "affected_products": cve_data.affected_products,
            })

        # Insert in sub-batches to avoid overly large statements
        insert_batch_size = 500
        for i in range(0, len(new_records), insert_batch_size):
            chunk = new_records[i:i + insert_batch_size]
            from sqlalchemy.dialects.postgresql import insert as pg_insert
            stmt = pg_insert(CVE).values(chunk).on_conflict_do_nothing(
                index_elements=["cve_id"]
            )
            await session.execute(stmt)

    # 4. Lightweight update for existing CVEs (bump seen_count, merge kev_flag, backfill vendor/product)
    if existing_cves:
        kev_ids = [c.cve_id for c in existing_cves if c.kev_flag]
        if kev_ids:
            await session.execute(
                update(CVE)
                .where(CVE.cve_id.in_(kev_ids))
                .values(kev_flag=True, last_seen=datetime.utcnow())
            )

        non_kev_ids = [c.cve_id for c in existing_cves if not c.kev_flag]
        if non_kev_ids:
            await session.execute(
                update(CVE)
                .where(CVE.cve_id.in_(non_kev_ids))
                .values(last_seen=datetime.utcnow())
            )

        # Backfill vendor/product for existing CVEs that have missing fields
        from app.engine.vendor_product_extractor import extract_vendor_product
        vendor_updates = []
        for cve_data in existing_cves:
            existing_info = existing_rows.get(cve_data.cve_id, {})
            if existing_info.get("vendor") and existing_info.get("product"):
                continue  # Already has both, skip
            new_vendor, new_product = extract_vendor_product(
                vendor=existing_info.get("vendor") or cve_data.vendor,
                product=existing_info.get("product") or cve_data.product,
                cpe_names=cve_data.cpe_names,
                affected_products=cve_data.affected_products,
                raw_json=cve_data.raw_json,
                source=cve_data.source,
                sources=cve_data.sources,
            )
            updates = {}
            if new_vendor and not existing_info.get("vendor"):
                updates["vendor"] = new_vendor
            if new_product and not existing_info.get("product"):
                updates["product"] = new_product
            if updates:
                vendor_updates.append((cve_data.cve_id, updates))

        # Apply vendor/product updates in small batches
        for cve_id, updates in vendor_updates:
            await session.execute(
                update(CVE).where(CVE.cve_id == cve_id).values(**updates)
            )
        if vendor_updates:
            logger.info(f"Dedup (bulk): backfilled vendor/product for {len(vendor_updates)} CVEs")

    await session.flush()
    logger.info(
        f"Dedup (bulk): {len(new_cves)} new, {len(existing_cves)} existing"
    )
    return new_cves, len(existing_cves)
