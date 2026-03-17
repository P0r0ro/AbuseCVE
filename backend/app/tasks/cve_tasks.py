"""CVE scanning and CPE dictionary sync Celery tasks."""

from __future__ import annotations

import asyncio
import gzip
import logging
import time
import traceback
import xml.etree.ElementTree as ET
from io import BytesIO

from app.tasks.celery_app import celery_app
from app.config import settings

logger = logging.getLogger(__name__)


def _run_async(coro):
    """Run an async coroutine from sync Celery task."""
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


@celery_app.task(
    bind=True,
    name="app.tasks.cve_tasks.run_cve_scan",
    max_retries=3,
    default_retry_delay=60,
    acks_late=True,
)
def run_cve_scan(self):
    """Scheduled task: Run the full CVE pipeline cycle.

    1. Fetch CVEs from all 4 sources (NVD, CISA KEV, MITRE, RedHat)
    2. Push to Redis pool
    3. Apply filter rules
    4. Dedup against database (merge multi-source data)
    5. Send alerts for new matching CVEs
    """
    logger.info("🔍 Starting CVE scan cycle...")

    async def _scan():
        from app.engine.pipeline import CVEPipeline
        from app.database import async_session
        from app.services.smtp_service import send_cve_alert
        from app.models.alert_log import AlertLog
        from app.models.cve import CVE
        from datetime import datetime

        pipeline = CVEPipeline()

        async with async_session() as session:
            try:
                result = await pipeline.run_full_cycle(session)

                new_cves = result.get("new_cves", [])
                matches = result.get("matches", [])
                logger.info(f"Pipeline result: {len(new_cves)} new CVEs to alert")

                # Build rule name lookup from matches
                rule_names = {}
                for m in matches:
                    rule_names[m["cve_id"]] = m.get("rule_name", "")

                # Send alerts for new CVEs that matched filters
                alerts_sent = 0
                alerts_failed = 0
                for cve_data in new_cves:
                    cve_dict = {
                        "cve_id": cve_data.cve_id,
                        "vendor": cve_data.vendor,
                        "product": cve_data.product,
                        "description": cve_data.description,
                        "severity": cve_data.severity,
                        "cvss_score": cve_data.cvss_score,
                        "source": cve_data.source,
                        "sources": cve_data.sources,
                        "published_date": cve_data.published_date.isoformat() if cve_data.published_date else None,
                        "kev_flag": cve_data.kev_flag,
                        "cvss_scores": cve_data.cvss_scores,
                    }

                    rule_name = rule_names.get(cve_data.cve_id, "")

                    try:
                        email_result = await send_cve_alert(cve_dict, rule_name=rule_name)

                        # Log the alert
                        alert_log = AlertLog(
                            cve_id=cve_data.cve_id,
                            sent_at=datetime.utcnow(),
                            recipient=settings.alert_recipients,
                            status=email_result.get("status", "unknown"),
                            error_message=email_result.get("error"),
                            rule_name=rule_name,
                            is_new_cve=True,
                        )
                        session.add(alert_log)

                        if email_result.get("status") == "sent":
                            alerts_sent += 1
                        else:
                            alerts_failed += 1
                            logger.error(
                                f"Alert failed for {cve_data.cve_id}: "
                                f"{email_result.get('error', 'unknown error')}"
                            )

                    except Exception as e:
                        alerts_failed += 1
                        logger.error(
                            f"Alert exception for {cve_data.cve_id}: "
                            f"{type(e).__name__}: {e}\n"
                            f"Traceback: {traceback.format_exc()}"
                        )
                        # Still log the failed alert
                        alert_log = AlertLog(
                            cve_id=cve_data.cve_id,
                            sent_at=datetime.utcnow(),
                            recipient=settings.alert_recipients,
                            status="failed",
                            error_message=f"{type(e).__name__}: {str(e)[:500]}",
                            rule_name=rule_name,
                            is_new_cve=True,
                        )
                        session.add(alert_log)

                    # Mark CVE as alerted
                    from sqlalchemy import update as sql_update
                    await session.execute(
                        sql_update(CVE)
                        .where(CVE.cve_id == cve_data.cve_id)
                        .values(alert_sent=True)
                    )

                    # Dispatch to webhook/CRM integrations
                    try:
                        from app.services.webhook_service import dispatch_to_all_integrations
                        await dispatch_to_all_integrations(session, cve_dict, rule_name=rule_name)
                    except Exception as ie:
                        logger.warning(f"Integration dispatch failed for {cve_data.cve_id}: {ie}")

                # Log all NEW CVEs that did NOT get an alert email as status="stored"
                # so the Alerts tab shows every incoming CVE, not just emailed ones.
                alerted_ids = {cve_data.cve_id for cve_data in new_cves}
                all_new_cves = result.get("all_new_cves", [])
                unmatched_new = [c for c in all_new_cves if c.cve_id not in alerted_ids]

                if unmatched_new:
                    logger.info(f"Logging {len(unmatched_new)} non-alerted new CVEs as 'stored'")
                    for cve_data in unmatched_new:
                        session.add(AlertLog(
                            cve_id=cve_data.cve_id,
                            sent_at=datetime.utcnow(),
                            recipient=None,
                            status="stored",
                            error_message=None,
                            rule_name=None,
                            is_new_cve=True,
                        ))

                await session.commit()

                scan_summary = {
                    "total_fetched": result.get("total_fetched", 0),
                    "filtered": result.get("filtered_count", 0),
                    "new_alerted": alerts_sent,
                    "alerts_failed": alerts_failed,
                    "existing": result.get("existing_count", 0),
                    "total_new_stored": result.get("total_new_stored", 0),
                }

                # Only send a scan summary email when the scan actually fetched something
                # or when alerts were sent/failed — avoids flooding with empty scan emails
                total_fetched = scan_summary["total_fetched"]
                if total_fetched > 0 or alerts_sent > 0 or alerts_failed > 0:
                    try:
                        from app.services.smtp_service import send_scan_summary
                        await send_scan_summary(scan_summary, matched_cves=new_cves)
                    except Exception as e:
                        logger.warning(f"Scan summary email failed: {e}")
                else:
                    logger.info("CVE scan: no new CVEs fetched, skipping summary email")

                return scan_summary

            except Exception as e:
                logger.error(
                    f"CVE scan failed: {type(e).__name__}: {e}\n"
                    f"Traceback: {traceback.format_exc()}"
                )
                await session.rollback()
                raise

    try:
        result = _run_async(_scan())
        logger.info(f"✅ CVE scan complete: {result}")
        return result
    except Exception as exc:
        logger.error(f"❌ CVE scan failed, retrying: {type(exc).__name__}: {exc}")
        raise self.retry(exc=exc)


# ── CPE Dictionary Sync ─────────────────────────────────────────────────────

CPE_DICT_URL = "https://nvd.nist.gov/feeds/xml/cpe/dictionary/official-cpe-dictionary_v2.3.xml.gz"
CPE_API_URL = "https://services.nvd.nist.gov/rest/json/cpes/2.0"
CPE_NS = "{http://cpe.mitre.org/dictionary/2.0}"
CPE23_NS = "{http://scap.nist.gov/schema/cpe-extension/2.3}"


def _parse_cpe23_uri(cpe_uri: str):
    """Parse vendor and product from a CPE 2.3 URI string.

    Format: cpe:2.3:part:vendor:product:version:...
    Returns (vendor, product) or (None, None).
    """
    parts = cpe_uri.split(":")
    if len(parts) >= 5:
        vendor = parts[3] if parts[3] not in ("*", "-", "") else None
        product = parts[4] if parts[4] not in ("*", "-", "") else None
        return vendor, product
    return None, None


@celery_app.task(
    bind=True,
    name="app.tasks.cve_tasks.sync_cpe_dictionary",
    max_retries=2,
    default_retry_delay=300,
    acks_late=True,
)
def sync_cpe_dictionary(self, use_api: bool = False):
    """Download and sync the NVD CPE Dictionary into the local Vendor/Product tables.

    Two modes:
    - XML mode (default): Downloads official-cpe-dictionary_v2.3.xml.gz (~30MB)
      and parses it using streaming XML. Fast, complete, one-shot.
    - API mode (use_api=True): Uses NVD CPE API 2.0 with pagination.
      Slower but works if XML feed is unavailable.

    This task is idempotent — re-running it will only add new entries.
    """
    logger.info("Starting CPE Dictionary sync...")
    start = time.time()

    async def _sync():
        import httpx
        from sqlalchemy import select
        from sqlalchemy.dialects.postgresql import insert as pg_insert
        from app.database import async_session
        from app.models.vendor_product import Vendor, Product, CPESyncStatus
        from datetime import datetime

        async with async_session() as session:
            # Mark sync as running
            sync_status = CPESyncStatus(
                status="running",
                last_sync_at=datetime.utcnow(),
            )
            session.add(sync_status)
            await session.commit()
            sync_id = sync_status.id

            try:
                if use_api:
                    vendor_products = await _fetch_cpe_via_api()
                else:
                    vendor_products = await _fetch_cpe_via_xml()

                logger.info(f"CPE sync: parsed {len(vendor_products)} unique vendor:product pairs")

                # Deduplicate and batch-insert vendors
                unique_vendors = set()
                for v, p in vendor_products:
                    if v:
                        unique_vendors.add(v)

                # Insert vendors (ON CONFLICT DO NOTHING)
                vendor_batch_size = 500
                vendor_list = sorted(unique_vendors)
                for i in range(0, len(vendor_list), vendor_batch_size):
                    chunk = vendor_list[i:i + vendor_batch_size]
                    values = [{"name": v, "is_cpe_source": True} for v in chunk]
                    stmt = pg_insert(Vendor).values(values).on_conflict_do_nothing(
                        index_elements=["name"]
                    )
                    await session.execute(stmt)
                await session.commit()

                # Build vendor name → id lookup
                result = await session.execute(select(Vendor.name, Vendor.id))
                vendor_id_map = {row[0]: row[1] for row in result.all()}

                # Insert products (ON CONFLICT DO NOTHING on vendor_id + name)
                product_batch_size = 500
                product_entries = []
                seen_product_keys = set()
                for v, p in vendor_products:
                    if not v or not p:
                        continue
                    vid = vendor_id_map.get(v)
                    if not vid:
                        continue
                    key = (vid, p)
                    if key in seen_product_keys:
                        continue
                    seen_product_keys.add(key)
                    product_entries.append({
                        "name": p,
                        "vendor_id": vid,
                        "is_cpe_source": True,
                    })

                for i in range(0, len(product_entries), product_batch_size):
                    chunk = product_entries[i:i + product_batch_size]
                    stmt = pg_insert(Product).values(chunk).on_conflict_do_nothing(
                        constraint="uq_product_vendor_name"
                    )
                    await session.execute(stmt)
                    if (i // product_batch_size) % 20 == 0:
                        await session.commit()
                        logger.info(f"CPE sync: inserted products batch {i}/{len(product_entries)}")

                await session.commit()

                duration = int(time.time() - start)

                # Update sync status
                await session.execute(
                    select(CPESyncStatus).where(CPESyncStatus.id == sync_id)
                )
                sync_rec = (await session.execute(
                    select(CPESyncStatus).where(CPESyncStatus.id == sync_id)
                )).scalar_one()
                sync_rec.status = "completed"
                sync_rec.total_vendors = len(unique_vendors)
                sync_rec.total_products = len(product_entries)
                sync_rec.duration_seconds = duration
                await session.commit()

                result_summary = {
                    "vendors": len(unique_vendors),
                    "products": len(product_entries),
                    "duration_seconds": duration,
                }
                logger.info(f"CPE Dictionary sync complete: {result_summary}")
                return result_summary

            except Exception as e:
                # Mark sync as failed
                try:
                    sync_rec = (await session.execute(
                        select(CPESyncStatus).where(CPESyncStatus.id == sync_id)
                    )).scalar_one_or_none()
                    if sync_rec:
                        sync_rec.status = "failed"
                        sync_rec.error_message = f"{type(e).__name__}: {str(e)[:500]}"
                        sync_rec.duration_seconds = int(time.time() - start)
                        await session.commit()
                except Exception:
                    pass
                raise

    async def _fetch_cpe_via_xml():
        """Download and parse the XML CPE dictionary."""
        import httpx

        logger.info(f"CPE sync: downloading XML dictionary from {CPE_DICT_URL}")
        async with httpx.AsyncClient(timeout=120.0, follow_redirects=True) as client:
            headers = {}
            if settings.nvd_api_key:
                headers["apiKey"] = settings.nvd_api_key
            resp = await client.get(CPE_DICT_URL, headers=headers)
            resp.raise_for_status()

        logger.info(f"CPE sync: downloaded {len(resp.content)} bytes, decompressing...")
        xml_data = gzip.decompress(resp.content)
        logger.info(f"CPE sync: decompressed to {len(xml_data)} bytes, parsing...")

        # Stream-parse the XML to avoid loading full tree into memory
        vendor_products = set()
        for event, elem in ET.iterparse(BytesIO(xml_data), events=("end",)):
            if elem.tag == f"{CPE23_NS}cpe23-item":
                cpe_name = elem.get("name", "")
                vendor, product = _parse_cpe23_uri(cpe_name)
                if vendor and product:
                    vendor_products.add((vendor.lower(), product.lower()))
                elem.clear()
            elif elem.tag == f"{CPE_NS}cpe-item":
                # Also try the cpe23-item child
                child = elem.find(f"{CPE23_NS}cpe23-item")
                if child is not None:
                    cpe_name = child.get("name", "")
                    vendor, product = _parse_cpe23_uri(cpe_name)
                    if vendor and product:
                        vendor_products.add((vendor.lower(), product.lower()))
                elem.clear()

        logger.info(f"CPE sync (XML): {len(vendor_products)} unique vendor:product pairs")
        return list(vendor_products)

    async def _fetch_cpe_via_api():
        """Fetch CPE entries via the NVD API 2.0 with pagination."""
        import httpx

        vendor_products = set()
        start_index = 0
        results_per_page = 5000
        total = None

        async with httpx.AsyncClient(timeout=60.0) as client:
            while True:
                params = {
                    "resultsPerPage": results_per_page,
                    "startIndex": start_index,
                }
                headers = {}
                if settings.nvd_api_key:
                    headers["apiKey"] = settings.nvd_api_key

                resp = await client.get(CPE_API_URL, params=params, headers=headers)
                resp.raise_for_status()
                data = resp.json()

                if total is None:
                    total = data.get("totalResults", 0)
                    logger.info(f"CPE sync (API): {total} total CPE entries")

                products = data.get("products", [])
                if not products:
                    break

                for item in products:
                    cpe = item.get("cpe", {})
                    cpe_name = cpe.get("cpeName", "")
                    vendor, product = _parse_cpe23_uri(cpe_name)
                    if vendor and product:
                        vendor_products.add((vendor.lower(), product.lower()))

                start_index += len(products)
                logger.info(f"CPE sync (API): {start_index}/{total} processed")

                if start_index >= total:
                    break

                # Rate limit: NVD allows 5 requests/30s without key, 50/30s with key
                import asyncio
                await asyncio.sleep(0.6 if settings.nvd_api_key else 6.0)

        logger.info(f"CPE sync (API): {len(vendor_products)} unique vendor:product pairs")
        return list(vendor_products)

    try:
        result = _run_async(_sync())
        logger.info(f"CPE Dictionary sync complete: {result}")
        return result
    except Exception as exc:
        logger.error(f"CPE Dictionary sync failed: {type(exc).__name__}: {exc}\n{traceback.format_exc()}")
        raise self.retry(exc=exc)


# ── Vendor/Product Enrichment (link existing CVEs to Golden List) ────────────

@celery_app.task(
    bind=True,
    name="app.tasks.cve_tasks.enrich_cve_vendor_product",
    max_retries=1,
    default_retry_delay=120,
    acks_late=True,
)
def enrich_cve_vendor_product(self, batch_size: int = 500, use_llm: bool = False):
    """Link existing CVEs to normalized Vendor/Product entities.

    Runs the 4-tier extraction pipeline on CVEs that lack vendor_id/product_id:
    1. Direct CPE match (from CVE record's cpe_names)
    2. Local DB lookup (check extracted strings against the Golden List)
    3. Heuristic/regex fallback (existing extraction logic)
    4. LLM inference (optional, only if use_llm=True)

    This is safe to run multiple times — only processes unlinked CVEs.
    """
    logger.info(f"Starting CVE vendor/product enrichment (batch_size={batch_size}, llm={use_llm})")

    async def _enrich():
        from sqlalchemy import select, update, or_, and_, asc, func
        from app.database import async_session
        from app.models.cve import CVE
        from app.models.vendor_product import Vendor, Product
        from app.engine.vendor_product_extractor import extract_vendor_product

        # Build in-memory vendor/product lookup from Golden List
        async with async_session() as session:
            vendor_rows = (await session.execute(select(Vendor.id, Vendor.name))).all()
            vendor_map = {row[1]: row[0] for row in vendor_rows}  # name → id

            product_rows = (await session.execute(
                select(Product.id, Product.name, Product.vendor_id)
            )).all()
            # (vendor_id, product_name) → product_id
            product_map = {(row[2], row[1]): row[0] for row in product_rows}

        if not vendor_map:
            logger.warning("No vendors in Golden List — run sync_cpe_dictionary first")
            return {"status": "skipped", "reason": "empty_golden_list"}

        logger.info(f"Golden List loaded: {len(vendor_map)} vendors, {len(product_map)} products")

        total_linked = 0
        total_processed = 0
        total_llm_used = 0
        last_id = 0

        while True:
            async with async_session() as session:
                try:
                    # Select CVEs that don't have vendor_id yet
                    result = await session.execute(
                        select(
                            CVE.id, CVE.cve_id, CVE.vendor, CVE.product,
                            CVE.cpe_names, CVE.affected_products, CVE.raw_json,
                            CVE.source, CVE.sources, CVE.description,
                        )
                        .where(
                            and_(
                                CVE.id > last_id,
                                CVE.vendor_id.is_(None),
                            )
                        )
                        .order_by(asc(CVE.id))
                        .limit(batch_size)
                    )
                    rows = result.all()
                    if not rows:
                        break

                    batch_linked = 0
                    for row in rows:
                        (cve_pk, cve_id, cur_vendor, cur_product,
                         cpe_names, affected_prods, raw_json,
                         source, sources, description) = row

                        last_id = cve_pk
                        total_processed += 1

                        # Tier 1 & 3: Run existing extraction (includes CPE match + heuristics)
                        vendor_str, product_str = extract_vendor_product(
                            vendor=cur_vendor,
                            product=cur_product,
                            cpe_names=cpe_names,
                            affected_products=affected_prods,
                            raw_json=raw_json,
                            source=source,
                            sources=sources,
                            description=description,
                        )

                        extraction_method = None
                        vendor_id = None
                        product_id = None

                        # Determine extraction method based on what worked
                        if cpe_names and vendor_str:
                            extraction_method = "cpe_match"
                        elif vendor_str:
                            extraction_method = "heuristic"

                        # Tier 2: DB lookup — try to link to Golden List
                        if vendor_str:
                            vid = vendor_map.get(vendor_str.lower())
                            if vid:
                                vendor_id = vid
                                if not extraction_method or extraction_method == "heuristic":
                                    extraction_method = "db_lookup"
                                if product_str:
                                    pid = product_map.get((vid, product_str.lower()))
                                    if pid:
                                        product_id = pid

                        # Tier 4: LLM fallback (only if enabled and no vendor found)
                        if use_llm and not vendor_str and description:
                            try:
                                from app.services.llm_extraction_service import extract_with_llm
                                llm_result = await extract_with_llm(description)
                                if llm_result.status == "success" and (llm_result.vendor or llm_result.product):
                                    total_llm_used += 1
                                    extraction_method = "llm"
                                    if llm_result.vendor and not vendor_str:
                                        vendor_str = llm_result.vendor
                                        vid = vendor_map.get(vendor_str.lower())
                                        if vid:
                                            vendor_id = vid
                                    if llm_result.product and not product_str:
                                        product_str = llm_result.product
                                        if vendor_id:
                                            pid = product_map.get((vendor_id, product_str.lower()))
                                            if pid:
                                                product_id = pid
                            except Exception as e:
                                logger.debug(f"LLM extraction failed for {cve_id}: {e}")

                        # Build update dict
                        updates = {}
                        if vendor_str and not cur_vendor:
                            updates["vendor"] = vendor_str
                        if product_str and not cur_product:
                            updates["product"] = product_str
                        if vendor_id:
                            updates["vendor_id"] = vendor_id
                        if product_id:
                            updates["product_id"] = product_id
                        if extraction_method:
                            updates["extraction_method"] = extraction_method

                        if updates:
                            await session.execute(
                                update(CVE).where(CVE.id == cve_pk).values(**updates)
                            )
                            batch_linked += 1

                    await session.commit()
                    total_linked += batch_linked
                    logger.info(
                        f"Enrichment: {total_processed} processed, {total_linked} linked, "
                        f"{total_llm_used} LLM-assisted"
                    )

                except Exception as e:
                    logger.error(f"Enrichment batch error at id>{last_id}: {e}")
                    await session.rollback()
                    last_id += batch_size
                    continue

        return {
            "total_processed": total_processed,
            "total_linked": total_linked,
            "total_llm_used": total_llm_used,
        }

    try:
        result = _run_async(_enrich())
        logger.info(f"CVE enrichment complete: {result}")
        return result
    except Exception as exc:
        logger.error(f"CVE enrichment failed: {type(exc).__name__}: {exc}\n{traceback.format_exc()}")
        raise self.retry(exc=exc)
