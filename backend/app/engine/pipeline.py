"""CVE Pipeline – orchestrates the full fetch → pool → filter → dedup → alert flow.

Uses Redis as the log aggregation pool between stages:
1. FETCH: Pull CVEs from all 4 sources → push to Redis pool
2. FILTER: Pop from pool → apply filter rules
3. DEDUP: Check filtered CVEs against DB
4. DISPATCH: Queue new CVEs for SMTP alert
"""

from __future__ import annotations

import json
import logging
from datetime import datetime
from typing import List, Optional, Dict, Any

import redis.asyncio as aioredis
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.engine.sources.nvd import NVDSource
from app.engine.sources.cisa_kev import CISAKEVSource
from app.engine.sources.mitre_cvelistv5 import MITRECVEListSource
from app.engine.sources.redhat import RedHatSource
from app.engine.sources.base import NormalizedCVE
from app.engine.filter_engine import filter_cves, FilterMatch
from app.engine.dedup import dedup_and_store, dedup_and_store_bulk
from app.models.filter_rule import FilterRule
from app.models.cve import CVE

logger = logging.getLogger(__name__)

REDIS_CVE_POOL = "abusecve:cve_pool"
REDIS_LAST_SYNC = "abusecve:last_sync"


class CVEPipeline:
    """Orchestrates the full CVE processing pipeline."""

    def __init__(self):
        self.nvd = NVDSource()
        self.kev = CISAKEVSource()
        self.mitre = MITRECVEListSource()
        self.redhat = RedHatSource()

    async def _get_redis(self) -> aioredis.Redis:
        return aioredis.from_url(settings.redis_url, decode_responses=True)

    def _serialize_cve(self, cve: NormalizedCVE) -> str:
        """Serialize a NormalizedCVE to JSON string for Redis."""
        return json.dumps({
            "cve_id": cve.cve_id,
            "vendor": cve.vendor,
            "product": cve.product,
            "description": cve.description,
            "severity": cve.severity,
            "cvss_score": cve.cvss_score,
            "cvss_vector": cve.cvss_vector,
            "source": cve.source,
            "sources": cve.sources,
            "published_date": cve.published_date.isoformat() if cve.published_date else None,
            "modified_date": cve.modified_date.isoformat() if cve.modified_date else None,
            "kev_flag": cve.kev_flag,
            "cpe_names": cve.cpe_names,
            "references": cve.references,
            "raw_json": cve.raw_json,
            "cvss_scores": cve.cvss_scores,
            "weaknesses": cve.weaknesses,
            "affected_products": cve.affected_products,
        })

    def _deserialize_cve(self, raw: str) -> Optional[NormalizedCVE]:
        """Deserialize a JSON string from Redis back to NormalizedCVE."""
        try:
            data = json.loads(raw)
            pub_date = None
            if data.get("published_date"):
                pub_date = datetime.fromisoformat(data["published_date"])
            mod_date = None
            if data.get("modified_date"):
                mod_date = datetime.fromisoformat(data["modified_date"])

            return NormalizedCVE(
                cve_id=data["cve_id"],
                vendor=data.get("vendor"),
                product=data.get("product"),
                description=data.get("description"),
                severity=data.get("severity"),
                cvss_score=data.get("cvss_score"),
                cvss_vector=data.get("cvss_vector"),
                source=data.get("source", "UNKNOWN"),
                sources=data.get("sources", []),
                published_date=pub_date,
                modified_date=mod_date,
                kev_flag=data.get("kev_flag", False),
                cpe_names=data.get("cpe_names", []),
                references=data.get("references", []),
                raw_json=data.get("raw_json"),
                cvss_scores=data.get("cvss_scores", {}),
                weaknesses=data.get("weaknesses", []),
                affected_products=data.get("affected_products", []),
            )
        except Exception as e:
            logger.warning(f"Failed to deserialize CVE from pool: {e}")
            return None

    # ── Stage 1: FETCH ────────────────────────────────────
    async def fetch_and_pool(self, since: Optional[datetime] = None) -> int:
        """Fetch CVEs from all sources and push to Redis pool.

        Returns number of CVEs pooled.
        """
        r = await self._get_redis()

        # Get last sync time from Redis
        if since is None:
            last_sync = await r.get(REDIS_LAST_SYNC)
            if last_sync:
                since = datetime.fromisoformat(last_sync)

        all_cves: List[NormalizedCVE] = []

        # Fetch from NVD (incremental)
        try:
            nvd_cves = await self.nvd.fetch_recent(since=since)
            all_cves.extend(nvd_cves)
            logger.info(f"Fetched {len(nvd_cves)} CVEs from NVD")
        except Exception as e:
            logger.error(f"NVD fetch failed: {e}", exc_info=True)

        # Fetch from CISA KEV
        try:
            kev_cves = await self.kev.fetch_recent(since=since)
            all_cves.extend(kev_cves)
            logger.info(f"Fetched {len(kev_cves)} CVEs from CISA KEV")
        except Exception as e:
            logger.error(f"CISA KEV fetch failed: {e}", exc_info=True)

        # Fetch from MITRE
        try:
            mitre_cves = await self.mitre.fetch_recent(since=since)
            all_cves.extend(mitre_cves)
            logger.info(f"Fetched {len(mitre_cves)} CVEs from MITRE")
        except Exception as e:
            logger.error(f"MITRE fetch failed: {e}", exc_info=True)

        # Fetch from RedHat
        try:
            redhat_cves = await self.redhat.fetch_recent(since=since)
            all_cves.extend(redhat_cves)
            logger.info(f"Fetched {len(redhat_cves)} CVEs from RedHat")
        except Exception as e:
            logger.error(f"RedHat fetch failed: {e}", exc_info=True)

        # Push to Redis pool (serialized)
        pooled = 0
        for cve in all_cves:
            cve_json = self._serialize_cve(cve)
            await r.rpush(REDIS_CVE_POOL, cve_json)
            pooled += 1

        # Update last sync time
        await r.set(REDIS_LAST_SYNC, datetime.utcnow().isoformat())
        await r.aclose()

        logger.info(f"Pipeline FETCH: {pooled} CVEs pushed to pool")
        return pooled

    # ── Stage 2 & 3: FILTER + DEDUP ──────────────────────
    async def process_pool(self, session: AsyncSession) -> Dict[str, Any]:
        """Pop CVEs from pool, filter, dedup, and return results."""
        r = await self._get_redis()

        # Pop all from pool
        raw_cves: List[str] = []
        while True:
            item = await r.lpop(REDIS_CVE_POOL)
            if item is None:
                break
            raw_cves.append(item)

        await r.aclose()

        if not raw_cves:
            logger.info("Pipeline PROCESS: pool is empty")
            return {"new_cves": [], "existing_count": 0, "filtered_count": 0}

        # Deserialize
        cves: List[NormalizedCVE] = []
        for raw in raw_cves:
            cve = self._deserialize_cve(raw)
            if cve:
                cves.append(cve)

        logger.info(f"Pipeline PROCESS: {len(cves)} CVEs from pool")

        # Load active filter rules
        result = await session.execute(
            select(FilterRule).where(FilterRule.enabled == True)
        )
        rules = [r.to_dict() for r in result.scalars().all()]

        if not rules:
            logger.warning("No active filter rules — storing all CVEs to DB without alerting")
            # Still store to DB even without rules
            new_cves, existing = await dedup_and_store(session, cves)
            await session.commit()
            return {
                "new_cves": [],
                "existing_count": existing,
                "filtered_count": 0,
                "total_pooled": len(cves),
                "stored_without_filter": len(new_cves),
            }

        # Apply filters
        matches = filter_cves(cves, rules)
        logger.info(f"Pipeline FILTER: {len(matches)} CVEs passed filters")

        # Dedup ALL CVEs (not just matched — store everything in DB)
        all_new, all_existing = await dedup_and_store(session, cves)

        # Only return matched CVEs for alerting
        matched_ids = {m.cve.cve_id for m in matches}
        alertable_cves = [c for c in all_new if c.cve_id in matched_ids]

        await session.commit()

        return {
            "new_cves": alertable_cves,
            "existing_count": all_existing,
            "filtered_count": len(matches),
            "total_pooled": len(cves),
            "total_new_stored": len(all_new),
            "matches": [
                {"cve_id": m.cve.cve_id, "rule_id": m.rule_id, "rule_name": m.rule_name}
                for m in matches
            ],
        }

    # ── Full Run ──────────────────────────────────────────
    async def run_full_cycle(self, session: AsyncSession) -> Dict[str, Any]:
        """Run the complete pipeline: fetch → pool → filter → dedup."""
        pooled = await self.fetch_and_pool()
        result = await self.process_pool(session)
        result["total_fetched"] = pooled
        logger.info(
            f"Pipeline COMPLETE: fetched={pooled}, "
            f"filtered={result.get('filtered_count', 0)}, "
            f"new={len(result.get('new_cves', []))}, "
            f"existing={result.get('existing_count', 0)}"
        )
        return result

    # ── Initialize DB (bulk import from all sources) ─────
    async def initialize_db(
        self,
        session: AsyncSession,
    ) -> Dict[str, Any]:
        """Bulk-import ALL past CVEs from all 4 sources into the database.

        Uses streaming batch processing to avoid OOM:
        - NVD: streamed in pages of 2000, committed per page
        - Others: fetched then batch-committed in chunks of 5000
        """
        logger.info("DB Init: Starting full bulk import from all sources")

        total_new = 0
        total_existing = 0
        source_stats = {}

        # 1. CISA KEV first (small — ~1500 entries, always fits in memory)
        try:
            kev_cves = await self.kev.fetch_all()
            new, existing = await dedup_and_store_bulk(session, kev_cves)
            await session.commit()
            total_new += len(new)
            total_existing += existing
            source_stats["CISA_KEV"] = len(kev_cves)
            logger.info(f"DB Init: {len(kev_cves)} CVEs from CISA KEV → {len(new)} new")
        except Exception as e:
            logger.error(f"DB Init CISA failed: {e}", exc_info=True)

        # 2. NVD full mirror — STREAM in batches of 2000 to avoid OOM
        nvd_total = 0
        try:
            async for batch, fetched, total in self.nvd.fetch_all_batched():
                if batch:
                    new, existing = await dedup_and_store_bulk(session, batch)
                    await session.commit()
                    total_new += len(new)
                    total_existing += existing
                    nvd_total += len(batch)
                    logger.info(
                        f"DB Init NVD batch: {fetched}/{total} fetched, "
                        f"{len(new)} new this batch, {nvd_total} total NVD"
                    )
            source_stats["NVD"] = nvd_total
            logger.info(f"DB Init: {nvd_total} CVEs from NVD complete")
        except Exception as e:
            logger.error(f"DB Init NVD failed at {nvd_total} CVEs: {e}", exc_info=True)
            source_stats["NVD"] = f"{nvd_total} (partial, error: {e})"

        # 3. MITRE CVEListV5 — fetch then batch-commit
        try:
            mitre_cves = await self.mitre.fetch_all()
            batch_size = 5000
            mitre_new = 0
            for i in range(0, len(mitre_cves), batch_size):
                chunk = mitre_cves[i:i + batch_size]
                new, existing = await dedup_and_store_bulk(session, chunk)
                await session.commit()
                mitre_new += len(new)
                total_new += len(new)
                total_existing += existing
                logger.info(f"DB Init MITRE batch {i // batch_size + 1}: {len(new)} new")
            del mitre_cves  # Free memory
            source_stats["MITRE"] = mitre_new
            logger.info(f"DB Init: MITRE complete → {mitre_new} new")
        except Exception as e:
            logger.error(f"DB Init MITRE failed: {e}", exc_info=True)

        # 4. RedHat — fetch then batch-commit
        try:
            redhat_cves = await self.redhat.fetch_all()
            batch_size = 5000
            redhat_new = 0
            for i in range(0, len(redhat_cves), batch_size):
                chunk = redhat_cves[i:i + batch_size]
                new, existing = await dedup_and_store_bulk(session, chunk)
                await session.commit()
                redhat_new += len(new)
                total_new += len(new)
                total_existing += existing
            del redhat_cves
            source_stats["REDHAT"] = redhat_new
            logger.info(f"DB Init: RedHat complete → {redhat_new} new")
        except Exception as e:
            logger.error(f"DB Init RedHat failed: {e}", exc_info=True)

        logger.info(f"DB Init complete: {total_new} new, {total_existing} merged/existing")
        return {
            "total_new": total_new,
            "already_existed": total_existing,
            "sources": source_stats,
        }

    async def initialize_db_from_directory(
        self,
        session: AsyncSession,
        mitre_dir: Optional[str] = None,
        nvd_dir: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Bulk import from locally downloaded data directories.

        Steps for manual import:
        1. MITRE: git clone https://github.com/CVEProject/cvelistV5.git
           Then pass the /path/to/cvelistV5/cves directory
        2. NVD: Download NVD JSON feeds from https://nvd.nist.gov/feeds/json/cve/1.1/
           Then pass the extracted directory

        This is much faster than API-based download.
        """
        logger.info("DB Init: Starting bulk import from local directories")
        all_cves: List[NormalizedCVE] = []

        # Import from MITRE local directory
        if mitre_dir:
            logger.info(f"DB Init: Importing MITRE CVEs from {mitre_dir}")
            mitre_cves = self.mitre.parse_from_directory(mitre_dir)
            all_cves.extend(mitre_cves)
            logger.info(f"DB Init: {len(mitre_cves)} CVEs from MITRE local")

        # CISA KEV (always fetched from API — it's small)
        try:
            kev_cves = await self.kev.fetch_all()
            kev_ids = {c.cve_id for c in kev_cves}
            for cve in all_cves:
                if cve.cve_id in kev_ids:
                    cve.kev_flag = True
            all_cves.extend(kev_cves)
            logger.info(f"DB Init: {len(kev_cves)} from CISA KEV")
        except Exception as e:
            logger.error(f"DB Init CISA failed: {e}")

        # RedHat (API-based, but faster than NVD)
        try:
            redhat_cves = await self.redhat.fetch_all()
            all_cves.extend(redhat_cves)
            logger.info(f"DB Init: {len(redhat_cves)} from RedHat")
        except Exception as e:
            logger.error(f"DB Init RedHat failed: {e}")

        # Store all
        logger.info(f"DB Init local: Storing {len(all_cves)} total CVEs")

        # Process in batches to avoid memory issues
        batch_size = 5000
        total_new = 0
        total_existing = 0
        for i in range(0, len(all_cves), batch_size):
            batch = all_cves[i:i + batch_size]
            new_cves, existing = await dedup_and_store_bulk(session, batch)
            total_new += len(new_cves)
            total_existing += existing
            await session.commit()
            logger.info(
                f"DB Init batch {i // batch_size + 1}: "
                f"{len(new_cves)} new, {existing} existing"
            )

        return {
            "total_fetched": len(all_cves),
            "new_stored": total_new,
            "already_existed": total_existing,
        }
