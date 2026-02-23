"""CVE Pipeline – orchestrates the full fetch → pool → filter → dedup → alert flow.

Uses Redis as the log aggregation pool between stages:
1. FETCH: Pull CVEs from all sources → push to Redis pool
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
from app.engine.sources.base import NormalizedCVE
from app.engine.filter_engine import filter_cves, FilterMatch
from app.engine.dedup import dedup_and_store
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

    async def _get_redis(self) -> aioredis.Redis:
        return aioredis.from_url(settings.redis_url, decode_responses=True)

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
            logger.error(f"NVD fetch failed: {e}")

        # Fetch from CISA KEV
        try:
            kev_cves = await self.kev.fetch_recent(since=since)
            all_cves.extend(kev_cves)
            logger.info(f"Fetched {len(kev_cves)} CVEs from CISA KEV")
        except Exception as e:
            logger.error(f"CISA KEV fetch failed: {e}")

        # Push to Redis pool (serialized)
        pooled = 0
        for cve in all_cves:
            cve_json = json.dumps({
                "cve_id": cve.cve_id,
                "vendor": cve.vendor,
                "product": cve.product,
                "description": cve.description,
                "severity": cve.severity,
                "cvss_score": cve.cvss_score,
                "cvss_vector": cve.cvss_vector,
                "source": cve.source,
                "published_date": cve.published_date.isoformat() if cve.published_date else None,
                "modified_date": cve.modified_date.isoformat() if cve.modified_date else None,
                "kev_flag": cve.kev_flag,
                "cpe_names": cve.cpe_names,
                "references": cve.references,
                "raw_json": cve.raw_json,
            })
            await r.rpush(REDIS_CVE_POOL, cve_json)
            pooled += 1

        # Update last sync time
        await r.set(REDIS_LAST_SYNC, datetime.utcnow().isoformat())
        await r.aclose()

        logger.info(f"Pipeline FETCH: {pooled} CVEs pushed to pool")
        return pooled

    # ── Stage 2 & 3: FILTER + DEDUP ──────────────────────
    async def process_pool(self, session: AsyncSession) -> Dict[str, Any]:
        """Pop CVEs from pool, filter, dedup, and return results.

        Returns dict with new_cves, existing_count, and matches.
        """
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
            try:
                data = json.loads(raw)
                pub_date = None
                if data.get("published_date"):
                    pub_date = datetime.fromisoformat(data["published_date"])
                mod_date = None
                if data.get("modified_date"):
                    mod_date = datetime.fromisoformat(data["modified_date"])

                cves.append(NormalizedCVE(
                    cve_id=data["cve_id"],
                    vendor=data.get("vendor"),
                    product=data.get("product"),
                    description=data.get("description"),
                    severity=data.get("severity"),
                    cvss_score=data.get("cvss_score"),
                    cvss_vector=data.get("cvss_vector"),
                    source=data.get("source", "UNKNOWN"),
                    published_date=pub_date,
                    modified_date=mod_date,
                    kev_flag=data.get("kev_flag", False),
                    cpe_names=data.get("cpe_names", []),
                    references=data.get("references", []),
                    raw_json=data.get("raw_json"),
                ))
            except Exception as e:
                logger.warning(f"Failed to deserialize CVE from pool: {e}")

        logger.info(f"Pipeline PROCESS: {len(cves)} CVEs from pool")

        # Load active filter rules
        result = await session.execute(
            select(FilterRule).where(FilterRule.enabled == True)
        )
        rules = [r.to_dict() for r in result.scalars().all()]

        if not rules:
            logger.warning("No active filter rules — skipping filter stage")
            return {"new_cves": [], "existing_count": 0, "filtered_count": 0}

        # Apply filters
        matches = filter_cves(cves, rules)
        logger.info(f"Pipeline FILTER: {len(matches)} CVEs passed filters")

        # Dedup matched CVEs
        matched_cves = [m.cve for m in matches]
        new_cves, existing_count = await dedup_and_store(session, matched_cves)

        await session.commit()

        return {
            "new_cves": new_cves,
            "existing_count": existing_count,
            "filtered_count": len(matches),
            "total_pooled": len(cves),
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

    # ── Initialize DB (bulk import) ──────────────────────
    async def initialize_db(
        self,
        session: AsyncSession,
        vendor_keyword: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Bulk-import past CVEs for vendor into the database.

        Uses NVD keyword search or full download for initial population.
        """
        logger.info(f"DB Init: Starting bulk import" +
                    (f" for vendor={vendor_keyword}" if vendor_keyword else ""))

        if vendor_keyword:
            cves = await self.nvd.fetch_by_keyword(vendor_keyword)
        else:
            cves = await self.nvd.fetch_all()

        # Also check KEV
        kev_cves = await self.kev.fetch_all()
        kev_ids = {c.cve_id for c in kev_cves}

        # Mark KEV flags
        for cve in cves:
            if cve.cve_id in kev_ids:
                cve.kev_flag = True

        # Store all (dedup handles duplicates)
        new_cves, existing = await dedup_and_store(session, cves)
        await session.commit()

        logger.info(f"DB Init complete: {len(new_cves)} new, {existing} existing")
        return {
            "total_fetched": len(cves),
            "new_stored": len(new_cves),
            "already_existed": existing,
        }
