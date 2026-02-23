"""Deduplication logic – checks CVEs against the database.

If CVE exists: increment seen_count, update last_seen, skip alerting.
If CVE is new: insert it, flag for alerting.
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import List, Tuple

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.engine.sources.base import NormalizedCVE
from app.models.cve import CVE

logger = logging.getLogger(__name__)


async def dedup_and_store(
    session: AsyncSession,
    cves: List[NormalizedCVE],
) -> Tuple[List[NormalizedCVE], int]:
    """Check CVEs against DB. Store new ones, increment counter for existing.

    Returns:
        (new_cves, existing_count) - list of truly new CVEs and count of existing
    """
    new_cves: List[NormalizedCVE] = []
    existing_count = 0

    for cve_data in cves:
        # Check if CVE exists
        result = await session.execute(
            select(CVE).where(CVE.cve_id == cve_data.cve_id)
        )
        existing = result.scalar_one_or_none()

        if existing:
            # CVE exists → increment counter, update last_seen
            existing.seen_count = (existing.seen_count or 0) + 1
            existing.last_seen = datetime.utcnow()
            # Update KEV flag if newly flagged
            if cve_data.kev_flag and not existing.kev_flag:
                existing.kev_flag = True
            # Update CVSS if we now have a score and didn't before
            if cve_data.cvss_score and not existing.cvss_score:
                existing.cvss_score = cve_data.cvss_score
                existing.severity = cve_data.severity
                existing.cvss_vector = cve_data.cvss_vector
            existing_count += 1
            logger.debug(f"CVE {cve_data.cve_id} already exists (seen {existing.seen_count}x)")
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
            )
            session.add(new_record)
            new_cves.append(cve_data)
            logger.debug(f"CVE {cve_data.cve_id} is NEW — queued for alert")

    await session.flush()
    logger.info(f"Dedup: {len(new_cves)} new, {existing_count} existing")
    return new_cves, existing_count
