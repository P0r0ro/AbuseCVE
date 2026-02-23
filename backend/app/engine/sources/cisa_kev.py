"""CISA Known Exploited Vulnerabilities (KEV) catalog connector."""

from __future__ import annotations

import logging
from datetime import datetime
from typing import List, Optional

import httpx

from app.engine.sources.base import BaseCVESource, NormalizedCVE

logger = logging.getLogger(__name__)

KEV_FEED_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


class CISAKEVSource(BaseCVESource):
    name = "CISA_KEV"

    def _parse_vuln(self, vuln: dict) -> NormalizedCVE:
        """Parse a CISA KEV entry into NormalizedCVE."""
        cve_id = vuln.get("cveID", "")
        vendor = vuln.get("vendorProject", "")
        product = vuln.get("product", "")
        description = vuln.get("shortDescription", "")

        # Dates
        date_added = vuln.get("dateAdded")
        pub_date = None
        if date_added:
            try:
                pub_date = datetime.strptime(date_added, "%Y-%m-%d")
            except ValueError:
                pass

        due_date = vuln.get("dueDate")

        return NormalizedCVE(
            cve_id=cve_id,
            vendor=vendor.lower() if vendor else None,
            product=product.lower() if product else None,
            description=description,
            severity=None,  # KEV doesn't include CVSS, enrich from NVD later
            cvss_score=None,
            source="CISA_KEV",
            published_date=pub_date,
            kev_flag=True,
            references=[f"https://nvd.nist.gov/vuln/detail/{cve_id}"],
            raw_json=vuln,
        )

    async def _fetch_catalog(self) -> List[dict]:
        """Download the full KEV catalog JSON."""
        async with httpx.AsyncClient() as client:
            for attempt in range(3):
                try:
                    resp = await client.get(KEV_FEED_URL, timeout=60.0)
                    resp.raise_for_status()
                    data = resp.json()
                    return data.get("vulnerabilities", [])
                except Exception as e:
                    logger.error(f"CISA KEV fetch error (attempt {attempt + 1}): {e}")
                    if attempt < 2:
                        import asyncio
                        await asyncio.sleep(5 * (attempt + 1))
        return []

    async def fetch_recent(self, since: Optional[datetime] = None) -> List[NormalizedCVE]:
        """Fetch KEV entries added since a given date."""
        vulns = await self._fetch_catalog()
        results: List[NormalizedCVE] = []

        for vuln in vulns:
            parsed = self._parse_vuln(vuln)
            if since and parsed.published_date and parsed.published_date < since:
                continue
            results.append(parsed)

        logger.info(f"CISA KEV: {len(results)} entries" +
                    (f" since {since}" if since else ""))
        return results

    async def fetch_by_keyword(self, keyword: str) -> List[NormalizedCVE]:
        """Filter KEV entries by keyword in description/product/vendor."""
        vulns = await self._fetch_catalog()
        keyword_lower = keyword.lower()
        results: List[NormalizedCVE] = []

        for vuln in vulns:
            searchable = " ".join([
                vuln.get("vendorProject", ""),
                vuln.get("product", ""),
                vuln.get("shortDescription", ""),
                vuln.get("cveID", ""),
            ]).lower()
            if keyword_lower in searchable:
                results.append(self._parse_vuln(vuln))

        logger.info(f"CISA KEV keyword '{keyword}': {len(results)} entries")
        return results

    async def fetch_all(self, start_index: int = 0, page_size: int = 2000) -> List[NormalizedCVE]:
        """Fetch entire KEV catalog."""
        vulns = await self._fetch_catalog()
        results = [self._parse_vuln(v) for v in vulns[start_index:]]
        logger.info(f"CISA KEV full catalog: {len(results)} entries")
        return results
