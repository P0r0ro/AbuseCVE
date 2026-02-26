"""NVD API 2.0 connector with local mirroring support.

Implements the NVD-recommended approach:
1. Initial population: Download full dataset with max page size (2000)
2. Incremental updates: Use lastModStartDate/lastModEndDate for changes
3. Sync no more than once every 2 hours
4. Respect rate limits: 50 req/30s with key, 5 req/30s without
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timedelta
from typing import List, Optional

import httpx

from app.engine.sources.base import BaseCVESource, NormalizedCVE
from app.config import settings

logger = logging.getLogger(__name__)

NVD_CVE_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
MAX_PAGE_SIZE = 2000
RATE_LIMIT_WITH_KEY = (50, 30)   # 50 requests per 30 seconds
RATE_LIMIT_NO_KEY = (5, 30)      # 5 requests per 30 seconds


class NVDSource(BaseCVESource):
    name = "NVD"

    def __init__(self):
        self.api_key = settings.nvd_api_key
        self._request_times: list[float] = []

    def _headers(self) -> dict:
        headers = {"Accept": "application/json"}
        if self.api_key:
            headers["apiKey"] = self.api_key
        return headers

    async def _rate_limit(self):
        """Enforce NVD rate limiting."""
        max_requests, window = (
            RATE_LIMIT_WITH_KEY if self.api_key else RATE_LIMIT_NO_KEY
        )
        now = asyncio.get_event_loop().time()
        # Remove old timestamps
        self._request_times = [t for t in self._request_times if now - t < window]
        if len(self._request_times) >= max_requests:
            sleep_time = window - (now - self._request_times[0]) + 0.5
            logger.debug(f"NVD rate limit: sleeping {sleep_time:.1f}s")
            await asyncio.sleep(sleep_time)
        self._request_times.append(asyncio.get_event_loop().time())

    def _parse_cve(self, vuln: dict) -> NormalizedCVE:
        """Parse a single NVD CVE item into NormalizedCVE."""
        cve_data = vuln.get("cve", {})
        cve_id = cve_data.get("id", "")

        # Description
        descriptions = cve_data.get("descriptions", [])
        description = ""
        for desc in descriptions:
            if desc.get("lang") == "en":
                description = desc.get("value", "")
                break
        if not description and descriptions:
            description = descriptions[0].get("value", "")

        # CVSS scoring — try v3.1, then v3.0, then v2.0
        severity = None
        cvss_score = None
        cvss_vector = None
        cvss_scores = {}
        metrics = cve_data.get("metrics", {})

        version_map = {"cvssMetricV31": "3.1", "cvssMetricV30": "3.0", "cvssMetricV2": "2.0"}
        for version_key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
            metric_list = metrics.get(version_key, [])
            if metric_list:
                primary = metric_list[0]
                cvss_data = primary.get("cvssData", {})
                score = cvss_data.get("baseScore")
                vector = cvss_data.get("vectorString")
                sev = primary.get("baseSeverity") or cvss_data.get("baseSeverity")
                source_name = primary.get("source", "NVD")
                cvss_scores[source_name] = {
                    "score": score,
                    "vector": vector,
                    "version": version_map[version_key],
                    "severity": sev.upper() if sev else None,
                }
                if cvss_score is None:
                    cvss_score = score
                    cvss_vector = vector
                    severity = sev

        if severity:
            severity = severity.upper()

        # CPE names and vendor/product extraction
        cpe_names = []
        vendor = None
        product = None
        configurations = cve_data.get("configurations", [])
        for config in configurations:
            for node in config.get("nodes", []):
                for match in node.get("cpeMatch", []):
                    cpe = match.get("criteria", "")
                    if cpe:
                        cpe_names.append(cpe)
                        # Extract vendor/product from CPE 2.3
                        # cpe:2.3:a:vendor:product:...
                        parts = cpe.split(":")
                        if len(parts) >= 5 and not vendor:
                            vendor = parts[3]
                            product = parts[4]

        # References
        references = [
            ref.get("url", "")
            for ref in cve_data.get("references", [])
            if ref.get("url")
        ]

        # Dates
        published = cve_data.get("published")
        modified = cve_data.get("lastModified")
        pub_date = datetime.fromisoformat(published.replace("Z", "+00:00")) if published else None
        mod_date = datetime.fromisoformat(modified.replace("Z", "+00:00")) if modified else None

        # Weaknesses (CWE)
        weaknesses = []
        for weakness in cve_data.get("weaknesses", []):
            for desc in weakness.get("description", []):
                val = desc.get("value", "")
                if val.startswith("CWE-"):
                    weaknesses.append(val)

        return NormalizedCVE(
            cve_id=cve_id,
            vendor=vendor,
            product=product,
            description=description,
            severity=severity,
            cvss_score=cvss_score,
            cvss_vector=cvss_vector,
            source="NVD",
            published_date=pub_date,
            modified_date=mod_date,
            kev_flag=False,
            cpe_names=cpe_names,
            references=references,
            raw_json=cve_data,
            cvss_scores=cvss_scores,
            weaknesses=weaknesses,
        )

    async def _fetch_page(
        self,
        client: httpx.AsyncClient,
        params: dict,
    ) -> dict:
        """Fetch a single page from NVD API with rate limiting and retries."""
        await self._rate_limit()
        for attempt in range(3):
            try:
                resp = await client.get(
                    NVD_CVE_API,
                    params=params,
                    headers=self._headers(),
                    timeout=60.0,
                )
                if resp.status_code == 403:
                    logger.warning("NVD API 403 — rate limited, backing off...")
                    await asyncio.sleep(30 * (attempt + 1))
                    continue
                resp.raise_for_status()
                return resp.json()
            except httpx.HTTPStatusError as e:
                logger.error(f"NVD API error: {e.response.status_code}")
                if attempt < 2:
                    await asyncio.sleep(10 * (attempt + 1))
            except httpx.RequestError as e:
                logger.error(f"NVD request error: {e}")
                if attempt < 2:
                    await asyncio.sleep(10 * (attempt + 1))
        return {"vulnerabilities": [], "totalResults": 0}

    async def fetch_recent(self, since: Optional[datetime] = None) -> List[NormalizedCVE]:
        """Fetch CVEs modified since the given date (incremental sync)."""
        if since is None:
            since = datetime.utcnow() - timedelta(hours=2)

        params = {
            "lastModStartDate": since.strftime("%Y-%m-%dT%H:%M:%S.000"),
            "lastModEndDate": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.000"),
            "resultsPerPage": MAX_PAGE_SIZE,
            "startIndex": 0,
        }

        results: List[NormalizedCVE] = []
        async with httpx.AsyncClient() as client:
            while True:
                data = await self._fetch_page(client, params)
                vulns = data.get("vulnerabilities", [])
                for vuln in vulns:
                    try:
                        results.append(self._parse_cve(vuln))
                    except Exception as e:
                        logger.warning(f"Failed to parse CVE: {e}")

                total = data.get("totalResults", 0)
                fetched = params["startIndex"] + len(vulns)
                logger.info(f"NVD incremental: {fetched}/{total} CVEs fetched")

                if fetched >= total or not vulns:
                    break
                params["startIndex"] = fetched

        logger.info(f"NVD fetch_recent: {len(results)} CVEs since {since}")
        return results

    async def fetch_by_keyword(self, keyword: str) -> List[NormalizedCVE]:
        """Fetch CVEs matching a keyword."""
        params = {
            "keywordSearch": keyword,
            "resultsPerPage": MAX_PAGE_SIZE,
            "startIndex": 0,
        }

        results: List[NormalizedCVE] = []
        async with httpx.AsyncClient() as client:
            data = await self._fetch_page(client, params)
            for vuln in data.get("vulnerabilities", []):
                try:
                    results.append(self._parse_cve(vuln))
                except Exception as e:
                    logger.warning(f"Failed to parse CVE: {e}")

        logger.info(f"NVD keyword '{keyword}': {len(results)} CVEs found")
        return results

    async def fetch_all_batched(self, start_index: int = 0, page_size: int = 2000):
        """Fetch ALL CVEs as an async generator, yielding one page at a time.

        Yields (batch: List[NormalizedCVE], fetched: int, total: int) tuples.
        This keeps memory usage bounded — only one page (~2000 CVEs) in RAM.
        """
        params = {
            "resultsPerPage": min(page_size, MAX_PAGE_SIZE),
            "startIndex": start_index,
        }

        async with httpx.AsyncClient() as client:
            while True:
                data = await self._fetch_page(client, params)
                vulns = data.get("vulnerabilities", [])
                batch = []
                for vuln in vulns:
                    try:
                        batch.append(self._parse_cve(vuln))
                    except Exception as e:
                        logger.warning(f"Failed to parse CVE: {e}")

                total = data.get("totalResults", 0)
                fetched = params["startIndex"] + len(vulns)
                logger.info(f"NVD full mirror: {fetched}/{total} CVEs fetched")

                yield batch, fetched, total

                if fetched >= total or not vulns:
                    break
                params["startIndex"] = fetched

    async def fetch_all(self, start_index: int = 0, page_size: int = 2000) -> List[NormalizedCVE]:
        """Fetch ALL CVEs (non-streaming, for backwards compat)."""
        results: List[NormalizedCVE] = []
        async for batch, fetched, total in self.fetch_all_batched(start_index, page_size):
            results.extend(batch)
        return results

    async def fetch_by_cpe(self, cpe_name: str) -> List[NormalizedCVE]:
        """Fetch CVEs for a specific CPE name (e.g., cpe:2.3:a:fortinet:*)."""
        params = {
            "cpeName": cpe_name,
            "resultsPerPage": MAX_PAGE_SIZE,
            "startIndex": 0,
        }

        results: List[NormalizedCVE] = []
        async with httpx.AsyncClient() as client:
            while True:
                data = await self._fetch_page(client, params)
                vulns = data.get("vulnerabilities", [])
                for vuln in vulns:
                    try:
                        results.append(self._parse_cve(vuln))
                    except Exception as e:
                        logger.warning(f"Failed to parse CVE: {e}")

                total = data.get("totalResults", 0)
                fetched = params["startIndex"] + len(vulns)
                if fetched >= total or not vulns:
                    break
                params["startIndex"] = fetched

        logger.info(f"NVD CPE '{cpe_name}': {len(results)} CVEs found")
        return results
