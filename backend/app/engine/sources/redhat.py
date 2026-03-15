"""RedHat Security Data API connector.

API docs: https://access.redhat.com/hydra/rest/securitydata
Endpoints:
  - GET /cve.json — list CVEs with filtering
  - GET /cve/{CVE-ID}.json — CVE detail
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timedelta
from typing import List, Optional

import httpx

from app.engine.sources.base import BaseCVESource, NormalizedCVE

logger = logging.getLogger(__name__)

REDHAT_API = "https://access.redhat.com/hydra/rest/securitydata"
PAGE_SIZE = 1000  # RedHat API max per_page


class RedHatSource(BaseCVESource):
    name = "REDHAT"

    def __init__(self):
        self._request_times: list[float] = []

    async def _rate_limit(self):
        """Simple rate limiter: max 10 req/10s."""
        now = asyncio.get_event_loop().time()
        self._request_times = [t for t in self._request_times if now - t < 10]
        if len(self._request_times) >= 10:
            sleep_time = 10 - (now - self._request_times[0]) + 0.5
            logger.debug(f"RedHat rate limit: sleeping {sleep_time:.1f}s")
            await asyncio.sleep(sleep_time)
        self._request_times.append(asyncio.get_event_loop().time())

    def _parse_list_item(self, item: dict) -> NormalizedCVE:
        """Parse a CVE from the /cve.json list endpoint."""
        cve_id = item.get("CVE", "")
        severity = (item.get("severity") or "").upper()
        cvss_score = item.get("cvss3_score")
        if cvss_score:
            try:
                cvss_score = float(cvss_score)
            except (ValueError, TypeError):
                cvss_score = None

        # Map severity string
        if not severity and cvss_score:
            if cvss_score >= 9.0:
                severity = "CRITICAL"
            elif cvss_score >= 7.0:
                severity = "HIGH"
            elif cvss_score >= 4.0:
                severity = "MEDIUM"
            else:
                severity = "LOW"

        pub_date = None
        date_str = item.get("public_date")
        if date_str:
            try:
                pub_date = datetime.fromisoformat(date_str.replace("Z", "+00:00"))
            except Exception:
                try:
                    pub_date = datetime.strptime(date_str[:10], "%Y-%m-%d")
                except Exception:
                    pass

        cvss_scores = {}
        if cvss_score:
            cvss_scores["REDHAT"] = {
                "score": cvss_score,
                "vector": item.get("cvss3_scoring_vector"),
                "version": "3.1",
                "severity": severity,
            }

        # Also extract CVSS2 if available
        cvss2 = item.get("cvss_score")
        if cvss2:
            try:
                cvss_scores["REDHAT_V2"] = {
                    "score": float(cvss2),
                    "vector": item.get("cvss_scoring_vector"),
                    "version": "2.0",
                    "severity": None,
                }
            except (ValueError, TypeError):
                pass

        # Affected packages → products
        affected_packages = item.get("affected_packages", [])
        affected_products = item.get("affected_release", [])

        # Extract product from available data
        from app.engine.vendor_product_extractor import extract_from_redhat_raw
        _, product = extract_from_redhat_raw(item)

        return NormalizedCVE(
            cve_id=cve_id,
            vendor="redhat",
            product=product,
            description=item.get("bugzilla_description", ""),
            severity=severity,
            cvss_score=cvss_score,
            cvss_vector=item.get("cvss3_scoring_vector"),
            source="REDHAT",
            published_date=pub_date,
            kev_flag=False,
            references=[
                item.get("resource_url", ""),
                item.get("bugzilla", ""),
            ],
            raw_json=item,
            cvss_scores=cvss_scores,
            weaknesses=[item.get("CWE", "")] if item.get("CWE") else [],
            affected_products=affected_packages[:20] if affected_packages else [],
        )

    def _parse_detail(self, data: dict) -> NormalizedCVE:
        """Parse a CVE from the /cve/{ID}.json detail endpoint."""
        cve_id = data.get("name", "")

        # Description from details or bugzilla
        description = ""
        details = data.get("details", [])
        if details:
            description = " ".join(details)
        if not description:
            description = data.get("bugzilla", {}).get("description", "")

        # CVSS
        cvss3 = data.get("cvss3", {})
        cvss_score = None
        cvss_vector = None
        severity = (data.get("threat_severity") or "").upper()

        if cvss3:
            cvss_score = cvss3.get("cvss3_base_score")
            cvss_vector = cvss3.get("cvss3_scoring_vector")
            if cvss_score:
                try:
                    cvss_score = float(cvss_score)
                except (ValueError, TypeError):
                    cvss_score = None

        # Map severity
        severity_map = {"LOW": "LOW", "MODERATE": "MEDIUM", "IMPORTANT": "HIGH", "CRITICAL": "CRITICAL"}
        severity = severity_map.get(severity, severity) if severity else None

        cvss_scores = {}
        if cvss_score:
            cvss_scores["REDHAT"] = {
                "score": cvss_score,
                "vector": cvss_vector,
                "version": "3.1",
                "severity": severity,
            }

        pub_date = None
        date_str = data.get("public_date")
        if date_str:
            try:
                pub_date = datetime.fromisoformat(date_str.replace("Z", "+00:00"))
            except Exception:
                pass

        # Affected products
        affected = []
        for release in data.get("affected_release", []):
            pkg = release.get("package")
            if pkg:
                affected.append(pkg)

        # References
        references = []
        if data.get("bugzilla", {}).get("url"):
            references.append(data["bugzilla"]["url"])
        references.append(f"https://access.redhat.com/security/cve/{cve_id}")

        # Weaknesses
        weaknesses = []
        cwe = data.get("cwe")
        if cwe:
            weaknesses.append(cwe)

        # Extract product from detail data
        from app.engine.vendor_product_extractor import extract_from_redhat_raw
        _, detail_product = extract_from_redhat_raw(data)

        return NormalizedCVE(
            cve_id=cve_id,
            vendor="redhat",
            product=detail_product,
            description=description,
            severity=severity,
            cvss_score=cvss_score,
            cvss_vector=cvss_vector,
            source="REDHAT",
            published_date=pub_date,
            kev_flag=False,
            references=references,
            raw_json=data,
            cvss_scores=cvss_scores,
            weaknesses=weaknesses,
            affected_products=affected[:20],
        )

    async def _fetch_page(
        self,
        client: httpx.AsyncClient,
        params: dict,
    ) -> list:
        """Fetch a single page from RedHat API with rate limiting."""
        await self._rate_limit()
        for attempt in range(3):
            try:
                resp = await client.get(
                    f"{REDHAT_API}/cve.json",
                    params=params,
                    timeout=60.0,
                )
                if resp.status_code == 429:
                    logger.warning("RedHat API 429 — rate limited, backing off...")
                    await asyncio.sleep(30 * (attempt + 1))
                    continue
                resp.raise_for_status()
                return resp.json()
            except httpx.HTTPStatusError as e:
                logger.error(f"RedHat API error: {e.response.status_code}")
                if attempt < 2:
                    await asyncio.sleep(10 * (attempt + 1))
            except httpx.RequestError as e:
                logger.error(f"RedHat request error: {e}")
                if attempt < 2:
                    await asyncio.sleep(10 * (attempt + 1))
        return []

    async def fetch_recent(self, since: Optional[datetime] = None) -> List[NormalizedCVE]:
        """Fetch CVEs modified/created since a given date."""
        if since is None:
            since = datetime.utcnow() - timedelta(hours=2)

        params = {
            "after": since.strftime("%Y-%m-%d"),
            "per_page": PAGE_SIZE,
            "page": 1,
        }

        results: List[NormalizedCVE] = []
        async with httpx.AsyncClient() as client:
            while True:
                items = await self._fetch_page(client, params)
                if not items:
                    break

                for item in items:
                    try:
                        results.append(self._parse_list_item(item))
                    except Exception as e:
                        logger.warning(f"Failed to parse RedHat CVE: {e}")

                logger.info(f"RedHat: page {params['page']}, {len(items)} items")

                if len(items) < PAGE_SIZE:
                    break
                params["page"] += 1

        logger.info(f"RedHat fetch_recent: {len(results)} CVEs since {since}")
        return results

    async def fetch_by_keyword(self, keyword: str) -> List[NormalizedCVE]:
        """Search RedHat CVEs by keyword."""
        results: List[NormalizedCVE] = []
        async with httpx.AsyncClient() as client:
            items = await self._fetch_page(client, {
                "bug": keyword,
                "per_page": PAGE_SIZE,
            })
            for item in items:
                try:
                    results.append(self._parse_list_item(item))
                except Exception as e:
                    logger.warning(f"Failed to parse RedHat CVE: {e}")

        logger.info(f"RedHat keyword '{keyword}': {len(results)} CVEs")
        return results

    async def fetch_all(self, start_index: int = 0, page_size: int = 1000) -> List[NormalizedCVE]:
        """Fetch ALL RedHat CVEs (paginated)."""
        results: List[NormalizedCVE] = []
        page = (start_index // page_size) + 1

        async with httpx.AsyncClient() as client:
            while True:
                items = await self._fetch_page(client, {
                    "per_page": page_size,
                    "page": page,
                })
                if not items:
                    break

                for item in items:
                    try:
                        results.append(self._parse_list_item(item))
                    except Exception as e:
                        logger.warning(f"Failed to parse RedHat CVE: {e}")

                logger.info(f"RedHat full: page {page}, total {len(results)} CVEs so far")

                if len(items) < page_size:
                    break
                page += 1

        logger.info(f"RedHat fetch_all: {len(results)} total CVEs")
        return results
