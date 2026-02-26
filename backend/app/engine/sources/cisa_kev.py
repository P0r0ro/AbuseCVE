"""CISA Known Exploited Vulnerabilities (KEV) catalog + Vulnrichment connector.

Sources:
- KEV catalog: https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
- Vulnrichment: https://github.com/cisagov/vulnrichment (enriched CVSS/CWE/SSVC)
"""

from __future__ import annotations

import asyncio
import json
import logging
import zipfile
import io
from datetime import datetime
from typing import List, Optional, Dict

import httpx

from app.engine.sources.base import BaseCVESource, NormalizedCVE

logger = logging.getLogger(__name__)

KEV_FEED_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
VULNRICHMENT_API = "https://api.github.com/repos/cisagov/vulnrichment"


class CISAKEVSource(BaseCVESource):
    name = "CISA_KEV"

    def _parse_vuln(self, vuln: dict, enrichment: Optional[dict] = None) -> NormalizedCVE:
        """Parse a CISA KEV entry into NormalizedCVE, optionally enriched."""
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

        # CVSS from enrichment
        cvss_score = None
        cvss_vector = None
        severity = None
        cvss_scores = {}
        weaknesses = []

        if enrichment:
            # Parse vulnrichment data (CVE JSON 5.0 ADP format)
            containers = enrichment.get("containers", {})
            adp_list = containers.get("adp", [])
            for adp in adp_list:
                provider = adp.get("providerMetadata", {}).get("shortName", "CISA-ADP")
                metrics = adp.get("metrics", [])
                for metric in metrics:
                    for key in ["cvssV4_0", "cvssV3_1", "cvssV3_0"]:
                        if key in metric:
                            cvss_data = metric[key]
                            score = cvss_data.get("baseScore")
                            vector = cvss_data.get("vectorString")
                            sev = cvss_data.get("baseSeverity")
                            version = key.replace("cvssV", "").replace("_", ".")
                            cvss_scores[provider] = {
                                "score": score,
                                "vector": vector,
                                "version": version,
                                "severity": sev.upper() if sev else None,
                            }
                            if score and cvss_score is None:
                                cvss_score = score
                                cvss_vector = vector
                                severity = sev.upper() if sev else None
                            break

                # SSVC decision
                for metric in metrics:
                    if "other" in metric:
                        other = metric["other"]
                        if other.get("type") == "ssvc":
                            pass  # Store SSVC data if needed later

                # CWE from enrichment
                for pt in adp.get("problemTypes", []):
                    for desc in pt.get("descriptions", []):
                        cwe_id = desc.get("cweId")
                        if cwe_id:
                            weaknesses.append(cwe_id)

        return NormalizedCVE(
            cve_id=cve_id,
            vendor=vendor.lower() if vendor else None,
            product=product.lower() if product else None,
            description=description,
            severity=severity,
            cvss_score=cvss_score,
            cvss_vector=cvss_vector,
            source="CISA_KEV",
            published_date=pub_date,
            kev_flag=True,
            references=[f"https://nvd.nist.gov/vuln/detail/{cve_id}"],
            raw_json=vuln,
            cvss_scores=cvss_scores,
            weaknesses=weaknesses,
            affected_products=[f"{vendor} {product}"] if vendor and product else [],
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
                        await asyncio.sleep(5 * (attempt + 1))
        return []

    async def _fetch_vulnrichment_index(self) -> Dict[str, dict]:
        """Fetch vulnrichment data for enrichment (recent delta releases)."""
        enrichment: Dict[str, dict] = {}
        try:
            async with httpx.AsyncClient(timeout=120.0) as client:
                # Get latest release with delta zip
                resp = await client.get(
                    f"{VULNRICHMENT_API}/releases",
                    params={"per_page": 3},
                    headers={"Accept": "application/vnd.github+json"},
                )
                if resp.status_code != 200:
                    return enrichment

                releases = resp.json()
                for release in releases[:1]:  # Only latest release
                    for asset in release.get("assets", []):
                        if asset["name"].endswith(".zip"):
                            zip_url = asset["browser_download_url"]
                            zip_resp = await client.get(zip_url, follow_redirects=True)
                            if zip_resp.status_code == 200:
                                with zipfile.ZipFile(io.BytesIO(zip_resp.content)) as zf:
                                    for name in zf.namelist():
                                        if name.endswith(".json") and "CVE-" in name:
                                            try:
                                                data = json.loads(zf.read(name))
                                                cve_id = data.get("cveMetadata", {}).get("cveId", "")
                                                if cve_id:
                                                    enrichment[cve_id] = data
                                            except Exception:
                                                pass
                            break
        except Exception as e:
            logger.warning(f"Vulnrichment fetch failed (non-critical): {e}")

        logger.info(f"CISA vulnrichment: {len(enrichment)} enrichment records loaded")
        return enrichment

    async def fetch_recent(self, since: Optional[datetime] = None) -> List[NormalizedCVE]:
        """Fetch KEV entries added since a given date."""
        vulns = await self._fetch_catalog()
        enrichment = await self._fetch_vulnrichment_index()
        results: List[NormalizedCVE] = []

        for vuln in vulns:
            cve_id = vuln.get("cveID", "")
            parsed = self._parse_vuln(vuln, enrichment.get(cve_id))
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
        """Fetch entire KEV catalog with enrichment."""
        vulns = await self._fetch_catalog()
        enrichment = await self._fetch_vulnrichment_index()

        results = [
            self._parse_vuln(v, enrichment.get(v.get("cveID", "")))
            for v in vulns[start_index:]
        ]
        logger.info(f"CISA KEV full catalog: {len(results)} entries")
        return results
