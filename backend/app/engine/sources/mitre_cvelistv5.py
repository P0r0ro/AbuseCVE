"""MITRE CVEListV5 connector — fetches from the cvelistV5 GitHub repository.

Supports two modes:
1. Bulk import via downloadable delta releases (ZIP) from GitHub releases
2. Incremental updates via GitHub API for recently changed files

The repository is at: https://github.com/CVEProject/cvelistV5
Delta downloads: https://github.com/CVEProject/cvelistV5/releases
"""

from __future__ import annotations

import asyncio
import json
import logging
import zipfile
import io
import os
import glob as glob_module
from datetime import datetime, timedelta
from typing import List, Optional

import httpx

from app.engine.sources.base import BaseCVESource, NormalizedCVE

logger = logging.getLogger(__name__)

GITHUB_API = "https://api.github.com"
REPO_OWNER = "CVEProject"
REPO_NAME = "cvelistV5"
DELTA_RELEASES_URL = f"{GITHUB_API}/repos/{REPO_OWNER}/{REPO_NAME}/releases"
# For full zip download
FULL_ZIP_URL = f"https://github.com/{REPO_OWNER}/{REPO_NAME}/archive/refs/heads/main.zip"


class MITRECVEListSource(BaseCVESource):
    name = "MITRE"

    def __init__(self):
        self._headers = {"Accept": "application/vnd.github+json"}
        # Rate limit tracking
        self._request_count = 0

    def _parse_cve_json5(self, data: dict) -> Optional[NormalizedCVE]:
        """Parse a CVE JSON 5.0 format record into NormalizedCVE."""
        try:
            cve_metadata = data.get("cveMetadata", {})
            cve_id = cve_metadata.get("cveId", "")
            if not cve_id:
                return None

            state = cve_metadata.get("state", "")
            if state == "REJECTED":
                return None

            # Published / modified dates
            date_published = cve_metadata.get("datePublished")
            date_updated = cve_metadata.get("dateUpdated")
            pub_date = None
            mod_date = None
            if date_published:
                try:
                    pub_date = datetime.fromisoformat(date_published.replace("Z", "+00:00"))
                except Exception:
                    pass
            if date_updated:
                try:
                    mod_date = datetime.fromisoformat(date_updated.replace("Z", "+00:00"))
                except Exception:
                    pass

            # Container data (CNA or ADP)
            containers = data.get("containers", {})
            cna = containers.get("cna", {})
            adp_list = containers.get("adp", [])

            # Description
            description = ""
            descriptions = cna.get("descriptions", [])
            for desc in descriptions:
                if desc.get("lang", "").startswith("en"):
                    description = desc.get("value", "")
                    break
            if not description and descriptions:
                description = descriptions[0].get("value", "")

            # CVSS from CNA
            cvss_score = None
            cvss_vector = None
            severity = None
            cvss_scores = {}

            metrics = cna.get("metrics", [])
            for metric in metrics:
                for key in ["cvssV4_0", "cvssV3_1", "cvssV3_0", "cvssV2_0"]:
                    if key in metric:
                        cvss_data = metric[key]
                        score = cvss_data.get("baseScore")
                        vector = cvss_data.get("vectorString")
                        sev = cvss_data.get("baseSeverity")
                        version = key.replace("cvssV", "").replace("_", ".")
                        if score and cvss_score is None:
                            cvss_score = score
                            cvss_vector = vector
                            severity = sev.upper() if sev else None
                        provider = cna.get("providerMetadata", {}).get("shortName", "MITRE")
                        cvss_scores[provider] = {
                            "score": score,
                            "vector": vector,
                            "version": version,
                            "severity": sev.upper() if sev else None,
                        }
                        break

            # Also check ADP containers for extra CVSS
            for adp in adp_list:
                adp_metrics = adp.get("metrics", [])
                adp_provider = adp.get("providerMetadata", {}).get("shortName", "ADP")
                for metric in adp_metrics:
                    for key in ["cvssV4_0", "cvssV3_1", "cvssV3_0", "cvssV2_0"]:
                        if key in metric:
                            cvss_data = metric[key]
                            score = cvss_data.get("baseScore")
                            vector = cvss_data.get("vectorString")
                            sev = cvss_data.get("baseSeverity")
                            version = key.replace("cvssV", "").replace("_", ".")
                            cvss_scores[adp_provider] = {
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

            # Affected products
            affected = cna.get("affected", [])
            vendor = None
            product = None
            cpe_names = []
            affected_products = []

            for aff in affected:
                v = aff.get("vendor", "")
                p = aff.get("product", "")
                if v and not vendor:
                    vendor = v.lower()
                if p and not product:
                    product = p.lower()
                if v and p:
                    affected_products.append(f"{v} {p}")
                # CPE
                for cpe_entry in aff.get("cpes", []):
                    if isinstance(cpe_entry, str):
                        cpe_names.append(cpe_entry)

            # References
            references = [
                ref.get("url", "")
                for ref in cna.get("references", [])
                if ref.get("url")
            ]

            # Weaknesses (CWE)
            weaknesses = []
            for w in cna.get("problemTypes", []):
                for desc in w.get("descriptions", []):
                    cwe_id = desc.get("cweId", "")
                    if cwe_id:
                        weaknesses.append(cwe_id)

            return NormalizedCVE(
                cve_id=cve_id,
                vendor=vendor,
                product=product,
                description=description,
                severity=severity,
                cvss_score=cvss_score,
                cvss_vector=cvss_vector,
                source="MITRE",
                published_date=pub_date,
                modified_date=mod_date,
                kev_flag=False,
                cpe_names=cpe_names,
                references=references,
                raw_json=data,
                cvss_scores=cvss_scores,
                weaknesses=weaknesses,
                affected_products=affected_products,
            )
        except Exception as e:
            logger.warning(f"Failed to parse MITRE CVE: {e}")
            return None

    async def fetch_recent(self, since: Optional[datetime] = None) -> List[NormalizedCVE]:
        """Fetch recently modified CVEs using GitHub delta releases."""
        if since is None:
            since = datetime.utcnow() - timedelta(hours=2)

        results: List[NormalizedCVE] = []

        async with httpx.AsyncClient(timeout=120.0) as client:
            try:
                # Get latest delta release
                resp = await client.get(
                    DELTA_RELEASES_URL,
                    headers=self._headers,
                    params={"per_page": 5},
                )
                resp.raise_for_status()
                releases = resp.json()

                for release in releases:
                    # Check if release is since our last sync
                    release_date = datetime.fromisoformat(
                        release["published_at"].replace("Z", "+00:00")
                    )
                    if release_date < since:
                        continue

                    # Find the delta zip asset
                    for asset in release.get("assets", []):
                        if "delta" in asset["name"].lower() and asset["name"].endswith(".zip"):
                            zip_url = asset["browser_download_url"]
                            logger.info(f"MITRE: Downloading delta {asset['name']}")
                            zip_resp = await client.get(zip_url, follow_redirects=True)
                            zip_resp.raise_for_status()

                            # Parse the zip
                            with zipfile.ZipFile(io.BytesIO(zip_resp.content)) as zf:
                                for name in zf.namelist():
                                    if name.endswith(".json") and "CVE-" in name:
                                        try:
                                            data = json.loads(zf.read(name))
                                            cve = self._parse_cve_json5(data)
                                            if cve:
                                                results.append(cve)
                                        except Exception as e:
                                            logger.debug(f"Skip {name}: {e}")
                            break  # Only process first matching zip

            except Exception as e:
                logger.error(f"MITRE fetch_recent failed: {e}")

        logger.info(f"MITRE fetch_recent: {len(results)} CVEs since {since}")
        return results

    async def fetch_by_keyword(self, keyword: str) -> List[NormalizedCVE]:
        """Search CVEs by keyword (limited — searches GitHub code)."""
        results: List[NormalizedCVE] = []
        # GitHub code search is limited; this is a best-effort approach
        async with httpx.AsyncClient(timeout=60.0) as client:
            try:
                resp = await client.get(
                    f"{GITHUB_API}/search/code",
                    headers=self._headers,
                    params={
                        "q": f"{keyword} repo:{REPO_OWNER}/{REPO_NAME} extension:json",
                        "per_page": 20,
                    },
                )
                if resp.status_code == 200:
                    for item in resp.json().get("items", []):
                        if "CVE-" in item.get("name", ""):
                            # Fetch the raw file
                            raw_url = item.get("html_url", "").replace(
                                "github.com", "raw.githubusercontent.com"
                            ).replace("/blob/", "/")
                            if raw_url:
                                raw_resp = await client.get(raw_url)
                                if raw_resp.status_code == 200:
                                    cve = self._parse_cve_json5(raw_resp.json())
                                    if cve:
                                        results.append(cve)
            except Exception as e:
                logger.error(f"MITRE keyword search failed: {e}")

        return results

    async def fetch_all(self, start_index: int = 0, page_size: int = 2000) -> List[NormalizedCVE]:
        """Fetch all CVEs by downloading the full repository ZIP.

        This downloads the main branch ZIP (~800MB) and parses all CVE JSON files.
        For a faster approach, use the bulk_import_from_directory() method with
        a manually downloaded/extracted copy.
        """
        results: List[NormalizedCVE] = []
        logger.info("MITRE: Starting full ZIP download (this may take a while)...")

        async with httpx.AsyncClient(timeout=3600.0) as client:
            try:
                resp = await client.get(FULL_ZIP_URL, follow_redirects=True)
                resp.raise_for_status()
                logger.info(f"MITRE: ZIP downloaded ({len(resp.content) / 1024 / 1024:.1f} MB)")

                with zipfile.ZipFile(io.BytesIO(resp.content)) as zf:
                    json_files = [n for n in zf.namelist() if n.endswith(".json") and "CVE-" in n]
                    total = len(json_files)
                    logger.info(f"MITRE: Parsing {total} CVE files...")

                    for idx, name in enumerate(json_files):
                        if idx < start_index:
                            continue
                        try:
                            data = json.loads(zf.read(name))
                            cve = self._parse_cve_json5(data)
                            if cve:
                                results.append(cve)
                        except Exception:
                            pass

                        if (idx + 1) % 10000 == 0:
                            logger.info(f"MITRE: Parsed {idx + 1}/{total} files...")

            except Exception as e:
                logger.error(f"MITRE full download failed: {e}")

        logger.info(f"MITRE fetch_all: {len(results)} CVEs parsed")
        return results

    def parse_from_directory(self, directory: str) -> List[NormalizedCVE]:
        """Parse CVEs from a locally extracted cvelistV5 directory.

        Usage for manual bulk import:
        1. git clone https://github.com/CVEProject/cvelistV5.git
        2. Or download and extract the ZIP
        3. Call: source.parse_from_directory("/path/to/cvelistV5/cves")
        """
        results: List[NormalizedCVE] = []
        json_files = glob_module.glob(os.path.join(directory, "**", "CVE-*.json"), recursive=True)
        total = len(json_files)
        logger.info(f"MITRE: Parsing {total} CVE files from {directory}")

        for idx, filepath in enumerate(json_files):
            try:
                with open(filepath, "r") as f:
                    data = json.load(f)
                cve = self._parse_cve_json5(data)
                if cve:
                    results.append(cve)
            except Exception:
                pass

            if (idx + 1) % 10000 == 0:
                logger.info(f"MITRE local: Parsed {idx + 1}/{total}")

        logger.info(f"MITRE local import: {len(results)} CVEs from directory")
        return results
