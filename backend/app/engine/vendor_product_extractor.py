"""Vendor/product extraction utilities.

Extracts vendor and product from multiple data sources within a CVE record,
used both during ingestion and for backfilling existing records.
"""

from __future__ import annotations

import logging
import re
from typing import Optional, Tuple

logger = logging.getLogger(__name__)


def extract_from_cpe(cpe_string: str) -> Tuple[Optional[str], Optional[str]]:
    """Extract vendor and product from a CPE 2.3 string.

    CPE format: cpe:2.3:part:vendor:product:version:...
    """
    parts = cpe_string.split(":")
    if len(parts) >= 5:
        vendor = parts[3] if parts[3] not in ("*", "-", "") else None
        product = parts[4] if parts[4] not in ("*", "-", "") else None
        return vendor, product
    return None, None


def extract_from_cpe_list(cpe_names: list) -> Tuple[Optional[str], Optional[str]]:
    """Try each CPE in the list until we find vendor/product."""
    for cpe in (cpe_names or []):
        vendor, product = extract_from_cpe(cpe)
        if vendor and product:
            return vendor.lower(), product.lower()
    # Second pass: accept partial matches (vendor only)
    for cpe in (cpe_names or []):
        vendor, product = extract_from_cpe(cpe)
        if vendor:
            return vendor.lower(), (product.lower() if product else None)
    return None, None


def extract_from_affected_products(affected_products: list) -> Tuple[Optional[str], Optional[str]]:
    """Extract vendor/product from affected_products list.

    Format is typically "Vendor Product" strings.
    """
    for entry in (affected_products or []):
        if not entry or not isinstance(entry, str):
            continue
        parts = entry.strip().split(None, 1)
        if len(parts) >= 2:
            return parts[0].lower(), parts[1].lower()
        elif len(parts) == 1 and parts[0]:
            return parts[0].lower(), None
    return None, None


def extract_from_redhat_raw(raw_json: dict) -> Tuple[Optional[str], Optional[str]]:
    """Extract product from RedHat raw_json data.

    RedHat stores affected packages like 'python39-3.9.18-3.el8_10' or
    product names in affected_release entries.
    """
    if not raw_json:
        return "redhat", None

    # Try affected_release for product names
    affected_releases = raw_json.get("affected_release", [])
    if isinstance(affected_releases, list):
        for release in affected_releases:
            if isinstance(release, dict):
                product_name = release.get("product_name", "")
                if product_name:
                    return "redhat", product_name.lower()

    # Try affected_packages for package names (less ideal but better than nothing)
    packages = raw_json.get("affected_packages", [])
    if isinstance(packages, list) and packages:
        pkg = packages[0]
        if isinstance(pkg, str):
            # Strip version info: "package-name-1.2.3-1.el8" -> "package-name"
            # RPM names use last two hyphens for version-release
            match = re.match(r'^([a-zA-Z][a-zA-Z0-9_+-]*?)(?:-\d)', pkg)
            if match:
                return "redhat", match.group(1).lower()

    # Try bugzilla_description
    bugzilla_desc = raw_json.get("bugzilla_description", "")
    if bugzilla_desc:
        # Pattern: "CVE-YYYY-NNNNN product_name: description"
        match = re.match(r'CVE-\d{4}-\d+\s+(.+?):\s', bugzilla_desc)
        if match:
            return "redhat", match.group(1).strip().lower()

    return "redhat", None


def extract_from_nvd_raw(raw_json: dict) -> Tuple[Optional[str], Optional[str]]:
    """Try to extract vendor/product from NVD raw_json when CPE configs are missing.

    Parses the configurations block that may have been missed, and falls back
    to description-based extraction.
    """
    if not raw_json:
        return None, None

    # Try configurations block (in case parsing was incomplete)
    configurations = raw_json.get("configurations", [])
    for config in configurations:
        for node in config.get("nodes", []):
            for match in node.get("cpeMatch", []):
                cpe = match.get("criteria", "")
                if cpe:
                    vendor, product = extract_from_cpe(cpe)
                    if vendor:
                        return vendor.lower(), product.lower() if product else None

    return None, None


def extract_from_mitre_raw(raw_json: dict) -> Tuple[Optional[str], Optional[str]]:
    """Try to extract vendor/product from MITRE raw_json."""
    if not raw_json:
        return None, None

    containers = raw_json.get("containers", {})
    cna = containers.get("cna", {})
    affected = cna.get("affected", [])

    for aff in affected:
        v = aff.get("vendor", "")
        p = aff.get("product", "")
        if v:
            return v.lower(), p.lower() if p else None
    return None, None


def extract_vendor_product(
    vendor: Optional[str],
    product: Optional[str],
    cpe_names: list = None,
    affected_products: list = None,
    raw_json: dict = None,
    source: str = None,
    sources: list = None,
) -> Tuple[Optional[str], Optional[str]]:
    """Master extraction function — tries every available avenue.

    Returns (vendor, product) using the best available data.
    Preserves existing values if already set.
    """
    # Already have both — nothing to do
    if vendor and product:
        return vendor, product

    # 1. Try CPE names
    if not (vendor and product) and cpe_names:
        cpe_v, cpe_p = extract_from_cpe_list(cpe_names)
        if cpe_v and not vendor:
            vendor = cpe_v
        if cpe_p and not product:
            product = cpe_p

    # 2. Try affected_products list
    if not (vendor and product) and affected_products:
        ap_v, ap_p = extract_from_affected_products(affected_products)
        if ap_v and not vendor:
            vendor = ap_v
        if ap_p and not product:
            product = ap_p

    # 3. Try source-specific raw_json parsing
    if not (vendor and product) and raw_json:
        primary_source = source or (sources[0] if sources else None)

        if primary_source == "REDHAT":
            rh_v, rh_p = extract_from_redhat_raw(raw_json)
            if rh_v and not vendor:
                vendor = rh_v
            if rh_p and not product:
                product = rh_p
        elif primary_source == "NVD":
            nvd_v, nvd_p = extract_from_nvd_raw(raw_json)
            if nvd_v and not vendor:
                vendor = nvd_v
            if nvd_p and not product:
                product = nvd_p
        elif primary_source == "MITRE":
            m_v, m_p = extract_from_mitre_raw(raw_json)
            if m_v and not vendor:
                vendor = m_v
            if m_p and not product:
                product = m_p

    return vendor, product
